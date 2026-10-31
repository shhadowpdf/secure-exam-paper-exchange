"""
run_simulation.py - Two-party simulation (sender / recipient folders on one computer).

Folder layout created:
  simulation/
    sender/       private key + original exam paper + (sender's copy of recipient public key)
    recipient/    private key + received package + decrypted output + (trusted copy of sender public key)
    channel/      "untrusted network": the package in transit
    attacker/     attacker's own key pair + tampered packages
Public keys are copied between folders to model a trusted out-of-band exchange.
"""
import argparse
import copy
import json
import os
import shutil
import sys
import uuid

import secure_exam as se

PASS_S, PASS_R, PASS_A = b"sender-demo-pass", b"recipient-demo-pass", b"attacker-demo-pass"
results = []


def log(msg=""):
    print(msg)
    results.append(msg)


def check(name, expected_reject, fn):
    """Run fn(); report PASS if behaviour matches expectation."""
    try:
        out = fn()
        outcome, detail = "ACCEPTED", out or ""
    except se.SecureExamError as e:
        outcome, detail = "REJECTED", f"{type(e).__name__}: {e}"
    ok = (outcome == "REJECTED") == expected_reject
    log(f"  [{'PASS' if ok else 'FAIL'}] {name}\n         -> {outcome}  {detail}")
    return ok


def flip_b64(s):
    """Flip one bit inside a base64 field (decode, flip, re-encode)."""
    raw = bytearray(se.b64d(s))
    raw[len(raw) // 2] ^= 0x01
    return se.b64e(bytes(raw))


def main():
    parser = argparse.ArgumentParser(description="Run the secure examination-paper exchange simulation.")
    parser.add_argument("--output-dir", default="simulation",
                        help="Parent directory for a new, non-overwriting simulation run.")
    args = parser.parse_args()
    os.makedirs(args.output_dir, exist_ok=True)
    root = os.path.join(args.output_dir, f"run_{uuid.uuid4().hex[:8]}")
    os.makedirs(root)
    S, R, C, A = (os.path.join(root, d) for d in ("sender", "recipient", "channel", "attacker"))
    for d in (S, R, C, A):
        os.makedirs(d)

    log("=" * 72)
    log("SECURE EXAMINATION-PAPER EXCHANGE - SIMULATION")
    log("=" * 72)

    # ---------- Step 0: keys (RSA-4096)
    log("\n[Setup] Generating RSA-4096 key pairs (this takes a few seconds each)...")
    s_priv, s_pub = se.generate_keypair("faculty", S, PASS_S)
    r_priv, r_pub = se.generate_keypair("coordinator", R, PASS_R)
    a_priv, a_pub = se.generate_keypair("attacker", A, PASS_A)
    # trusted public-key exchange
    shutil.copy(r_pub, os.path.join(S, "coordinator_public.pem"))
    shutil.copy(s_pub, os.path.join(R, "faculty_public.pem"))
    log(f"  sender    : {s_priv} (passphrase-encrypted PEM)")
    log(f"  recipient : {r_priv} (passphrase-encrypted PEM)")
    log(f"  attacker  : {a_priv}")
    log(f"  Public keys exchanged via trusted channel (copied between folders).")

    # ---------- sample input
    paper = os.path.join(S, "exam_paper.txt")
    with open(paper, "w") as f:
        f.write("CONFIDENTIAL - END SEMESTER EXAMINATION\n"
                "Course: Applied Cryptography    Max marks: 100    Duration: 3 hrs\n\n"
                "Q1. (10) Explain why AES-GCM requires a unique nonce per key.\n"
                "Q2. (15) Compare RSA-OAEP with textbook RSA encryption.\n"
                "Q3. (15) Describe how RSA-PSS differs from PKCS#1 v1.5 signatures.\n"
                "Q4. (20) Design a hybrid scheme for confidential file transfer.\n"
                "Q5. (40) Analyse the attacks possible on an unauthenticated channel.\n")
    original = open(paper, "rb").read()
    log(f"\n[Input] {paper}  ({len(original)} bytes)  SHA-256 = {se.sha256_hex(original)}")

    # sender-side objects
    sender_priv = se.load_private_key(s_priv, PASS_S)
    rcpt_pub_at_sender = se.load_public_key(os.path.join(S, "coordinator_public.pem"))
    # recipient-side objects
    rcpt_priv = se.load_private_key(r_priv, PASS_R)
    sender_pub_at_rcpt = se.load_public_key(os.path.join(R, "faculty_public.pem"))
    attacker_priv = se.load_private_key(a_priv, PASS_A)
    attacker_pub = se.load_public_key(a_pub)

    def send(path):
        pkg = se.encrypt_and_sign(original, "exam_paper.txt", "faculty", "coordinator",
                                  rcpt_pub_at_sender, sender_priv)
        with open(path, "w") as f:
            json.dump(pkg, f, indent=2)
        return pkg

    def receive(path, spub=sender_pub_at_rcpt, rpriv=rcpt_priv, save=None):
        pt, meta = se.verify_and_decrypt(open(path, "rb").read(), spub, rpriv, "coordinator")
        if save:
            open(save, "wb").write(pt)
        return pt, meta

    passed = []

    # ================= TEST 1
    log("\n" + "-" * 72)
    log("TEST 1: Authorised recipient recovers the original file")
    log("-" * 72)
    pkg_path = os.path.join(C, "exam_paper.pkg.json")
    pkg1 = send(pkg_path)
    shutil.copy(pkg_path, os.path.join(R, "received.pkg.json"))
    out_path = os.path.join(R, "exam_paper_decrypted.txt")

    def t1():
        pt, meta = receive(os.path.join(R, "received.pkg.json"), save=out_path)
        same = pt == original
        return f"sender={meta['sender']}  SHA-256={se.sha256_hex(pt)}  identical_to_original={same}" \
            if same else (_ for _ in ()).throw(AssertionError("mismatch"))
    passed.append(check("Decrypt + verify with correct keys", False, t1))
    log(f"  Ciphertext in channel does not contain plaintext: "
        f"{b'CONFIDENTIAL' not in open(pkg_path, 'rb').read()}")

    # ================= TEST 2
    log("\n" + "-" * 72)
    log("TEST 2: Attacker modifies ciphertext / metadata / signature (and other fields)")
    log("-" * 72)

    def tampered(mutator, name):
        p = copy.deepcopy(pkg1)
        mutator(p)
        path = os.path.join(A, name)
        with open(path, "w") as f:
            json.dump(p, f, indent=2)
        return path

    cases = [
        ("Flip 1 bit in ciphertext", lambda p: p.update(ciphertext=flip_b64(p["ciphertext"]))),
        ("Change metadata (recipient -> 'attacker')", lambda p: p["metadata"].update(recipient="attacker")),
        ("Change metadata (filename)", lambda p: p["metadata"].update(filename="easy_paper.txt")),
        ("Flip 1 bit in signature", lambda p: p.update(signature=flip_b64(p["signature"]))),
        ("Flip 1 bit in GCM tag", lambda p: p.update(tag=flip_b64(p["tag"]))),
        ("Flip 1 bit in nonce", lambda p: p.update(nonce=flip_b64(p["nonce"]))),
        ("Flip 1 bit in wrapped session key", lambda p: p.update(encrypted_session_key=flip_b64(p["encrypted_session_key"]))),
        ("Truncate package (drop signature field)", lambda p: p.pop("signature")),
    ]
    for i, (name, mut) in enumerate(cases):
        path = tampered(mut, f"tampered_{i}.json")
        passed.append(check(name, True, lambda path=path: receive(path)))

    def wrong_recipient():
        package = se.encrypt_and_sign(original, "exam_paper.txt", "faculty", "another-coordinator",
                                      rcpt_pub_at_sender, sender_priv)
        path = os.path.join(A, "wrong_recipient.json")
        with open(path, "w") as f:
            json.dump(package, f)
        return receive(path)
    passed.append(check("Reject correctly signed package addressed to another recipient",
                        True, wrong_recipient))

    # Stronger attack: attacker tampers AND re-signs with his own key
    def resign_attack():
        p = copy.deepcopy(pkg1)
        p["ciphertext"] = flip_b64(p["ciphertext"])
        body = {k: v for k, v in p.items() if k != "signature"}
        from cryptography.hazmat.primitives import hashes
        p["signature"] = se.b64e(attacker_priv.sign(se.canonical(body), se._pss(), hashes.SHA256()))
        path = os.path.join(A, "tampered_resigned.json")
        json.dump(p, open(path, "w"))
        return receive(path)
    passed.append(check("Tamper + re-sign with attacker's own key", True, resign_attack))

    # Replacement attack: attacker builds a whole fake package for the coordinator
    def replace_attack():
        fake = se.encrypt_and_sign(b"FAKE EXAM PAPER", "exam_paper.txt", "faculty", "coordinator",
                                   rcpt_pub_at_sender, attacker_priv)
        path = os.path.join(A, "forged.json")
        json.dump(fake, open(path, "w"))
        return receive(path)
    passed.append(check("Replace package with attacker-forged one", True, replace_attack))

    # ================= TEST 3
    log("\n" + "-" * 72)
    log("TEST 3: Recipient attempts decryption with an incorrect private key")
    log("-" * 72)
    passed.append(check("Decrypt using attacker's private key (signature itself is valid)", True,
                        lambda: receive(pkg_path, rpriv=attacker_priv)))
    wrong = se.generate_keypair("wrong_recipient", A, b"x")[0]
    passed.append(check("Decrypt using a different freshly generated RSA-4096 key", True,
                        lambda: receive(pkg_path, rpriv=se.load_private_key(wrong, b"x"))))
    try:
        se.load_private_key(r_priv, b"wrong-passphrase")
        passed.append(False); log("  [FAIL] wrong passphrase accepted")
    except ValueError as e:
        log(f"  [PASS] Private-key file with wrong passphrase\n"
            f"         -> REJECTED  {type(e).__name__}: incorrect passphrase or invalid key file")
        passed.append(True)

    # ================= TEST 4
    log("\n" + "-" * 72)
    log("TEST 4: Signature verification with an incorrect sender public key")
    log("-" * 72)
    passed.append(check("Verify using attacker's public key instead of faculty's", True,
                        lambda: receive(pkg_path, spub=attacker_pub)))
    passed.append(check("Verify using recipient's own public key as sender key", True,
                        lambda: receive(pkg_path, spub=se.load_public_key(r_pub))))

    # ================= TEST 5
    log("\n" + "-" * 72)
    log("TEST 5: Same file encrypted twice -> different packages")
    log("-" * 72)
    pa = send(os.path.join(C, "pkg_run_A.json"))
    pb = send(os.path.join(C, "pkg_run_B.json"))
    diffs = {k: (pa[k] != pb[k]) for k in ("encrypted_session_key", "nonce", "ciphertext", "tag", "signature")}
    for k, v in diffs.items():
        log(f"  {k:<22} differs between runs: {v}")
    log(f"  package_id differs: {pa['metadata']['package_id'] != pb['metadata']['package_id']}")
    ok5 = all(diffs.values())
    log(f"  [{'PASS' if ok5 else 'FAIL'}] All security-relevant fields differ; both still decrypt:")
    for tag, p in (("A", "pkg_run_A.json"), ("B", "pkg_run_B.json")):
        pt, _ = receive(os.path.join(C, p))
        log(f"         package {tag} -> plaintext identical to original: {pt == original}")
        ok5 &= pt == original
    passed.append(ok5)

    # ---------- summary
    log("\n" + "=" * 72)
    log(f"SUMMARY: {sum(passed)}/{len(passed)} checks passed")
    log("=" * 72)
    report = "\n".join(results) + "\n"
    for report_path in (os.path.join(root, "test_results.txt"), "test_results.txt"):
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report)
    print(f"Artifacts and test report: {root}")
    sys.exit(0 if all(passed) else 1)


if __name__ == "__main__":
    main()
