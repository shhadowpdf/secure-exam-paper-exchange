"""
secure_exam.py - Secure examination-paper exchange.

Hybrid scheme (library: `cryptography`):
  * RSA-4096 key pairs for sender and recipient
  * AES-256-GCM (fresh random key + fresh 96-bit nonce per encryption) for the file
  * RSA-OAEP (MGF1-SHA256, SHA-256) to wrap the AES session key for the recipient
  * RSA-PSS (MGF1-SHA256, SHA-256) signature by the sender over the whole package

Order of checks on receipt (plaintext is released only if ALL succeed):
  1. parse / structure check
  2. verify RSA-PSS signature with the trusted sender public key
  3. unwrap the AES key with the recipient private key (RSA-OAEP)
  4. AES-GCM decrypt + verify tag (metadata is bound as Associated Data)
"""
import argparse
import base64
import binascii
import getpass
import hashlib
import json
import os
import sys
import tempfile
import time
import uuid

from cryptography.exceptions import InvalidSignature, InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RSA_BITS = 4096
AES_BITS = 256
NONCE_LEN = 12
TAG_LEN = 16
VERSION = 1

ALGORITHMS = {
    "key_exchange": "RSA-4096-OAEP-MGF1-SHA256",
    "bulk_cipher": "AES-256-GCM",
    "signature": "RSA-4096-PSS-MGF1-SHA256",
}


class SecureExamError(Exception):
    """Base class: package rejected, no plaintext released."""


class PackageFormatError(SecureExamError):
    pass


class SignatureVerificationError(SecureExamError):
    pass


class KeyUnwrapError(SecureExamError):
    pass


class IntegrityError(SecureExamError):
    pass


class KeyFileError(SecureExamError):
    pass


# --------------------------------------------------------------- helpers
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def canonical(obj) -> bytes:
    """Deterministic JSON so signer and verifier hash identical bytes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _pss():
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def _oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------- keys
def generate_keypair(name: str, folder: str, passphrase: bytes, public_dir: str = None):
    """Create RSA-4096 pair. Private key: passphrase-encrypted PKCS#8 PEM."""
    if not passphrase:
        raise ValueError("A non-empty passphrase is required to protect the private key.")
    os.makedirs(folder, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
    priv_path = os.path.join(folder, f"{name}_private.pem")
    pub_path = os.path.join(public_dir or folder, f"{name}_public.pem")
    os.makedirs(os.path.dirname(pub_path), exist_ok=True)

    with open(priv_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(passphrase),
        ))
    os.chmod(priv_path, 0o600)
    with open(pub_path, "wb") as f:
        f.write(key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    return priv_path, pub_path


def load_private_key(path: str, passphrase: bytes):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=passphrase)


def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def _load_private_key_for_cli(path: str, passphrase: bytes):
    try:
        return load_private_key(path, passphrase)
    except ValueError:
        raise KeyFileError(
            "Unable to load private key: incorrect passphrase or invalid key file.") from None


# --------------------------------------------------------------- sender
def encrypt_and_sign(plaintext: bytes, filename: str, sender_id: str, recipient_id: str,
                     recipient_public_key, sender_private_key) -> dict:
    # 1. fresh AES-256 session key + fresh nonce
    session_key = AESGCM.generate_key(bit_length=AES_BITS)
    nonce = os.urandom(NONCE_LEN)

    metadata = {
        "version": VERSION,
        "package_id": str(uuid.uuid4()),
        "filename": filename,
        "sender": sender_id,
        "recipient": recipient_id,
        "created_utc": int(time.time()),
        "algorithms": ALGORITHMS,
    }

    # 2. AES-GCM; metadata is Associated Data so it is authenticated too
    ct_and_tag = AESGCM(session_key).encrypt(nonce, plaintext, canonical(metadata))
    ciphertext, tag = ct_and_tag[:-TAG_LEN], ct_and_tag[-TAG_LEN:]

    # 3. wrap session key for recipient (RSA-OAEP / SHA-256)
    enc_key = recipient_public_key.encrypt(session_key, _oaep())

    package = {
        "metadata": metadata,
        "encrypted_session_key": b64e(enc_key),
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
        "tag": b64e(tag),
    }

    # 4. sign the complete package (everything except the signature itself)
    package["signature"] = b64e(sender_private_key.sign(canonical(package), _pss(), hashes.SHA256()))
    return package


# --------------------------------------------------------------- recipient
_REQUIRED = ("metadata", "encrypted_session_key", "nonce", "ciphertext", "tag", "signature")
_REQUIRED_METADATA = ("version", "package_id", "filename", "sender", "recipient",
                      "created_utc", "algorithms")


def parse_package(raw: bytes) -> dict:
    try:
        pkg = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise PackageFormatError(f"Malformed package: {e}") from None
    if not isinstance(pkg, dict) or set(pkg) != set(_REQUIRED):
        raise PackageFormatError("Malformed package: unexpected or missing field.")
    if not isinstance(pkg["metadata"], dict):
        raise PackageFormatError("Malformed package: metadata must be an object.")
    meta = pkg["metadata"]
    if set(meta) != set(_REQUIRED_METADATA):
        raise PackageFormatError("Malformed package: unexpected or missing metadata field.")
    if type(meta["version"]) is not int or type(meta["created_utc"]) is not int:
        raise PackageFormatError("Malformed package: invalid metadata version or timestamp.")
    if any(not isinstance(meta[k], str) or not meta[k]
           for k in ("package_id", "filename", "sender", "recipient")):
        raise PackageFormatError("Malformed package: metadata text fields must be non-empty strings.")
    if not isinstance(meta["algorithms"], dict):
        raise PackageFormatError("Malformed package: algorithms must be an object.")
    for k in _REQUIRED[1:]:
        if not isinstance(pkg[k], str):
            raise PackageFormatError(f"Malformed package: {k} must be base64 text.")
    try:
        for k in _REQUIRED[1:]:
            b64d(pkg[k])
        if len(b64d(pkg["nonce"])) != NONCE_LEN or len(b64d(pkg["tag"])) != TAG_LEN:
            raise ValueError("bad nonce/tag length")
    except (binascii.Error, UnicodeEncodeError, ValueError) as e:
        raise PackageFormatError(f"Malformed package: {e}") from None
    return pkg


def verify_and_decrypt(raw: bytes, sender_public_key, recipient_private_key,
                       expected_recipient: str = None) -> tuple:
    """Return (plaintext, metadata) only if every check passes."""
    pkg = parse_package(raw)

    # --- Check 1: sender authentication + whole-package integrity
    body = {k: v for k, v in pkg.items() if k != "signature"}
    try:
        sender_public_key.verify(b64d(pkg["signature"]), canonical(body), _pss(), hashes.SHA256())
    except InvalidSignature:
        raise SignatureVerificationError(
            "Signature verification FAILED: package was altered or was not signed "
            "by the trusted sender.") from None

    meta = pkg["metadata"]
    if meta.get("version") != VERSION or meta.get("algorithms") != ALGORITHMS:
        raise PackageFormatError("Unsupported package version or cryptographic algorithms.")
    if expected_recipient is not None and meta.get("recipient") != expected_recipient:
        raise PackageFormatError(f"Package addressed to '{meta.get('recipient')}', not '{expected_recipient}'.")

    # --- Check 2: recover AES session key
    try:
        session_key = recipient_private_key.decrypt(b64d(pkg["encrypted_session_key"]), _oaep())
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise KeyUnwrapError(
            "Session-key recovery FAILED: this private key is not the intended recipient's.") from None
    if len(session_key) != AES_BITS // 8:
        raise KeyUnwrapError("Recovered session key has an invalid length.")

    # --- Check 3: AES-GCM tag (also authenticates metadata as AAD)
    try:
        plaintext = AESGCM(session_key).decrypt(
            b64d(pkg["nonce"]), b64d(pkg["ciphertext"]) + b64d(pkg["tag"]), canonical(meta))
    except InvalidTag:
        raise IntegrityError("AES-GCM authentication FAILED: ciphertext/metadata corrupted.") from None

    return plaintext, meta  # released only here


# --------------------------------------------------------------- CLI
def _pw(prompt):
    return os.environ.get("EXAM_KEY_PASSPHRASE", "").encode() or getpass.getpass(prompt).encode()


def _write_atomically(path: str, data: bytes):
    target_dir = os.path.dirname(os.path.abspath(path))
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(dir=target_dir, delete=False) as f:
            temp_path = f.name
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, path)
        temp_path = None
    finally:
        if temp_path is not None:
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass


def main():
    ap = argparse.ArgumentParser(description="Secure exam-paper exchange")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("keygen"); g.add_argument("--name", required=True)
    g.add_argument("--folder", required=True); g.add_argument("--public-dir")

    e = sub.add_parser("encrypt")
    e.add_argument("--in", dest="infile", required=True); e.add_argument("--out", required=True)
    e.add_argument("--sender", required=True); e.add_argument("--recipient", required=True)
    e.add_argument("--sender-key", required=True); e.add_argument("--recipient-pub", required=True)

    d = sub.add_parser("decrypt")
    d.add_argument("--in", dest="infile", required=True); d.add_argument("--out", required=True)
    d.add_argument("--sender-pub", required=True); d.add_argument("--recipient-key", required=True)
    d.add_argument("--recipient", required=True, help="Expected recipient identity in signed metadata")

    a = ap.parse_args()
    try:
        if a.cmd == "keygen":
            print("Generated:", *generate_keypair(a.name, a.folder, _pw("Passphrase: "), a.public_dir))
        elif a.cmd == "encrypt":
            data = open(a.infile, "rb").read()
            pkg = encrypt_and_sign(data, os.path.basename(a.infile), a.sender, a.recipient,
                                   load_public_key(a.recipient_pub),
                                   _load_private_key_for_cli(a.sender_key, _pw("Sender key passphrase: ")))
            _write_atomically(a.out, json.dumps(pkg, indent=2).encode("utf-8"))
            print("Encrypted package written to", a.out)
        else:
            pt, meta = verify_and_decrypt(open(a.infile, "rb").read(), load_public_key(a.sender_pub),
                                          _load_private_key_for_cli(
                                              a.recipient_key, _pw("Recipient key passphrase: ")),
                                          a.recipient)
            _write_atomically(a.out, pt)
            print(f"OK: verified sender '{meta['sender']}', decrypted to {a.out}")
    except SecureExamError as ex:
        print("REJECTED:", ex, file=sys.stderr)
        raise SystemExit(1)
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm) as ex:
        print(f"ERROR: {ex}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
