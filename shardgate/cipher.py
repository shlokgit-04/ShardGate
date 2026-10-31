"""AES-256-GCM wrappers. Tampering raises ValueError at decrypt time."""
import os
from Crypto.Cipher import AES

def encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    c = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = c.encrypt_and_digest(plaintext)
    return nonce + tag + ct

def decrypt(key: bytes, blob: bytes) -> bytes:
    if len(blob) < 28:
        raise ValueError("ciphertext too short")
    nonce, tag, ct = blob[:12], blob[12:28], blob[28:]
    c = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return c.decrypt_and_verify(ct, tag)
