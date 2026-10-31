"""Document vault: everything at rest is AES-256-GCM ciphertext. Nothing else."""
import json, os
from .cipher import encrypt, decrypt

class Vault:
    def __init__(self, vault_dir: str = "vault"):
        self.vault_dir = vault_dir
        self.docs_dir = os.path.join(vault_dir, "docs")
        os.makedirs(self.docs_dir, exist_ok=True)
        self.index_path = os.path.join(vault_dir, "index.json")
        self.index = {}
        if os.path.exists(self.index_path):
            with open(self.index_path) as f:
                self.index = json.load(f)

    def _save_index(self):
        with open(self.index_path, "w") as f:
            json.dump(self.index, f, indent=2)

    def list_docs(self):
        return sorted(self.index.keys())

    def doc_size(self, name: str):
        return self.index.get(name, {}).get("size", 0)

    def read_blob(self, name: str) -> bytes:
        with open(os.path.join(self.docs_dir, name + ".enc"), "rb") as f:
            return f.read()

    def add_document(self, name: str, plaintext: bytes, key: bytes):
        blob = encrypt(key, plaintext)
        with open(os.path.join(self.docs_dir, name + ".enc"), "wb") as f:
            f.write(blob)
        self.index[name] = {"size": len(plaintext), "chunks": None}
        self._save_index()

    def write_with(self, guardian, name: str, plaintext: bytes):
        """Unlock, encrypt, wipe. The only place a full key exists, briefly."""
        key = guardian.reassemble()
        kb = bytearray(key)
        try:
            self.add_document(name, plaintext, bytes(kb))
        finally:
            guardian.zeroize(kb)

    def decrypt_doc(self, guardian, name: str) -> bytes:
        key = guardian.reassemble()
        kb = bytearray(key)
        try:
            return decrypt(bytes(kb), self.read_blob(name))
        finally:
            guardian.zeroize(kb)
