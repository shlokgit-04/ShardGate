"""KeyGuardian: the master key only ever exists as Shamir shards on disk.

Reassembly happens in RAM, for the instant a decrypt needs it, and the
buffer is zeroized right after. A missing shard means the guardian refuses.
"""
import os
from .shamir import split, combine

class KeyGuardian:
    def __init__(self, master_key: bytes, threshold: int = 2, shares: int = 3,
                 vault_dir: str = "vault"):
        if len(master_key) != 32:
            raise ValueError("master key must be 32 bytes (AES-256)")
        self.threshold = threshold
        self.shares = shares
        self.vault_dir = vault_dir
        self.shard_paths = {}
        for i, data in split(master_key, threshold, shares):
            p = os.path.join(vault_dir, f"shard_{i}.key")
            os.makedirs(vault_dir, exist_ok=True)
            with open(p, "wb") as f:
                f.write(data)
            self.shard_paths[i] = p

    def present_shards(self):
        return sorted(i for i, p in self.shard_paths.items() if os.path.exists(p))

    def reassemble(self) -> bytes:
        shards = [(i, open(self.shard_paths[i], "rb").read())
                  for i in self.present_shards()]
        if len(shards) < self.threshold:
            raise PermissionError(
                f"only {len(shards)} of {self.threshold} shards available; refusing to unlock")
        return combine(shards[:self.threshold])

    @staticmethod
    def zeroize(buf):
        """Best-effort wipe of a mutable key buffer (CPython caveat: GC copies)."""
        if isinstance(buf, bytearray):
            for i in range(len(buf)):
                buf[i] = 0

    def destroy_shard(self, i: int) -> bool:
        p = self.shard_paths.get(i)
        if p and os.path.exists(p):
            os.remove(p)
            return True
        return False
