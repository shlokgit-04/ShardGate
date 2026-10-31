"""Append-only JSON-lines audit log for every unlock, decrypt and refusal."""
import json, os, time

class AuditLog:
    def __init__(self, path="vault/audit.log"):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def log(self, event: str, detail: str = ""):
        with open(self.path, "a") as f:
            f.write(json.dumps({"ts": time.time(), "event": event, "detail": detail}) + "\n")

    def tail(self, n: int = 20):
        if not os.path.exists(self.path):
            return []
        with open(self.path) as f:
            lines = f.readlines()
        return [json.loads(l) for l in lines[-n:]]
