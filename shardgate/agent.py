"""ShardGate agent: answers questions over the encrypted vault.

At rest: ciphertext + Shamir shards. On a query: guardian reassembles the
key in RAM, documents decrypt into a short-lived buffer, the most relevant
chunks go to a pluggable LLM (offline extractive fallback by default), and
the buffer is zeroized. Missing shard or tampered ciphertext -> refusal,
logged to the audit trail.
"""
import re
from .audit import AuditLog
from .cipher import decrypt
from .vault import Vault

CHUNK = 400

class OfflineAnswerer:
    """Deterministic extractive answerer: no network, no API key, no cost."""
    name = "offline-extractive"

    def answer(self, question, contexts):
        q = set(re.findall(r"[a-z0-9]+", question.lower()))
        scored = []
        for ctx in contexts:
            words = re.findall(r"[a-z0-9]+", ctx["text"].lower())
            score = sum(1 for w in set(words) if w in q) / (1 + len(words))
            scored.append((score, ctx))
        scored.sort(key=lambda t: -t[0])
        best = [c for s, c in scored[:3] if s > 0]
        if not best:
            return "No relevant passage found in the encrypted vault.", []
        return " ".join(c["text"] for c in best), sorted({c["doc"] for c in best})

class LLMAdapter:
    """Pluggable remote-LLM interface. Set .fn = callable(question, contexts)."""
    name = "pluggable-llm"
    fn = None

class ShardGateAgent:
    def __init__(self, guardian: "KeyGuardian", vault: Vault, llm=None,
                 audit: AuditLog = None):
        self.guardian = guardian
        self.vault = vault
        self.llm = llm
        self.audit = audit or AuditLog()

    def _chunks(self, text: str):
        return [text[i:i + CHUNK] for i in range(0, len(text), CHUNK)]

    def ask(self, question: str) -> dict:
        try:
            key = self.guardian.reassemble()
        except PermissionError as e:
            self.audit.log("REFUSED", str(e))
            return {"answer": None, "refused": True, "reason": str(e)}

        kb = bytearray(key)
        try:
            contexts = []
            for name in self.vault.list_docs():
                try:
                    plain = decrypt(bytes(kb), self.vault.read_blob(name))
                except ValueError:
                    self.audit.log("TAMPER_DETECTED",
                                   f"{name}: GCM auth failed; ciphertext altered")
                    return {"answer": None, "refused": True,
                            "reason": f"tamper detected in '{name}'; refusing to answer"}
                text = plain.decode("utf-8", "replace")
                for idx, chunk in enumerate(self._chunks(text)):
                    contexts.append({"doc": name, "chunk": idx, "text": chunk})

            llm = self.llm if (self.llm and self.llm.fn) else OfflineAnswerer()
            answer, sources = llm.answer(question, contexts)
            self.audit.log("DECRYPT_OK",
                           f"question served over {len(contexts)} chunks from "
                           f"{len(self.vault.list_docs())} docs")
            return {"answer": answer, "sources": sources, "refused": False,
                    "llm": llm.name}
        finally:
            self.guardian.zeroize(kb)
