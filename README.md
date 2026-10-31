# ShardGate

A privacy-first AI document assistant built for the **Mathematics for Systems
Security** hackathon (AI pipeline track: *an AI agent that is private where
inputs are encrypted*).

## The idea

Most AI agents read your documents by holding a decryption key somewhere
permanent: an env var, a config file, a cloud KMS binding. ShardGate refuses
that. The master key **never exists whole at rest**, anywhere.

1. **Encryption at rest.** Every document is encrypted client-side with
   AES-256-GCM before it touches the disk. The vault stores only
   `nonce || tag || ciphertext`.
2. **The key is shattered.** The 256-bit master key is split with
   **Shamir's Secret Sharing** into 3 shards, threshold 2, over GF(2^8).
   Shards live in three separate files. One shard alone is
   information-theoretically useless: it is one point on a random line.
3. **Reassembly is an event, not a state.** When the agent must decrypt, the
   KeyGuardian interpolates the shards **in RAM**, decrypts, and zeroizes the
   buffer. A compromised disk, or a compromised agent process between queries,
   yields only ciphertext and useless shards.
4. **Tamper is loud.** GCM authentication makes any altered ciphertext fail
   decryption instead of returning corrupted plaintext. ShardGate treats that
   as evidence of tampering: it refuses to answer and writes an audit event.
5. **Compromise simulation.** Destroy a shard from the dashboard and the agent
   can no longer rebuild the key: it refuses, and the vault stays encrypted.

## The math

For each secret byte `s`, the dealer picks a random line
`f(x) = s + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)` over GF(2^8)
(AES polynomial `0x11b`) and gives share `i` the value `f(i)`. Any k shares
reconstruct `s = f(0)` by Lagrange interpolation:

    f(0) = Σ_i  y_i · Π_{m≠i}  x_m / (x_i − x_m)

In GF(2^8), subtraction is XOR, so `x_i − x_m = x_i ⊕ x_m`. Fewer than k
shares constrain nothing: every polynomial through those points is equally
likely, so the mutual information between the secret and a partial set is
exactly zero.

## The agent

`ask(question)` decrypts the needed documents **into a short-lived RAM
buffer**, chunks them, selects the most relevant passages, and passes only
those to the LLM layer. The LLM layer is pluggable: the default
`OfflineAnswerer` is a deterministic extractive scorer, so the whole demo runs
with **no API key and no paid service**. Attach any hosted LLM by setting
`LLMAdapter.fn`.

## Honest scope

- Plaintext exists briefly in RAM during a query, by design; the threat model
  is *at-rest* compromise and *key-at-rest* compromise, not a memory-scraping
  attacker during live use. Zeroization is best-effort in CPython.
- No FHE is used (the track marks it optional); the privacy boundary is
  Shamir sharding + authenticated encryption + minimal-context disclosure.
- The offline answerer is extractive, not generative. Quality is proportional
  to how well the question's keywords overlap the documents.

## Run it

    pip install -r requirements.txt
    python app.py            # http://localhost:5000

A demo vault (2 encrypted documents, 3 shards) is seeded on first run.

## Tests

    pytest tests/ -q

Covers: Shamir 2-of-3 roundtrip from every share pair, insufficient-share
refusal, AES-GCM roundtrip and tamper detection, agent answering over the
encrypted vault, refusal on a destroyed shard, refusal on a tampered document.
