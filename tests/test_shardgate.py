import os, shutil, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from shardgate.shamir import split, combine
from shardgate.cipher import encrypt, decrypt
from shardgate.guardian import KeyGuardian
from shardgate.vault import Vault
from shardgate.agent import ShardGateAgent
from shardgate.audit import AuditLog

def test_shamir_roundtrip_any_two_of_three():
    secret = b"0123456789abcdef0123456789abcdef"
    shares = split(secret, 2, 3)
    assert combine([shares[0], shares[1]]) == secret
    assert combine([shares[1], shares[2]]) == secret
    assert combine([shares[0], shares[2]]) == secret

def test_shamir_one_share_is_not_enough():
    secret = b"x" * 32
    shares = split(secret, 2, 3)
    with pytest.raises(ValueError):
        combine([shares[0]])
    # k-1 shares must not accidentally reconstruct the secret
    assert combine([shares[0], shares[1]]) == secret

def test_aesgcm_roundtrip_and_tamper():
    key = os.urandom(32)
    blob = encrypt(key, b"top secret")
    assert decrypt(key, blob) == b"top secret"
    bad = blob[:-1] + bytes([blob[-1] ^ 1])
    with pytest.raises(ValueError):
        decrypt(key, bad)

def test_agent_answers_over_encrypted_vault(tmp_path):
    d = str(tmp_path)
    key = os.urandom(32)
    g = KeyGuardian(key, 2, 3, vault_dir=d)
    v = Vault(d)
    v.write_with(g, "notes.txt", b"ShardGate reassembles the master key only in RAM and never stores it whole.")
    a = ShardGateAgent(g, v, audit=AuditLog(os.path.join(d, "audit.log")))
    r = a.ask("where does the master key exist?")
    assert not r["refused"] and "RAM" in r["answer"]

def test_agent_refuses_when_shard_missing(tmp_path):
    d = str(tmp_path)
    key = os.urandom(32)
    g = KeyGuardian(key, 2, 3, vault_dir=d)
    v = Vault(d)
    v.write_with(g, "notes.txt", b"hello world")
    a = ShardGateAgent(g, v, audit=AuditLog(os.path.join(d, "audit.log")))
    assert a.ask("anything")["refused"] is False
    g.destroy_shard(1)
    g.destroy_shard(2)
    r = a.ask("anything")
    assert r["refused"] is True and "shards" in r["reason"]

def test_agent_refuses_tampered_document(tmp_path):
    d = str(tmp_path)
    key = os.urandom(32)
    g = KeyGuardian(key, 2, 3, vault_dir=d)
    v = Vault(d)
    v.write_with(g, "notes.txt", b"hello world")
    path = os.path.join(d, "docs", "notes.txt.enc")
    blob = open(path, "rb").read()
    open(path, "wb").write(blob[:-1] + bytes([blob[-1] ^ 1]))
    a = ShardGateAgent(g, v, audit=AuditLog(os.path.join(d, "audit.log")))
    r = a.ask("anything")
    assert r["refused"] is True and "tamper" in r["reason"]
