"""Tests for secrets_operator.py"""
import json
import os
import pytest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from secrets_operator import (
    create_secret, get_secret, get_secret_by_name, rotate_secret, delete_secret,
    list_secrets, check_rotation_due, inject_to_env, audit_log, get_audit_log,
    get_secret_versions, encrypt_value, decrypt_value, encrypt_dict, decrypt_dict,
    _get_db, SecretType, AuditAction,
)

MASTER_KEY = "test-master-key-12345"


@pytest.fixture
def db(tmp_path):
    return _get_db(tmp_path / "test_secrets.db")


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------

def test_encrypt_decrypt_roundtrip():
    plain = "my-secret-password"
    salt = "test-salt-abc"
    cipher = encrypt_value(plain, MASTER_KEY, salt)
    assert cipher != plain
    assert decrypt_value(cipher, MASTER_KEY, salt) == plain


def test_different_keys_produce_different_ciphertext():
    salt = "salt"
    c1 = encrypt_value("hello", "key1", salt)
    c2 = encrypt_value("hello", "key2", salt)
    assert c1 != c2


def test_different_salts_produce_different_ciphertext():
    c1 = encrypt_value("hello", MASTER_KEY, "salt1")
    c2 = encrypt_value("hello", MASTER_KEY, "salt2")
    assert c1 != c2


def test_encrypt_dict_roundtrip():
    data = {"username": "admin", "password": "p@$$w0rd"}
    salt = "dict-salt"
    encrypted = encrypt_dict(data, MASTER_KEY, salt)
    assert encrypted["username"] != "admin"
    decrypted = decrypt_dict(encrypted, MASTER_KEY, salt)
    assert decrypted == data


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------

def test_create_secret(db):
    s = create_secret("db-creds", "default", SecretType.OPAQUE.value,
                      {"host": "localhost", "password": "secret"}, MASTER_KEY, db=db)
    assert s.name == "db-creds"
    assert s.version == 1
    assert "host" in s.data_encrypted


def test_create_secret_data_is_encrypted(db):
    data = {"key": "plaintext-value"}
    s = create_secret("enc-test", "default", SecretType.OPAQUE.value, data, MASTER_KEY, db=db)
    assert s.data_encrypted["key"] != "plaintext-value"


def test_create_tls_secret(db):
    s = create_secret("tls-cert", "prod", SecretType.TLS.value,
                      {"cert": "-----BEGIN CERT-----", "key": "-----BEGIN KEY-----"},
                      MASTER_KEY, db=db)
    assert s.type == SecretType.TLS.value


# ---------------------------------------------------------------------------
# Get
# ---------------------------------------------------------------------------

def test_get_secret_decrypts(db):
    data = {"username": "admin", "password": "hunter2"}
    s = create_secret("creds", "default", SecretType.OPAQUE.value, data, MASTER_KEY, db=db)
    result = get_secret(s.id, MASTER_KEY, db=db)
    assert result["data"]["username"] == "admin"
    assert result["data"]["password"] == "hunter2"


def test_get_secret_wrong_key_fails(db):
    data = {"k": "v"}
    s = create_secret("bad-key-test", "default", SecretType.OPAQUE.value, data, MASTER_KEY, db=db)
    result = get_secret(s.id, "wrong-key", db=db)
    # Decryption with wrong key returns garbled data, not the original
    assert result["data"]["k"] != "v"


def test_get_secret_not_found(db):
    assert get_secret("nonexistent-id", MASTER_KEY, db=db) is None


def test_get_secret_by_name(db):
    data = {"token": "abc123"}
    s = create_secret("named-secret", "ns1", SecretType.TOKEN.value, data, MASTER_KEY, db=db)
    result = get_secret_by_name("named-secret", "ns1", MASTER_KEY, db=db)
    assert result["data"]["token"] == "abc123"


# ---------------------------------------------------------------------------
# Rotation
# ---------------------------------------------------------------------------

def test_rotate_secret(db):
    data = {"password": "old-pass"}
    s = create_secret("to-rotate", "default", SecretType.OPAQUE.value, data, MASTER_KEY, db=db)
    new_data = {"password": "new-pass"}
    rotated = rotate_secret(s.id, new_data, MASTER_KEY, db=db)
    assert rotated.version == 2

    result = get_secret(s.id, MASTER_KEY, db=db)
    assert result["data"]["password"] == "new-pass"


def test_rotate_archives_old_version(db):
    data = {"key": "v1"}
    s = create_secret("versioned", "default", SecretType.OPAQUE.value, data, MASTER_KEY, db=db)
    rotate_secret(s.id, {"key": "v2"}, MASTER_KEY, db=db)
    versions = get_secret_versions(s.id, db=db)
    assert len(versions) >= 1
    assert versions[0]["version"] == 1


def test_rotate_multiple_times(db):
    s = create_secret("multi-rotate", "default", SecretType.OPAQUE.value,
                      {"v": "1"}, MASTER_KEY, db=db)
    for i in range(2, 5):
        rotate_secret(s.id, {"v": str(i)}, MASTER_KEY, db=db)
    result = get_secret(s.id, MASTER_KEY, db=db)
    assert result["version"] == 4
    assert result["data"]["v"] == "4"


# ---------------------------------------------------------------------------
# Rotation due
# ---------------------------------------------------------------------------

def test_check_rotation_due(db):
    import time
    s = create_secret("overdue", "default", SecretType.OPAQUE.value,
                      {"k": "v"}, MASTER_KEY, rotation_schedule=1, db=db)
    # Simulate age by patching last_rotated in DB
    db.execute("UPDATE secrets SET last_rotated=? WHERE id=?", (time.time() - 86400 * 5, s.id))
    db.commit()
    due = check_rotation_due(days_threshold=30, db=db)
    ids = [d["id"] for d in due]
    assert s.id in ids


def test_check_rotation_not_due(db):
    import time
    s = create_secret("fresh", "default", SecretType.OPAQUE.value,
                      {"k": "v"}, MASTER_KEY, rotation_schedule=90, db=db)
    due = check_rotation_due(days_threshold=30, db=db)
    ids = [d["id"] for d in due]
    assert s.id not in ids


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------

def test_delete_secret(db):
    s = create_secret("deleteme", "default", SecretType.OPAQUE.value, {"k": "v"}, MASTER_KEY, db=db)
    ok = delete_secret(s.id, db=db)
    assert ok
    assert get_secret(s.id, MASTER_KEY, db=db) is None


def test_delete_nonexistent(db):
    assert delete_secret("nonexistent", db=db) is False


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def test_audit_log_records_create(db):
    s = create_secret("audited", "default", SecretType.OPAQUE.value, {"k": "v"}, MASTER_KEY, db=db)
    log = get_audit_log(s.id, db=db)
    assert any(e["action"] == AuditAction.CREATE.value for e in log)


def test_audit_log_records_read(db):
    s = create_secret("read-audit", "default", SecretType.OPAQUE.value, {"k": "v"}, MASTER_KEY, db=db)
    get_secret(s.id, MASTER_KEY, db=db)
    log = get_audit_log(s.id, db=db)
    actions = [e["action"] for e in log]
    assert AuditAction.READ.value in actions


def test_audit_log_records_rotate(db):
    s = create_secret("rot-audit", "default", SecretType.OPAQUE.value, {"k": "v"}, MASTER_KEY, db=db)
    rotate_secret(s.id, {"k": "v2"}, MASTER_KEY, db=db)
    log = get_audit_log(s.id, db=db)
    actions = [e["action"] for e in log]
    assert AuditAction.ROTATE.value in actions


# ---------------------------------------------------------------------------
# Env injection
# ---------------------------------------------------------------------------

def test_inject_to_env(db):
    data = {"db_host": "localhost", "db_pass": "secret"}
    s = create_secret("env-inject", "default", SecretType.OPAQUE.value, data, MASTER_KEY, db=db)
    env_vars = inject_to_env(s.id, MASTER_KEY, prefix="TEST", db=db)
    assert "TEST_DB_HOST" in env_vars
    assert os.environ.get("TEST_DB_HOST") == "localhost"


def test_inject_to_env_no_prefix(db):
    data = {"api_key": "abc"}
    s = create_secret("no-prefix", "default", SecretType.OPAQUE.value, data, MASTER_KEY, db=db)
    env_vars = inject_to_env(s.id, MASTER_KEY, db=db)
    assert "API_KEY" in env_vars
