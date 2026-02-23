"""
BlackRoad Secrets Operator
Production-quality secrets management with XOR encryption, versioning,
rotation scheduling, audit logging, and env injection. No external deps.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

DB_PATH = Path.home() / ".blackroad" / "secrets_operator.db"

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class SecretType(str, Enum):
    OPAQUE = "Opaque"
    TLS    = "TLS"
    SSH    = "SSH"
    DOCKER = "Docker"
    BASIC  = "BasicAuth"
    TOKEN  = "ServiceAccountToken"


class AuditAction(str, Enum):
    CREATE  = "CREATE"
    READ    = "READ"
    UPDATE  = "UPDATE"
    ROTATE  = "ROTATE"
    DELETE  = "DELETE"
    INJECT  = "INJECT"
    EXPIRE  = "EXPIRE"


# ---------------------------------------------------------------------------
# XOR cipher (no external dependencies)
# ---------------------------------------------------------------------------

def _derive_key(master_key: str, salt: str) -> bytes:
    """Derive a 64-byte key from master_key + salt using SHA-256 iterations."""
    k = (master_key + salt).encode("utf-8")
    for _ in range(10_000):
        k = hashlib.sha256(k).digest()
    return k * 2  # 64 bytes


def _xor_cipher(data: bytes, key: bytes) -> bytes:
    """XOR each byte of data with cycling key bytes."""
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def encrypt_value(plaintext: str, master_key: str, salt: str) -> str:
    """Encrypt plaintext with XOR cipher; return hex string."""
    key = _derive_key(master_key, salt)
    cipher = _xor_cipher(plaintext.encode("utf-8"), key)
    return cipher.hex()


def decrypt_value(ciphertext_hex: str, master_key: str, salt: str) -> str:
    """Decrypt XOR-ciphered hex string back to plaintext."""
    key = _derive_key(master_key, salt)
    cipher = bytes.fromhex(ciphertext_hex)
    return _xor_cipher(cipher, key).decode("utf-8")


def encrypt_dict(data: dict, master_key: str, salt: str) -> dict:
    """Encrypt all values in a dict; keys remain plaintext."""
    return {k: encrypt_value(str(v), master_key, salt) for k, v in data.items()}


def decrypt_dict(data: dict, master_key: str, salt: str) -> dict:
    """Decrypt all values in a dict."""
    return {k: decrypt_value(v, master_key, salt) for k, v in data.items()}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Secret:
    name: str
    namespace: str
    type: str
    data_encrypted: dict           # {key: encrypted_hex}
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    version: int = 1
    rotation_schedule: int = 90    # days
    last_rotated: float = field(default_factory=time.time)
    created_at: float = field(default_factory=time.time)
    labels: dict = field(default_factory=dict)
    salt: str = field(default_factory=lambda: uuid.uuid4().hex)

    def is_rotation_due(self, days_threshold: int = 30) -> bool:
        age_days = (time.time() - self.last_rotated) / 86400
        return age_days >= (self.rotation_schedule - days_threshold)

    def age_days(self) -> float:
        return (time.time() - self.last_rotated) / 86400


@dataclass
class AuditEntry:
    action: str
    secret_id: str
    secret_name: str
    namespace: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    actor: str = "system"
    details: str = ""
    timestamp: float = field(default_factory=time.time)
    success: bool = True


# ---------------------------------------------------------------------------
# DB
# ---------------------------------------------------------------------------

def _get_db(path: Path = DB_PATH) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS secrets (
            id                TEXT PRIMARY KEY,
            name              TEXT NOT NULL,
            namespace         TEXT NOT NULL DEFAULT 'default',
            type              TEXT NOT NULL DEFAULT 'Opaque',
            data_encrypted    TEXT NOT NULL DEFAULT '{}',
            salt              TEXT NOT NULL,
            version           INTEGER NOT NULL DEFAULT 1,
            rotation_schedule INTEGER NOT NULL DEFAULT 90,
            last_rotated      REAL NOT NULL,
            created_at        REAL NOT NULL,
            labels            TEXT NOT NULL DEFAULT '{}',
            UNIQUE(name, namespace)
        );

        CREATE TABLE IF NOT EXISTS secret_versions (
            id                TEXT PRIMARY KEY,
            secret_id         TEXT NOT NULL,
            version           INTEGER NOT NULL,
            data_encrypted    TEXT NOT NULL,
            salt              TEXT NOT NULL,
            rotated_at        REAL NOT NULL,
            rotated_by        TEXT NOT NULL DEFAULT 'system',
            FOREIGN KEY(secret_id) REFERENCES secrets(id)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id          TEXT PRIMARY KEY,
            action      TEXT NOT NULL,
            secret_id   TEXT NOT NULL,
            secret_name TEXT NOT NULL,
            namespace   TEXT NOT NULL,
            actor       TEXT NOT NULL DEFAULT 'system',
            details     TEXT NOT NULL DEFAULT '',
            success     INTEGER NOT NULL DEFAULT 1,
            timestamp   REAL NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_secrets_ns ON secrets(namespace);
        CREATE INDEX IF NOT EXISTS idx_audit_sid ON audit_log(secret_id);
        CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_versions_sid ON secret_versions(secret_id);
    """)
    conn.commit()


def _row_to_secret(row: sqlite3.Row) -> Secret:
    return Secret(
        id=row["id"],
        name=row["name"],
        namespace=row["namespace"],
        type=row["type"],
        data_encrypted=json.loads(row["data_encrypted"]),
        salt=row["salt"],
        version=row["version"],
        rotation_schedule=row["rotation_schedule"],
        last_rotated=row["last_rotated"],
        created_at=row["created_at"],
        labels=json.loads(row["labels"]),
    )


# ---------------------------------------------------------------------------
# Core operations
# ---------------------------------------------------------------------------

def create_secret(
    name: str,
    namespace: str,
    secret_type: str,
    data: dict,
    master_key: str,
    rotation_schedule: int = 90,
    labels: Optional[dict] = None,
    db: Optional[sqlite3.Connection] = None,
) -> Secret:
    """Create and persist a new encrypted secret."""
    conn = db or _get_db()
    salt = uuid.uuid4().hex
    encrypted = encrypt_dict(data, master_key, salt)
    now = time.time()
    s = Secret(
        name=name,
        namespace=namespace,
        type=secret_type,
        data_encrypted=encrypted,
        salt=salt,
        rotation_schedule=rotation_schedule,
        last_rotated=now,
        created_at=now,
        labels=labels or {},
    )
    conn.execute(
        """INSERT INTO secrets
           (id,name,namespace,type,data_encrypted,salt,version,
            rotation_schedule,last_rotated,created_at,labels)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (s.id, s.name, s.namespace, s.type, json.dumps(s.data_encrypted),
         s.salt, s.version, s.rotation_schedule, s.last_rotated, s.created_at,
         json.dumps(s.labels)),
    )
    conn.commit()
    audit_log(AuditAction.CREATE.value, s.id, name, namespace, db=conn)
    return s


def get_secret(
    secret_id: str,
    master_key: str,
    db: Optional[sqlite3.Connection] = None,
) -> Optional[dict]:
    """Retrieve and decrypt a secret by ID. Returns plaintext dict or None."""
    conn = db or _get_db()
    row = conn.execute("SELECT * FROM secrets WHERE id=?", (secret_id,)).fetchone()
    if not row:
        return None
    s = _row_to_secret(row)
    audit_log(AuditAction.READ.value, s.id, s.name, s.namespace, db=conn)
    plaintext = decrypt_dict(s.data_encrypted, master_key, s.salt)
    return {
        "id": s.id,
        "name": s.name,
        "namespace": s.namespace,
        "type": s.type,
        "version": s.version,
        "data": plaintext,
        "labels": s.labels,
        "last_rotated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(s.last_rotated)),
        "age_days": round(s.age_days(), 1),
    }


def get_secret_by_name(
    name: str,
    namespace: str,
    master_key: str,
    db: Optional[sqlite3.Connection] = None,
) -> Optional[dict]:
    conn = db or _get_db()
    row = conn.execute("SELECT id FROM secrets WHERE name=? AND namespace=?", (name, namespace)).fetchone()
    if not row:
        return None
    return get_secret(row["id"], master_key, db=conn)


def rotate_secret(
    secret_id: str,
    new_data: dict,
    master_key: str,
    rotated_by: str = "system",
    db: Optional[sqlite3.Connection] = None,
) -> Secret:
    """Rotate a secret: archive old version, encrypt and store new data."""
    conn = db or _get_db()
    row = conn.execute("SELECT * FROM secrets WHERE id=?", (secret_id,)).fetchone()
    if not row:
        raise ValueError(f"Secret {secret_id} not found")
    s = _row_to_secret(row)

    # Archive current version
    conn.execute(
        "INSERT INTO secret_versions (id,secret_id,version,data_encrypted,salt,rotated_at,rotated_by) VALUES (?,?,?,?,?,?,?)",
        (str(uuid.uuid4()), s.id, s.version, json.dumps(s.data_encrypted), s.salt, time.time(), rotated_by),
    )

    # Encrypt new data with a fresh salt
    new_salt = uuid.uuid4().hex
    new_encrypted = encrypt_dict(new_data, master_key, new_salt)
    new_version = s.version + 1
    now = time.time()

    conn.execute(
        """UPDATE secrets SET data_encrypted=?, salt=?, version=?, last_rotated=?
           WHERE id=?""",
        (json.dumps(new_encrypted), new_salt, new_version, now, secret_id),
    )
    conn.commit()
    audit_log(AuditAction.ROTATE.value, secret_id, s.name, s.namespace,
              details=f"rotated to version {new_version}", db=conn)
    s.data_encrypted = new_encrypted
    s.salt = new_salt
    s.version = new_version
    s.last_rotated = now
    return s


def delete_secret(secret_id: str, db: Optional[sqlite3.Connection] = None) -> bool:
    conn = db or _get_db()
    row = conn.execute("SELECT name, namespace FROM secrets WHERE id=?", (secret_id,)).fetchone()
    if not row:
        return False
    conn.execute("DELETE FROM secrets WHERE id=?", (secret_id,))
    conn.commit()
    audit_log(AuditAction.DELETE.value, secret_id, row["name"], row["namespace"], db=conn)
    return True


# ---------------------------------------------------------------------------
# Rotation monitoring
# ---------------------------------------------------------------------------

def check_rotation_due(days_threshold: int = 30, db: Optional[sqlite3.Connection] = None) -> list[dict]:
    """Return list of secrets whose rotation is due within days_threshold days."""
    conn = db or _get_db()
    rows = conn.execute("SELECT * FROM secrets").fetchall()
    due = []
    for row in rows:
        s = _row_to_secret(row)
        age = s.age_days()
        remaining = s.rotation_schedule - age
        if remaining <= days_threshold:
            due.append({
                "id": s.id,
                "name": s.name,
                "namespace": s.namespace,
                "version": s.version,
                "age_days": round(age, 1),
                "rotation_schedule_days": s.rotation_schedule,
                "days_until_due": round(remaining, 1),
                "overdue": remaining <= 0,
            })
    return sorted(due, key=lambda x: x["days_until_due"])


def list_secrets(namespace: Optional[str] = None, db: Optional[sqlite3.Connection] = None) -> list[dict]:
    """List secrets (without plaintext data)."""
    conn = db or _get_db()
    query = "SELECT * FROM secrets" + (" WHERE namespace=?" if namespace else "")
    params = (namespace,) if namespace else ()
    rows = conn.execute(query, params).fetchall()
    return [
        {
            "id": r["id"],
            "name": r["name"],
            "namespace": r["namespace"],
            "type": r["type"],
            "version": r["version"],
            "rotation_schedule": r["rotation_schedule"],
            "age_days": round((time.time() - r["last_rotated"]) / 86400, 1),
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Environment injection
# ---------------------------------------------------------------------------

def inject_to_env(
    secret_id: str,
    master_key: str,
    prefix: str = "",
    db: Optional[sqlite3.Connection] = None,
) -> dict[str, str]:
    """
    Decrypt a secret and return a dict suitable for os.environ injection.
    Keys are uppercased and optionally prefixed.
    """
    conn = db or _get_db()
    row = conn.execute("SELECT * FROM secrets WHERE id=?", (secret_id,)).fetchone()
    if not row:
        raise ValueError(f"Secret {secret_id} not found")
    s = _row_to_secret(row)
    plaintext = decrypt_dict(s.data_encrypted, master_key, s.salt)
    env_vars: dict[str, str] = {}
    for k, v in plaintext.items():
        env_key = (prefix.upper() + "_" + k.upper()).lstrip("_")
        env_vars[env_key] = v
    # Actually inject into os.environ
    os.environ.update(env_vars)
    audit_log(AuditAction.INJECT.value, s.id, s.name, s.namespace,
              details=f"injected {len(env_vars)} vars", db=conn)
    return env_vars


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def audit_log(
    action: str,
    secret_id: str,
    secret_name: str,
    namespace: str,
    actor: str = "system",
    details: str = "",
    success: bool = True,
    db: Optional[sqlite3.Connection] = None,
) -> AuditEntry:
    conn = db or _get_db()
    entry = AuditEntry(
        action=action,
        secret_id=secret_id,
        secret_name=secret_name,
        namespace=namespace,
        actor=actor,
        details=details,
        success=success,
    )
    conn.execute(
        "INSERT INTO audit_log (id,action,secret_id,secret_name,namespace,actor,details,success,timestamp) VALUES (?,?,?,?,?,?,?,?,?)",
        (entry.id, entry.action, entry.secret_id, entry.secret_name,
         entry.namespace, entry.actor, entry.details, int(entry.success), entry.timestamp),
    )
    conn.commit()
    return entry


def get_audit_log(secret_id: Optional[str] = None, limit: int = 100, db: Optional[sqlite3.Connection] = None) -> list[dict]:
    conn = db or _get_db()
    if secret_id:
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE secret_id=? ORDER BY timestamp DESC LIMIT ?",
            (secret_id, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
    return [
        {
            "id": r["id"],
            "action": r["action"],
            "secret_name": r["secret_name"],
            "namespace": r["namespace"],
            "actor": r["actor"],
            "details": r["details"],
            "success": bool(r["success"]),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(r["timestamp"])),
        }
        for r in rows
    ]


def get_secret_versions(secret_id: str, db: Optional[sqlite3.Connection] = None) -> list[dict]:
    conn = db or _get_db()
    rows = conn.execute(
        "SELECT version, rotated_at, rotated_by FROM secret_versions WHERE secret_id=? ORDER BY version DESC",
        (secret_id,),
    ).fetchall()
    return [
        {
            "version": r["version"],
            "rotated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(r["rotated_at"])),
            "rotated_by": r["rotated_by"],
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli_main() -> None:
    import argparse, sys

    p = argparse.ArgumentParser(prog="secrets_operator", description="BlackRoad Secrets Operator")
    sub = p.add_subparsers(dest="cmd")

    cr = sub.add_parser("create", help="Create a secret")
    cr.add_argument("name")
    cr.add_argument("--namespace", default="default")
    cr.add_argument("--type", default="Opaque", dest="secret_type", choices=[t.value for t in SecretType])
    cr.add_argument("--data", required=True, help="JSON dict of key:value pairs")
    cr.add_argument("--master-key", required=True)
    cr.add_argument("--rotation-days", type=int, default=90)

    gt = sub.add_parser("get", help="Get and decrypt a secret")
    gt.add_argument("id")
    gt.add_argument("--master-key", required=True)

    rt = sub.add_parser("rotate", help="Rotate a secret")
    rt.add_argument("id")
    rt.add_argument("--data", required=True, help="JSON new data")
    rt.add_argument("--master-key", required=True)

    sub.add_parser("list", help="List secrets (no plaintext)")
    ls_ns = sub.get_parser if hasattr(sub, "get_parser") else None

    due = sub.add_parser("due", help="Check rotation due")
    due.add_argument("--days", type=int, default=30)

    inj = sub.add_parser("inject", help="Inject secret to env")
    inj.add_argument("id")
    inj.add_argument("--master-key", required=True)
    inj.add_argument("--prefix", default="")

    aud = sub.add_parser("audit", help="View audit log")
    aud.add_argument("--id", default=None, dest="secret_id")
    aud.add_argument("--limit", type=int, default=20)

    args = p.parse_args()
    db = _get_db()

    if args.cmd == "create":
        data = json.loads(args.data)
        s = create_secret(args.name, args.namespace, args.secret_type, data,
                          args.master_key, rotation_schedule=args.rotation_days, db=db)
        print(json.dumps({"id": s.id, "name": s.name, "version": s.version}, indent=2))
    elif args.cmd == "get":
        result = get_secret(args.id, args.master_key, db=db)
        print(json.dumps(result, indent=2))
    elif args.cmd == "rotate":
        data = json.loads(args.data)
        s = rotate_secret(args.id, data, args.master_key, db=db)
        print(json.dumps({"id": s.id, "version": s.version}, indent=2))
    elif args.cmd == "list":
        print(json.dumps(list_secrets(db=db), indent=2))
    elif args.cmd == "due":
        print(json.dumps(check_rotation_due(days_threshold=args.days, db=db), indent=2))
    elif args.cmd == "inject":
        env_vars = inject_to_env(args.id, args.master_key, prefix=args.prefix, db=db)
        print(json.dumps({k: "***" for k in env_vars}, indent=2))
    elif args.cmd == "audit":
        print(json.dumps(get_audit_log(args.secret_id, limit=args.limit, db=db), indent=2))
    else:
        p.print_help()
        sys.exit(1)


if __name__ == "__main__":
    _cli_main()
