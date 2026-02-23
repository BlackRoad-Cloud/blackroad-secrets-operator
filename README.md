# blackroad-secrets-operator

> Kubernetes-style secrets operator with XOR encryption, versioning, rotation scheduling, audit logging, and environment injection. Zero external dependencies.

## Features

- **6 secret types**: Opaque, TLS, SSH, Docker, BasicAuth, ServiceAccountToken
- **XOR cipher encryption** with per-secret salt (no `cryptography` library required)
- **Secret versioning** — every rotation archives the previous version
- **Rotation scheduling** — configurable per-secret rotation window
- **Rotation due alerts** — query secrets approaching their rotation deadline
- **Audit log** — immutable append-only log of CREATE/READ/ROTATE/DELETE/INJECT
- **Environment injection** — decrypt directly into `os.environ` with optional prefix
- **SQLite persistence** — `~/.blackroad/secrets_operator.db`

## Quick start

```bash
pip install -r requirements.txt

# Create a secret
python src/secrets_operator.py create db-creds \
  --data '{"host":"db.internal","password":"s3cr3t"}' \
  --master-key my-master-key

# Get (decrypts)
python src/secrets_operator.py get <id> --master-key my-master-key

# Rotate
python src/secrets_operator.py rotate <id> \
  --data '{"host":"db.internal","password":"n3w-p@ss"}' \
  --master-key my-master-key

# Check rotation due
python src/secrets_operator.py due --days 30

# Inject to env
python src/secrets_operator.py inject <id> --master-key my-master-key --prefix APP

# Audit log
python src/secrets_operator.py audit --limit 20
```

## API

```python
from src.secrets_operator import (
    create_secret, get_secret, rotate_secret,
    check_rotation_due, inject_to_env, get_audit_log,
)

MASTER_KEY = "my-master-key"

# Create
s = create_secret("db-creds", "production", "Opaque",
    {"host": "10.0.0.1", "password": "hunter2"}, MASTER_KEY)

# Read (returns plaintext)
result = get_secret(s.id, MASTER_KEY)
print(result["data"]["password"])  # hunter2

# Rotate
rotate_secret(s.id, {"host": "10.0.0.1", "password": "newpass"}, MASTER_KEY)

# Rotation due
due = check_rotation_due(days_threshold=30)

# Inject to env
env_vars = inject_to_env(s.id, MASTER_KEY, prefix="DB")
# os.environ["DB_HOST"] == "10.0.0.1"

# Audit
log = get_audit_log(s.id, limit=10)
```

## Encryption

Uses XOR cipher with SHA-256 key derivation (10,000 iterations + unique salt per secret). Suitable for development and internal use.

## Testing

```bash
pytest tests/ -v
```
