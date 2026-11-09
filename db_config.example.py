"""Copy to db_config.local.py. Create the disposable database separately.

This file is never imported automatically. --config must name the local copy.
No password, encryption key or production database name is embedded here.
"""
DATABASE = {
    "host": "127.0.0.1",
    "port": 5432,
    "dbname": "p24_design_batch2a",
    "user": "postgres",
    "password": None,  # Set only in your private local copy if required.
    "connect_timeout": 5,
}
NAMESPACE = "pishkhan24-reviewed-platform-contract-v1"
KEYS_PATH = "private/evidence.keys.json"
VAULT_PATH = "private/evidence_vault"
# Investigation reads fail closed until a trusted external issuer is configured.
# This is the Ed25519 public key only; do not store an issuer private key here.
# ACCESS_PUBLIC_KEY_PATH = "private/access_public.pem"
# ACCESS_ISSUER = "your-reviewed-issuer"
# ACCESS_AUDIENCE = "p24-evidence-inspection"

