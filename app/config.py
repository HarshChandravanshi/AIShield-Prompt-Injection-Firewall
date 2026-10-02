import os

BLOCK_THRESHOLD = int(os.getenv("AIS_SHIELD_BLOCK_THRESHOLD", "70"))
SANITIZE_THRESHOLD = int(os.getenv("AIS_SHIELD_SANITIZE_THRESHOLD", "35"))
AUDIT_LOG_FILE = os.getenv("AIS_SHIELD_LOG_FILE", "ais_shield_audit.jsonl")
