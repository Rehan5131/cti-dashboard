# utils/db.py
import os
from pymongo import MongoClient, ASCENDING, TEXT

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.environ.get("MONGO_DB", "cti_dashboard")

client = MongoClient(MONGO_URI)
db = client[DB_NAME]

IOCS = db["iocs"]
LOOKUPS = db["lookups"]
METRICS = db["metrics"]

# indexes (safe to re-run)
try:
    IOCS.create_index([("value", ASCENDING)], unique=True)
    IOCS.create_index([("type", ASCENDING)])
    IOCS.create_index([("tags", ASCENDING)])
    IOCS.create_index([("value", TEXT)])
    LOOKUPS.create_index([("ts", ASCENDING)])
    METRICS.create_index([("bucket", ASCENDING)], unique=True)
except Exception:
    pass
