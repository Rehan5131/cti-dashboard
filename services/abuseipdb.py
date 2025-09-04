# services/abuseipdb.py
import os
import requests

ABUSE_KEY = os.environ.get("ABUSEIPDB_API_KEY")
BASE = "https://api.abuseipdb.com/api/v2"

def ip_check(ip: str):
    if not ABUSE_KEY:
        return {"error": {"code": "NoApiKey", "message": "AbuseIPDB API key not set"}}
    try:
        r = requests.get(
            f"{BASE}/check",
            headers={"Key": ABUSE_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=20
        )
        return r.json()
    except Exception as e:
        return {"error": {"code": "RequestError", "message": str(e)}}
