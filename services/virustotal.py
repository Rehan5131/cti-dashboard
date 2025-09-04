# services/virustotal.py
import os
import requests

VT_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
BASE = "https://www.virustotal.com/api/v3"

def _get(url):
    if not VT_KEY:
        return {"error": {"code": "NoApiKey", "message": "VirusTotal API key not set"}}
    try:
        r = requests.get(url, headers={"x-apikey": VT_KEY}, timeout=20)
        return r.json()
    except Exception as e:
        return {"error": {"code": "RequestError", "message": str(e)}}

def ip_report(ip: str):
    return _get(f"{BASE}/ip_addresses/{ip}")

def domain_report(domain: str):
    return _get(f"{BASE}/domains/{domain}")
