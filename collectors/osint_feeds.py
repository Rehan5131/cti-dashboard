# collectors/osint_feeds.py
import csv
import io
import requests
from utils.helpers import now_ts

URLHAUS_RECENT_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"
FEODO_IPBLOCKLIST_JSON = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

def _safe_get(url, timeout=20):
    return requests.get(url, timeout=timeout, headers={"User-Agent": "CTI-Dashboard/1.0"})

def fetch_urlhaus(IOCS):
    """
    Fetch recent URLHaus CSV and upsert first N entries as URL or domain IOCs.
    """
    resp = _safe_get(URLHAUS_RECENT_CSV)
    resp.raise_for_status()
    text = resp.text

    # URLHaus CSV has many comment lines starting with '#'
    lines = [ln for ln in text.splitlines() if not ln.startswith("#")]
    data = csv.reader(lines)
    count = 0
    max_rows = 100  # limit for demo

    for row in data:
        # Expected columns: id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter
        if len(row) < 5:
            continue
        url = row[2].strip()
        threat = row[4].strip() or "malicious"
        if not url:
            continue
        # store as URL
        IOCS.update_one(
            {"value": url},
            {"$set": {"type": "url", "sources": ["urlhaus"], "last_seen": now_ts()},
             "$addToSet": {"tags": threat}},
            upsert=True
        )
        count += 1
        if count >= max_rows:
            break
    return count

def fetch_feodo(IOCS):
    """
    Fetch Feodo Tracker IP blocklist JSON and upsert IP IOCs.
    """
    resp = _safe_get(FEODO_IPBLOCKLIST_JSON)
    resp.raise_for_status()
    js = resp.json()
    ips = js.get("ips", []) or js.get("data", [])  # some variants
    count = 0
    max_rows = 100

    for it in ips[:max_rows]:
        ip = it.get("ip", "").strip() or it.get("indicator", "").strip()
        if not ip:
            continue
        IOCS.update_one(
            {"value": ip},
            {"$set": {"type": "ip", "sources": ["feodo"], "last_seen": now_ts()},
             "$addToSet": {"tags": "c2"}},
            upsert=True
        )
        count += 1
    return count

def fetch_and_store(IOCS, METRICS):
    """
    Pull from open feeds and return a dict of per-source ingested counts.
    The METRICS update is done in app.py so charts react immediately.
    """
    result = {}
    try:
        c1 = fetch_urlhaus(IOCS)
        result["urlhaus"] = c1
    except Exception:
        # avoid crash if source is temporarily unreachable
        result["urlhaus"] = 0

    try:
        c2 = fetch_feodo(IOCS)
        result["feodo"] = c2
    except Exception:
        result["feodo"] = 0

    return result
