# utils/helpers.py
from datetime import datetime, timezone

def now_ts():
    return datetime.now(timezone.utc)

def format_ts(ts):
    if ts is None:
        return ""
    try:
        return ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)
