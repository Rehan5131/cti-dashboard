import os
import io
import csv
import re
from urllib.parse import urlparse
from flask import Flask, render_template, request, redirect, url_for, jsonify, Response, flash
from apscheduler.schedulers.background import BackgroundScheduler
from bson.objectid import ObjectId

from utils.db import IOCS, LOOKUPS, METRICS
from utils.helpers import now_ts, format_ts
from collectors.osint_feeds import fetch_and_store
from services import virustotal as vt, abuseipdb as abuse

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

# -------- detection helpers --------
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_DOMAIN_RE = re.compile(r"^(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")

def looks_like_ip(s: str) -> bool:
    if not s or not _IP_RE.match(s):
        return False
    parts = s.split(".")
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False

def normalize_domain_or_url(q: str):
    """Return ('domain'|'url'|'unknown', value)"""
    q = q.strip()
    if not q:
        return "unknown", q
    try:
        p = urlparse(q if "://" in q else "http://" + q)
        if p.scheme and p.netloc:
            if p.path and p.path not in ("/", ""):
                return "url", f"{p.scheme}://{p.netloc}{p.path}"
            host = p.netloc
            return ("domain" if _DOMAIN_RE.match(host) else "unknown"), host
    except Exception:
        pass
    return ("domain" if _DOMAIN_RE.match(q) else "unknown"), q

# -------- pages --------
@app.route("/")
def dashboard():
    today = now_ts().strftime("%Y-%m-%d")
    doc = METRICS.find_one({"bucket": today}) or {}
    totals = doc.get("totals", {
        "ip": IOCS.count_documents({"type": "ip"}),
        "domain": IOCS.count_documents({"type": "domain"}),
        "url": IOCS.count_documents({"type": "url"}),
        "hash": IOCS.count_documents({"type": "hash"}),
    })
    targets = {"ip": 500, "domain": 300, "url": 200, "hash": 100}
    return render_template("dashboard.html", totals=totals, targets=targets)

@app.route("/charts")
def charts():
    return render_template("charts.html")

@app.route("/history")
def history():
    items = list(LOOKUPS.find().sort("ts", -1).limit(300))
    for it in items:
        it["_id_str"] = str(it["_id"])
        it["ts_str"] = format_ts(it.get("ts"))
    return render_template("history.html", lookups=items)

@app.route("/history/export.csv")
def history_export():
    cur = LOOKUPS.find().sort("ts", -1)
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["query", "kind", "ts"])
    for d in cur:
        cw.writerow([d.get("query"), d.get("kind"), format_ts(d.get("ts"))])
    return Response(si.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=lookup_history.csv"})

@app.route("/history/delete", methods=["POST"])
def history_delete():
    _id = request.form.get("_id")
    if _id:
        LOOKUPS.delete_one({"_id": ObjectId(_id)})
        flash("Record deleted.", "success")
    else:
        flash("Missing id.", "warning")
    return redirect(url_for("history"))

@app.route("/lookup_result")
def lookup_result():
    q = request.args.get("q", "").strip()
    if not q:
        flash("Missing query", "warning")
        return redirect(url_for("dashboard"))

    if looks_like_ip(q):
        kind, value = "ip", q
    else:
        kind, value = normalize_domain_or_url(q)

    vt_res, abuse_res, vt_error = None, None, None

    try:
        if kind == "ip":
            vt_res = vt.ip_report(value)
            abuse_res = abuse.ip_check(value)
        elif kind == "domain":
            vt_res = vt.domain_report(value)
        elif kind == "url":
            vt_res = vt.domain_report(urlparse(value).netloc)
    except Exception as e:
        vt_error = str(e)

    if isinstance(vt_res, dict) and "error" in vt_res and vt_res["error"].get("code") == "WrongCredentialsError":
        vt_error = "VirusTotal API key is invalid. Please set VIRUSTOTAL_API_KEY."

    local = IOCS.find_one({"value": value})
    LOOKUPS.insert_one({"query": q, "kind": kind, "ts": now_ts()})

    return render_template(
        "result.html",
        query=q,
        resolved=value,
        kind=kind,
        vt=vt_res,
        vt_error=vt_error,
        abuse=abuse_res,
        local=local
    )

@app.route("/tag_from_result", methods=["POST"])
def tag_from_result():
    value = request.form.get("value", "").strip()
    ioc_type = request.form.get("ioc_type", "").strip()
    tag = request.form.get("tag", "").strip()

    if not value:
        flash("Missing IOC value.", "warning")
        return redirect(url_for("dashboard"))

    update = {"$setOnInsert": {"first_seen": now_ts()},
              "$set": {"last_seen": now_ts()}}
    if ioc_type in ("ip", "domain", "url", "hash"):
        update["$set"]["type"] = ioc_type
    if tag:
        update["$addToSet"] = {"tags": tag}

    IOCS.update_one({"value": value}, update, upsert=True)
    flash("IOC saved/updated.", "success")
    return redirect(url_for("lookup_result", q=value))

@app.route("/export_iocs.csv")
def export_iocs():
    cur = IOCS.find({}, {"_id": 0, "value": 1, "type": 1, "sources": 1, "last_seen": 1, "tags": 1})
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["value", "type", "sources", "last_seen", "tags"])
    for d in cur:
        cw.writerow([d.get("value"),
                     d.get("type"),
                     ";".join(d.get("sources", [])),
                     format_ts(d.get("last_seen")),
                     ";".join(d.get("tags", []))])
    return Response(si.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=iocs.csv"})

# -------- API for charts --------
@app.route("/api/metrics")
def api_metrics():
    docs = list(METRICS.find({}, {"bucket": 1, "counts": 1, "totals": 1}).sort("bucket", 1))
    daily = []
    for d in docs:
        counts = d.get("counts", {})
        ingested_sum = sum(v for k, v in counts.items() if k.startswith("ingested."))
        daily.append({"bucket": d.get("bucket"), "count": ingested_sum})

    today_bucket = now_ts().strftime("%Y-%m-%d")
    today_totals = (METRICS.find_one({"bucket": today_bucket}) or {}).get("totals", {})
    if not today_totals:
        today_totals = {
            "ip": IOCS.count_documents({"type": "ip"}),
            "domain": IOCS.count_documents({"type": "domain"}),
            "url": IOCS.count_documents({"type": "url"}),
            "hash": IOCS.count_documents({"type": "hash"})
        }
    return jsonify({"daily": daily, "totals": today_totals})

@app.route("/api/boxplot")
def api_boxplot():
    pipeline = [
        {"$group": {"_id": "$type", "count": {"$sum": 1}}}
    ]
    data = list(IOCS.aggregate(pipeline))
    return jsonify(data)

# -------- scheduler & ingest --------
scheduler = BackgroundScheduler(daemon=True)

def ingest_job():
    ingested_by_source = fetch_and_store(IOCS, METRICS)
    bucket = now_ts().strftime("%Y-%m-%d")

    totals = {
        "ip": IOCS.count_documents({"type": "ip"}),
        "domain": IOCS.count_documents({"type": "domain"}),
        "url": IOCS.count_documents({"type": "url"}),
        "hash": IOCS.count_documents({"type": "hash"}),
    }
    METRICS.update_one({"bucket": bucket}, {"$set": {"totals": totals}}, upsert=True)

    if ingested_by_source:
        inc_doc = {f"counts.ingested.{src}": cnt for src, cnt in ingested_by_source.items() if cnt}
        if inc_doc:
            METRICS.update_one({"bucket": bucket}, {"$inc": inc_doc}, upsert=True)

interval_min = int(os.environ.get("INGEST_INTERVAL_MIN", 10))
scheduler.add_job(ingest_job, "interval", minutes=interval_min, id="ingest_job")
scheduler.start()

try:
    ingest_job()
except Exception:
    pass

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
