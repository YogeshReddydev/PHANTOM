"""PHANTOM 7.0 local IOC matching and incident case store.
All matching is local. Indicators are analyst-provided; matches are leads, not verdicts.
"""
from __future__ import annotations
import hashlib, ipaddress, json, os, sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

APP_DIR=Path(__file__).resolve().parent
DB_PATH=APP_DIR.parent/"data"/"phantom7.db"

def _now():
    return datetime.now(timezone.utc).isoformat()

def _db():
    DB_PATH.parent.mkdir(parents=True,exist_ok=True)
    c=sqlite3.connect(DB_PATH)
    c.row_factory=sqlite3.Row
    return c

def init():
    with _db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS iocs(
            id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL,
            value TEXT NOT NULL, label TEXT DEFAULT '', source TEXT DEFAULT 'manual',
            created_at TEXT NOT NULL, UNIQUE(kind,value))""")
        c.execute("""CREATE TABLE IF NOT EXISTS incidents(
            id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'low', status TEXT NOT NULL DEFAULT 'open',
            summary TEXT DEFAULT '', evidence_json TEXT DEFAULT '[]',
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS matches(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ioc_id INTEGER, kind TEXT,
            value TEXT, observed TEXT, process_name TEXT, pid INTEGER,
            detail TEXT, matched_at TEXT NOT NULL)""")

def list_iocs():
    with _db() as c:
        rows=[dict(r) for r in c.execute("SELECT * FROM iocs ORDER BY created_at DESC")]
    return {"indicators":rows,"count":len(rows)}

def add_ioc(kind:str,value:str,label:str="",source:str="manual"):
    kind=kind.strip().lower(); value=value.strip()
    if kind not in {"ip","domain","sha256","process"}:
        raise ValueError("Type must be ip, domain, sha256 or process")
    if not value or len(value)>512: raise ValueError("Indicator value is required (max 512 characters)")
    if kind=="sha256" and (len(value)!=64 or any(ch not in "0123456789abcdefABCDEF" for ch in value)):
        raise ValueError("SHA-256 must contain exactly 64 hexadecimal characters")
    if kind=="ip":
        try: ipaddress.ip_address(value)
        except ValueError: raise ValueError("Enter a valid IPv4 or IPv6 address")
    if kind=="domain":
        value=value.lower().rstrip(".")
        if "." not in value or any(ch.isspace() for ch in value): raise ValueError("Enter a valid domain name")
    if kind=="process": value=value.lower()
    with _db() as c:
        try:
            cur=c.execute("INSERT INTO iocs(kind,value,label,source,created_at) VALUES(?,?,?,?,?)",
                          (kind,value,label[:160],source[:80],_now()))
        except sqlite3.IntegrityError:
            raise ValueError("That indicator already exists")
        row=c.execute("SELECT * FROM iocs WHERE id=?",(cur.lastrowid,)).fetchone()
    return dict(row)

def delete_ioc(ioc_id:int):
    with _db() as c:
        cur=c.execute("DELETE FROM iocs WHERE id=?",(ioc_id,))
    return cur.rowcount>0

def _hash_file(path:str):
    try:
        if not path or not os.path.isfile(path): return None
        if os.path.getsize(path)>100*1024*1024: return None
        h=hashlib.sha256()
        with open(path,"rb") as f:
            for chunk in iter(lambda:f.read(1024*1024),b""): h.update(chunk)
        return h.hexdigest()
    except (OSError,PermissionError): return None

def scan_local():
    """Match configured IOCs against a bounded current endpoint snapshot."""
    from .detection_engine import analyze_endpoint
    snap=analyze_endpoint()
    with _db() as c:
        iocs=[dict(r) for r in c.execute("SELECT * FROM iocs")]
    by_kind={}
    for i in iocs: by_kind.setdefault(i["kind"],[]).append(i)
    matches=[]; hashed=set()
    def add(i,observed,proc="",pid=None,detail=""):
        matches.append({"ioc_id":i["id"],"kind":i["kind"],"value":i["value"],
                        "observed":observed,"process_name":proc,"pid":pid,"detail":detail})
    for proc in snap.get("processes",[]):
        name=(proc.get("name") or "").lower()
        exe=proc.get("exe") or ""
        for i in by_kind.get("process",[]):
            if name==i["value"].lower(): add(i,name,name,proc.get("pid"),"Process name exact match")
        for i in by_kind.get("sha256",[]):
            if exe and exe not in hashed:
                hashed.add(exe); digest=_hash_file(exe)
                if digest and digest.lower()==i["value"].lower():
                    add(i,digest,name,proc.get("pid"),"Executable SHA-256 exact match")
    for conn in snap.get("network",[]):
        ip=conn.get("remote_ip") or ""
        for i in by_kind.get("ip",[]):
            if ip and ip==i["value"]: add(i,ip,conn.get("process",""),conn.get("pid"),"Remote IP exact match")
    # Domain IOCs are stored for analyst use; process/socket telemetry has no reliable DNS query mapping here.
    with _db() as c:
        c.execute("DELETE FROM matches")
        for m in matches:
            c.execute("""INSERT INTO matches(ioc_id,kind,value,observed,process_name,pid,detail,matched_at)
                         VALUES(?,?,?,?,?,?,?,?)""",
                      (m["ioc_id"],m["kind"],m["value"],m["observed"],m["process_name"],m["pid"],m["detail"],_now()))
    return {"captured_at":snap.get("captured_at"),"processes_checked":snap.get("processes_checked",0),
            "connections_checked":snap.get("connection_count",0),"indicator_count":len(iocs),
            "match_count":len(matches),"matches":matches,
            "note":"Exact local matches only. Domain indicators are stored but not matched because DNS query telemetry is not currently collected. A match is an investigation lead, not a malware verdict."}

def list_matches():
    with _db() as c:
        rows=[dict(r) for r in c.execute("SELECT * FROM matches ORDER BY matched_at DESC")]
    return {"matches":rows,"count":len(rows)}

def list_incidents():
    with _db() as c:
        rows=[dict(r) for r in c.execute("SELECT id,title,severity,status,summary,created_at,updated_at FROM incidents ORDER BY updated_at DESC")]
    return {"incidents":rows,"count":len(rows)}

def create_incident(title:str,severity:str="low",summary:str="",evidence:Any=None):
    if not title.strip(): raise ValueError("Incident title is required")
    if severity not in {"low","medium","high","critical"}: raise ValueError("Invalid severity")
    ev=json.dumps(evidence if isinstance(evidence,list) else [],ensure_ascii=False)[:20000]
    now=_now()
    with _db() as c:
        cur=c.execute("""INSERT INTO incidents(title,severity,status,summary,evidence_json,created_at,updated_at)
                         VALUES(?,?, 'open',?,?,?,?)""",(title[:180],severity,summary[:4000],ev,now,now))
        row=c.execute("SELECT * FROM incidents WHERE id=?",(cur.lastrowid,)).fetchone()
    out=dict(row);out["evidence"]=json.loads(out.pop("evidence_json"))
    return out

def update_incident(incident_id:int,status:str):
    if status not in {"open","investigating","contained","resolved","closed"}:
        raise ValueError("Status must be open, investigating, contained, resolved or closed")
    with _db() as c:
        cur=c.execute("UPDATE incidents SET status=?,updated_at=? WHERE id=?",(status,_now(),incident_id))
        row=c.execute("SELECT * FROM incidents WHERE id=?",(incident_id,)).fetchone()
    if not row: return None
    out=dict(row);out["evidence"]=json.loads(out.pop("evidence_json"))
    return out
