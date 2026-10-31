"""PHANTOM 8.0 automatic, read-only endpoint monitoring and alerting."""
from __future__ import annotations
import hashlib, json, sqlite3, threading, time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

APP_DIR=Path(__file__).resolve().parent
DB_PATH=APP_DIR.parent/"data"/"phantom8.db"
INTERVAL_SECONDS=90
IOC_INTERVAL_SECONDS=300
_DEDUPE_SECONDS=1800
_stop=threading.Event()
_thread:threading.Thread|None=None
_state_lock=threading.Lock()
_state={"running":False,"last_scan":None,"last_ioc_scan":None,"last_error":None,"scan_count":0,"next_scan_seconds":INTERVAL_SECONDS}

def _now(): return datetime.now(timezone.utc).isoformat()
def _db():
    DB_PATH.parent.mkdir(parents=True,exist_ok=True)
    c=sqlite3.connect(DB_PATH,timeout=10)
    c.row_factory=sqlite3.Row
    return c

def init():
    with _db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL UNIQUE,
            source TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL,
            summary TEXT NOT NULL, evidence_json TEXT NOT NULL,
            first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, occurrences INTEGER NOT NULL DEFAULT 1,
            acknowledged INTEGER NOT NULL DEFAULT 0, incident_id INTEGER)""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_last_seen ON alerts(last_seen DESC)")
        c.execute("""CREATE TABLE IF NOT EXISTS monitor_runs(
            id INTEGER PRIMARY KEY AUTOINCREMENT, captured_at TEXT NOT NULL,
            process_count INTEGER NOT NULL, connection_count INTEGER NOT NULL,
            finding_count INTEGER NOT NULL, ioc_matches INTEGER NOT NULL DEFAULT 0,
            duration_ms INTEGER NOT NULL, error TEXT)""")

def _fingerprint(source:str,title:str,evidence:dict[str,Any])->str:
    stable={k:evidence.get(k) for k in ("pid","process_name","ioc_id","value","rule")}
    raw=json.dumps([source,title,stable],sort_keys=True,default=str)
    return hashlib.sha256(raw.encode()).hexdigest()

def _upsert_alert(source,severity,title,summary,evidence,auto_incident=False):
    now=_now(); fp=_fingerprint(source,title,evidence)
    with _db() as c:
        row=c.execute("SELECT * FROM alerts WHERE fingerprint=?",(fp,)).fetchone()
        if row:
            # Suppress repeated notifications for the same signal during the dedupe window,
            # while preserving occurrence count and last-seen time.
            c.execute("UPDATE alerts SET last_seen=?,occurrences=occurrences+1,summary=?,evidence_json=? WHERE id=?",
                      (now,summary,json.dumps(evidence,default=str)[:12000],row["id"]))
            return None
        incident_id=None
        if auto_incident:
            try:
                from . import phantom7
                inc=phantom7.create_incident(title,severity,summary,[evidence])
                incident_id=inc.get("id")
            except Exception:
                incident_id=None
        c.execute("""INSERT INTO alerts(fingerprint,source,severity,title,summary,evidence_json,first_seen,last_seen,incident_id)
                     VALUES(?,?,?,?,?,?,?,?,?)""",
                  (fp,source,severity,title,summary,json.dumps(evidence,default=str)[:12000],now,now,incident_id))
        return c.execute("SELECT * FROM alerts WHERE id=last_insert_rowid()").fetchone()

def _run_once(include_ioc=True):
    from .detection_engine import analyze_endpoint
    started=time.perf_counter(); snap=analyze_endpoint(); new_alerts=[]
    for f in snap.get("findings",[]):
        sev=(f.get("severity") or "low").lower()
        if sev not in {"medium","high","critical"}: continue
        title=f"Behavioral signal: {f.get('process_name','unknown')} (PID {f.get('pid','?')})"
        evidence={"pid":f.get("pid"),"process_name":f.get("process_name"),"executable":f.get("executable"),
                  "parent_name":f.get("parent_name"),"score":f.get("score"),"reasons":f.get("reasons",[]),
                  "mitre":f.get("mitre",[]),"rule":"local_behavior_heuristic"}
        row=_upsert_alert("behavior",sev,title,"; ".join(f.get("reasons",[])),evidence,auto_incident=sev in {"high","critical"})
        if row: new_alerts.append(dict(row))
    ioc_count=0; ioc_error=None
    # IOC scan is slower because SHA-256 indicators may require reading executable files.
    try:
        from . import phantom7
        ioc=phantom7.scan_local() if include_ioc else {"match_count":0,"matches":[]}
        ioc_count=ioc.get("match_count",0)
        for m in ioc.get("matches",[]):
            title=f"Local IOC exact match: {m.get('kind')} {m.get('value')}"
            evidence={**m,"rule":"configured_ioc_exact_match"}
            row=_upsert_alert("ioc","medium",title,m.get("detail","Exact configured IOC match"),evidence,auto_incident=False)
            if row: new_alerts.append(dict(row))
        if include_ioc:
            with _state_lock: _state["last_ioc_scan"]=_now()
    except Exception as e:
        ioc_error=f"IOC scan: {type(e).__name__}: {e}"
    duration=int((time.perf_counter()-started)*1000)
    with _db() as c:
        c.execute("INSERT INTO monitor_runs(captured_at,process_count,connection_count,finding_count,ioc_matches,duration_ms) VALUES(?,?,?,?,?,?)",
                  (snap.get("captured_at",_now()),snap.get("process_count",0),snap.get("connection_count",0),snap.get("finding_count",0),ioc_count,duration))
    with _state_lock:
        _state.update({"last_scan":snap.get("captured_at",_now()),"last_error":ioc_error,"scan_count":_state["scan_count"]+1})
    try:
        from . import database
        for a in new_alerts:
            database.add_event("security_alert_created",a.get("title"),None,
                               {"alert_id":a.get("id"),"severity":a.get("severity"),"source":a.get("source")})
    except Exception: pass
    return {"snapshot":snap,"new_alerts":len(new_alerts),"duration_ms":duration}

def _worker():
    last_ioc=0.0
    with _state_lock: _state["running"]=True
    while not _stop.is_set():
        try:
            # run once includes an IOC pass; throttle complete cycles to avoid resource pressure
            do_ioc=(last_ioc==0.0 or time.monotonic()-last_ioc>=IOC_INTERVAL_SECONDS)
            _run_once(include_ioc=do_ioc)
            if do_ioc: last_ioc=time.monotonic()
        except Exception as e:
            with _state_lock: _state["last_error"]=f"{type(e).__name__}: {e}"
            try:
                with _db() as c:
                    c.execute("INSERT INTO monitor_runs(captured_at,process_count,connection_count,finding_count,ioc_matches,duration_ms,error) VALUES(?,0,0,0,0,0,?)",(_now(),str(e)[:500]))
            except Exception: pass
        for remaining in range(INTERVAL_SECONDS,0,-1):
            if _stop.wait(1): break
            with _state_lock: _state["next_scan_seconds"]=remaining-1
    with _state_lock: _state["running"]=False

def start():
    global _thread
    if _thread and _thread.is_alive(): return
    _stop.clear(); _thread=threading.Thread(target=_worker,name="phantom8-monitor",daemon=True);_thread.start()
def stop():
    _stop.set()
    if _thread and _thread.is_alive(): _thread.join(timeout=5)

def health():
    with _state_lock: state=dict(_state)
    with _db() as c:
        state["unacknowledged_alerts"]=c.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged=0").fetchone()[0]
        state["total_alerts"]=c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        latest=c.execute("SELECT captured_at FROM monitor_runs ORDER BY id DESC LIMIT 1").fetchone()
        state["persisted_last_scan"]=latest[0] if latest else None
    state["interval_seconds"]=INTERVAL_SECONDS
    state["ioc_interval_seconds"]=IOC_INTERVAL_SECONDS
    state["mode"]="local read-only monitoring"
    return state

def list_alerts(limit=100):
    with _db() as c: rows=[dict(r) for r in c.execute("SELECT * FROM alerts ORDER BY last_seen DESC LIMIT ?",(max(1,min(limit,500)),))]
    for r in rows:
        try:r["evidence"]=json.loads(r.pop("evidence_json"))
        except Exception:r["evidence"]={}
    return {"alerts":rows,"count":len(rows)}

def acknowledge(alert_id:int):
    with _db() as c:
        cur=c.execute("UPDATE alerts SET acknowledged=1 WHERE id=?",(alert_id,))
    return cur.rowcount>0

def analytics():
    with _db() as c:
        by_severity={r[0]:r[1] for r in c.execute("SELECT severity,COUNT(*) FROM alerts GROUP BY severity")}
        by_source={r[0]:r[1] for r in c.execute("SELECT source,COUNT(*) FROM alerts GROUP BY source")}
        runs=[dict(r) for r in c.execute("SELECT captured_at,process_count,connection_count,finding_count,ioc_matches,duration_ms FROM monitor_runs ORDER BY id DESC LIMIT 24")]
    return {"by_severity":by_severity,"by_source":by_source,"recent_runs":runs}
