import json, os, sqlite3
from datetime import datetime, timezone
from .config import DB_PATH

def connect():
    folder=os.path.dirname(DB_PATH)
    if folder: os.makedirs(folder,exist_ok=True)
    conn=sqlite3.connect(DB_PATH)
    conn.row_factory=sqlite3.Row
    return conn

def init_db():
    with connect() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT, scanned_at TEXT NOT NULL,
            process_count INTEGER NOT NULL, finding_count INTEGER NOT NULL,
            findings_json TEXT NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at TEXT NOT NULL,
            event_type TEXT NOT NULL, process_name TEXT, pid INTEGER,
            details TEXT NOT NULL)""")

def save_scan(process_count,findings):
    now=datetime.now(timezone.utc).isoformat()
    with connect() as conn:
        cur=conn.execute("INSERT INTO scans(scanned_at,process_count,finding_count,findings_json) VALUES(?,?,?,?)",
                         (now,process_count,len(findings),json.dumps(findings)))
        conn.execute("INSERT INTO security_events(occurred_at,event_type,process_name,pid,details) VALUES(?,?,?,?,?)",
                     (now,"scan_completed",None,None,json.dumps({"process_count":process_count,"finding_count":len(findings)})))
        return cur.lastrowid,now

def recent_scans(limit=20):
    with connect() as conn:
        rows=conn.execute("SELECT id,scanned_at,process_count,finding_count FROM scans ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
        return [dict(r) for r in rows]

def get_scan(scan_id):
    with connect() as conn:
        row=conn.execute("SELECT * FROM scans WHERE id=?",(scan_id,)).fetchone()
        if not row:return None
        item=dict(row);item["findings"]=json.loads(item.pop("findings_json"));return item

def add_event(event_type,process_name=None,pid=None,details=None):
    now=datetime.now(timezone.utc).isoformat()
    with connect() as conn:
        conn.execute("INSERT INTO security_events(occurred_at,event_type,process_name,pid,details) VALUES(?,?,?,?,?)",
                     (now,event_type,process_name,pid,json.dumps(details or {})))

def recent_events(limit=100):
    with connect() as conn:
        rows=conn.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
        out=[]
        for row in rows:
            item=dict(row);item["details"]=json.loads(item["details"]);out.append(item)
        return out
