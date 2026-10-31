"""Read-only endpoint telemetry and explainable local heuristic analysis."""
from __future__ import annotations
import json, os, re, socket
from pathlib import Path
from collections import defaultdict
import psutil

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
INDICATORS_FILE = DATA_DIR / "threat_indicators.json"

# These are behavioral clues, not malware signatures. Keep severity conservative.
RULES = [
    ("T1059", "Command and Scripting Interpreter", "encoded_command", re.compile(r"(?:-enc(?:odedcommand)?\s+[a-z0-9+/=]{24,}|frombase64string\s*\()", re.I), 25,
     "Command line contains an encoded PowerShell/.NET command pattern."),
    ("T1218", "System Binary Proxy Execution", "proxy_binary", re.compile(r"(?:^|\\)(?:rundll32|regsvr32|mshta|installutil)\.exe$", re.I), 15,
     "A Windows utility that can be abused to proxy execution is running; it also has legitimate uses."),
    ("T1105", "Ingress Tool Transfer", "download_command", re.compile(r"(?:downloadstring\s*\(|invoke-webrequest|\biwr\s+https?://|curl\s+https?://|wget\s+https?://)", re.I), 20,
     "Command line contains a download-related pattern."),
    ("T1053", "Scheduled Task/Job", "scheduled_task_cli", re.compile(r"(?:schtasks\.exe.*\s/create|at\.exe\s+\d)", re.I), 15,
     "Command line appears to create a scheduled task or job."),
    ("T1547", "Boot or Logon Autostart Execution", "startup_writable", re.compile(r"\\(appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup|programdata\\microsoft\\windows\\start menu\\programs\\startup)\\", re.I), 20,
     "Executable path is in a Windows startup folder."),
]


def load_indicators():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not INDICATORS_FILE.exists():
        INDICATORS_FILE.write_text(json.dumps({"sha256": [], "process_names": [], "domains": [], "notes": "Add verified indicators only. Empty by default."}, indent=2), encoding="utf-8")
    try:
        data=json.loads(INDICATORS_FILE.read_text(encoding="utf-8"))
        return {k:[str(x).lower() for x in data.get(k,[]) if str(x).strip()] for k in ("sha256","process_names","domains")}
    except (OSError, ValueError, TypeError):
        return {"sha256":[],"process_names":[],"domains":[]}


def collect_network():
    rows=[]
    try:
        for c in psutil.net_connections(kind="inet"):
            if not c.pid: continue
            try:
                proc=psutil.Process(c.pid)
                name=proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                name="unknown"
            remote=""
            if c.raddr:
                try: remote=f"{c.raddr.ip}:{c.raddr.port}"
                except AttributeError: remote=str(c.raddr)
            local=""
            if c.laddr:
                try: local=f"{c.laddr.ip}:{c.laddr.port}"
                except AttributeError: local=str(c.laddr)
            rows.append({"pid":c.pid,"process":name,"family":"IPv6" if c.family==socket.AF_INET6 else "IPv4",
                         "type":"TCP" if c.type==socket.SOCK_STREAM else "UDP","local":local,"remote":remote,
                         "status":c.status or "—"})
    except (psutil.AccessDenied, OSError):
        pass
    return rows[:500]


def analyze_snapshot(processes, network):
    indicators=load_indicators(); findings=[]; by_pid={p.get("pid"):p for p in processes}
    for p in processes:
        name=(p.get("name") or ""); exe=(p.get("exe") or ""); cmd=(p.get("cmdline") or "")
        reasons=[]; techniques=[]; score=0
        for tid,technique,key,pattern,weight,reason in RULES:
            value=exe if key in ("proxy_binary","startup_writable") else cmd
            if pattern.search(value or ""):
                reasons.append(reason); techniques.append({"id":tid,"name":technique}); score+=weight
        if name.lower() in indicators["process_names"]:
            reasons.append("Process name matches a locally configured threat indicator."); score+=60
        # Parent-child context is useful evidence, but common parent names alone are not verdicts.
        parent=by_pid.get(p.get("ppid"))
        parent_name=(parent or {}).get("name","")
        if parent and name.lower() in {"powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe"} and parent_name.lower() in {"winword.exe","excel.exe","powerpnt.exe","outlook.exe"}:
            reasons.append(f"Office application is the parent process ({parent_name}); verify whether this launch was expected.")
            score+=25
        if not reasons: continue
        score=min(score,100)
        severity="high" if score>=60 else "medium" if score>=30 else "low"
        findings.append({"pid":p.get("pid"),"process_name":name,"executable":exe,"parent_pid":p.get("ppid"),
                         "parent_name":parent_name,"score":score,"severity":severity,"reasons":reasons,
                         "mitre":techniques,"recommendation":"Verify the process owner, full command line, file signature, hash and expected activity before taking action."})
    return sorted(findings,key=lambda x:x["score"],reverse=True)


def overview(snapshot):
    processes=snapshot.get("processes",[])
    network=collect_network()
    findings=analyze_snapshot(processes,network)
    return {"captured_at":snapshot.get("captured_at"),"process_count":len(processes),"connection_count":len(network),
            "findings":findings,"network":network,"indicator_counts":{k:len(v) for k,v in load_indicators().items()},
            "limitations":"Connection visibility depends on Windows permissions. Heuristics and local indicators are leads, not malware verdicts."}
