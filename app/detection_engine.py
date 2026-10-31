"""PHANTOM 6.0 read-only behavioral analysis engine.
Signals are explainable leads, never malware verdicts.
"""
from __future__ import annotations
import os, re, ipaddress, socket
from datetime import datetime, timezone
import psutil

ENCODED = re.compile(r"(?:-enc(?:odedcommand)?\s+[a-z0-9+/=]{20,}|frombase64string\s*\()", re.I)
DOWNLOAD = re.compile(r"(?:downloadstring\s*\(|invoke-webrequest|\biwr\s+https?://|\b(?:curl|wget)\s+https?://)", re.I)
SCHEDULE = re.compile(r"(?:schtasks(?:\.exe)?.{0,80}/create|\bat\.exe\s+\d)", re.I)
SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}
OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
LOLBINS = {"mshta.exe", "rundll32.exe", "regsvr32.exe", "installutil.exe"}

def _safe_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False

def analyze_endpoint():
    rows=[]; by_pid={}; denied=0
    for p in psutil.process_iter(["pid","name","exe","cmdline","ppid","username","create_time"]):
        try:
            x=p.info
            item={"pid":x.get("pid"),"name":x.get("name") or "unknown","exe":x.get("exe") or "",
                  "cmdline":" ".join(x.get("cmdline") or [])[:700],"ppid":x.get("ppid"),
                  "username":x.get("username") or "unknown","create_time":x.get("create_time")}
            rows.append(item); by_pid[item["pid"]]=item
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            denied+=1
    leads=[]
    for p in rows:
        name=p["name"].lower(); exe=p["exe"].lower(); cmd=p["cmdline"]
        reasons=[]; techniques=[]; score=0
        def add(reason, points, technique=None):
            nonlocal score
            reasons.append(reason); score += points
            if technique: techniques.append(technique)
        if ENCODED.search(cmd): add("Encoded PowerShell/.NET command pattern found in the command line.", 35, {"id":"T1059.001","name":"PowerShell"})
        if DOWNLOAD.search(cmd): add("Command line contains a web-download or remote-content pattern.", 20, {"id":"T1105","name":"Ingress Tool Transfer"})
        if SCHEDULE.search(cmd): add("Command line appears to create a scheduled task or job.", 20, {"id":"T1053.005","name":"Scheduled Task"})
        if name in LOLBINS and re.search(r"https?://|javascript:|vbscript:|scrobj\.dll|\b(?:-enc|/s|/u)\b",cmd,re.I):
            add("A signed Windows utility has command-line arguments often seen in proxy execution; verify context.", 20, {"id":"T1218","name":"System Binary Proxy Execution"})
        if exe:
            norm=exe.replace("/","\\")
            if re.search(r"\\(users\\[^\\]+\\appdata\\(local\\temp|roaming)|windows\\temp)\\",norm,re.I):
                add("Executable is running from a user-writable temporary location.", 20)
            if re.search(r"\\(users\\public|downloads)\\",norm,re.I):
                add("Executable is running from a commonly user-writable folder; verify its origin.", 10)
        parent=by_pid.get(p.get("ppid"))
        if parent and parent["name"].lower() in OFFICE and name in SCRIPT_HOSTS:
            add(f"Script or command interpreter was launched by {parent['name']}.", 30, {"id":"T1210","name":"Unusual parent-child process context"})
        if score:
            score=min(score,100)
            leads.append({"pid":p["pid"],"process_name":p["name"],"executable":p["exe"],"parent_pid":p["ppid"],
                          "parent_name":parent["name"] if parent else "unknown","username":p["username"],
                          "command_line":cmd,"score":score,"severity":"high" if score>=60 else "medium" if score>=30 else "low",
                          "reasons":reasons,"mitre":techniques,
                          "recommendation":"Verify the full command line, file origin, signature, hash and user activity. Do not terminate or delete based on this signal alone."})
    # Network context: summarize public remote endpoints per owning process; no IP is labeled malicious.
    network=[]; public_remote_count=0; net_denied=False
    try:
        for c in psutil.net_connections(kind="inet"):
            if not c.pid: continue
            remote=""
            if c.raddr:
                try: remote=c.raddr.ip
                except AttributeError: remote=str(c.raddr).split(":")[0]
            if remote and _safe_ip(remote): public_remote_count+=1
            proc=by_pid.get(c.pid)
            network.append({"pid":c.pid,"process":proc["name"] if proc else "unknown","remote_ip":remote or None,
                            "public_remote":bool(remote and _safe_ip(remote)),"status":c.status or "NONE"})
    except (psutil.AccessDenied, OSError):
        net_denied=True
    leads.sort(key=lambda x:x["score"],reverse=True)
    return {"captured_at":datetime.now(timezone.utc).isoformat(),"process_count":len(rows),"processes":rows,"processes_checked":len(rows),
            "access_limited_processes":denied,"connection_count":len(network),"public_remote_connections":public_remote_count,
            "network_visibility_limited":net_denied,"findings":leads,"finding_count":len(leads),
            "ruleset":"PHANTOM-6.0-local-heuristics","limitations":["Heuristic signals can produce false positives and are not malware verdicts.",
            "Network IP classification only distinguishes public from private addresses; it does not determine reputation.",
            "Windows permissions may hide process command lines or network connections.",
            "No process termination, file deletion, quarantine or firewall changes are performed."]}
