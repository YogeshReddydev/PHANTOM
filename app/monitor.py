from datetime import datetime, timezone
import psutil
from .config import MAX_PROCESSES

def collect_processes():
    # Read-only process inventory. Windows may deny access to some fields.
    rows = []
    for proc in psutil.process_iter(attrs=["pid", "ppid", "name", "exe", "cmdline", "username", "status", "create_time"]):
        if len(rows) >= MAX_PROCESSES:
            break
        try:
            info = proc.info
            rows.append({
                "pid": info.get("pid"),
                "ppid": info.get("ppid"),
                "name": info.get("name") or "unknown",
                "exe": info.get("exe") or "",
                "cmdline": " ".join(str(x) for x in (info.get("cmdline") or []))[:700],
                "username": info.get("username") or "",
                "status": info.get("status") or "unknown",
                "create_time": info.get("create_time"),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return {"captured_at": datetime.now(timezone.utc).isoformat(),
            "process_count": len(rows), "processes": rows}
