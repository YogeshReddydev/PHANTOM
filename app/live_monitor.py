from threading import Lock
from .monitor import collect_processes
from . import database

_lock=Lock()
_previous=set()

def poll_processes():
    """Read-only process snapshot; records newly observed PID+start-time pairs."""
    global _previous
    snapshot=collect_processes()
    current=set()
    for p in snapshot["processes"]:
        key=(p.get("pid"),p.get("create_time"))
        current.add(key)
    with _lock:
        started=current-_previous if _previous else set()
        _previous=current
    if started:
        by_key={(p.get("pid"),p.get("create_time")):p for p in snapshot["processes"]}
        for key in started:
            p=by_key.get(key,{})
            database.add_event("process_observed",p.get("name"),p.get("pid"),{
                "executable":p.get("exe") or "",
                "username":p.get("username") or "",
                "note":"Newly observed since PHANTOM monitoring began; not inherently suspicious."
            })
    return {
        "captured_at":snapshot["captured_at"],
        "process_count":snapshot["process_count"],
        "processes":[{"pid":p.get("pid"),"name":p.get("name"),"exe":p.get("exe"),
                      "username":p.get("username"),"status":p.get("status"),
                      "create_time":p.get("create_time")} for p in snapshot["processes"]]
    }
