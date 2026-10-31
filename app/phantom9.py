"""PHANTOM 9.0 evidence correlation and report assembly."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any

def build_evidence():
    from . import phantom8, phantom7, database
    alerts=phantom8.list_alerts(200).get("alerts",[])
    incidents=phantom7.list_incidents().get("incidents",[])
    events=database.recent_events(200)
    # Correlate alerts to cases using process/PID and incident references where available.
    case_by_id={int(x["id"]):x for x in incidents}
    correlated=[]
    for a in alerts:
        evidence=a.get("evidence") or {}
        related=[]
        if a.get("incident_id") and int(a["incident_id"]) in case_by_id:
            related.append(case_by_id[int(a["incident_id"])])
        pid=evidence.get("pid")
        pname=(evidence.get("process_name") or "").lower()
        for inc in incidents:
            text=(inc.get("title","")+" "+inc.get("summary","")).lower()
            if (pname and pname in text) or (pid is not None and str(pid) in text):
                if inc not in related: related.append(inc)
        correlated.append({"alert_id":a["id"],"title":a["title"],"severity":a["severity"],
            "source":a["source"],"first_seen":a["first_seen"],"last_seen":a["last_seen"],
            "occurrences":a["occurrences"],"acknowledged":bool(a["acknowledged"]),
            "evidence":evidence,"related_incidents":related})
    return {"generated_at":datetime.now(timezone.utc).isoformat(),
        "summary":{"alerts":len(alerts),"incidents":len(incidents),"events":len(events),
                   "unacknowledged_alerts":sum(not x.get("acknowledged") for x in alerts)},
        "correlations":correlated,"incidents":incidents,"recent_events":events[:100],
        "limitations":["Correlations use available alert evidence and incident text/IDs; they are not proof of causation.",
                       "Only telemetry already collected by PHANTOM is included.",
                       "AI analysis is advisory and depends on the configured local Ollama model."]}

def ai_context():
    report=build_evidence()
    # Bound context to keep local model prompts manageable.
    return report, str(report)[:18000]
