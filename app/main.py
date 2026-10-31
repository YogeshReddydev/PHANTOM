from pathlib import Path
import json
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from . import database
from .monitor import collect_processes
from .detection import analyze
from .local_ai import explain_finding, investigate_question
from .live_monitor import poll_processes
from .file_integrity import inspect_file
from .advanced import overview as advanced_overview
from .detection_engine import analyze_endpoint
from . import phantom7, phantom8, phantom9

BASE=Path(__file__).resolve().parent
app=FastAPI(title="PHANTOM",description="Local-first cybersecurity demo")
app.mount("/static",StaticFiles(directory=BASE/"static"),name="static")

class ChatRequest(BaseModel):
    question:str=Field(min_length=1,max_length=1500)
    context:str|None=Field(default=None,max_length=2500)
class FileRequest(BaseModel):
    path:str=Field(min_length=1,max_length=1000)
class IOCRequest(BaseModel):
    kind:str=Field(min_length=1,max_length=20)
    value:str=Field(min_length=1,max_length=512)
    label:str=Field(default="",max_length=160)
class IncidentRequest(BaseModel):
    title:str=Field(min_length=1,max_length=180)
    severity:str=Field(default="low")
    summary:str=Field(default="",max_length=4000)
    evidence:list=Field(default_factory=list)
class IncidentUpdate(BaseModel):
    status:str=Field(min_length=1,max_length=30)

@app.on_event("startup")
def startup():
    database.init_db()
    phantom7.init()
    phantom8.init()
    phantom8.start()

@app.get("/")
def dashboard():
    return FileResponse(BASE/"static"/"index.html")

@app.get("/api/status")
def status():
    return {"name":"PHANTOM","status":"online","ai_mode":"local Ollama optional"}

@app.post("/api/scan")
def scan():
    snapshot=collect_processes()
    findings=analyze(snapshot["processes"])
    scan_id,scanned_at=database.save_scan(snapshot["process_count"],findings)
    return {"scan_id":scan_id,"scanned_at":scanned_at,"process_count":snapshot["process_count"],
            "finding_count":len(findings),"findings":findings}

@app.get("/api/history")
def history():
    return {"scans":database.recent_scans()}

@app.post("/api/explain/{scan_id}/{finding_index}")
def explain(scan_id:int,finding_index:int):
    record=database.get_scan(scan_id)
    if not record:raise HTTPException(status_code=404,detail="Scan not found")
    findings=record["findings"]
    if finding_index<0 or finding_index>=len(findings):raise HTTPException(status_code=404,detail="Finding not found")
    return explain_finding(findings[finding_index])

@app.post("/api/chat")
def chat(request:ChatRequest):
    return investigate_question(request.question,request.context)

@app.get("/api/live")
def live():
    return poll_processes()

@app.get("/api/events")
def events():
    return {"events":database.recent_events(100)}

@app.post("/api/file-integrity")
def file_integrity(request:FileRequest):
    result=inspect_file(request.path)
    if not result.get("ok"):raise HTTPException(status_code=400,detail=result.get("error","Unable to inspect file"))
    database.add_event("file_hash_checked",result["file_name"],None,
                       {"sha256":result["sha256"],"signature_status":result["signature_status"]})
    return result


@app.get("/api/advanced/overview")
def advanced_security_overview():
    snapshot=collect_processes()
    result=advanced_overview(snapshot)
    database.add_event("advanced_snapshot",None,None,{"process_count":result["process_count"],"connection_count":result["connection_count"],"finding_count":len(result["findings"])})
    return result


@app.get("/api/detection/deep")
def deep_detection():
    """Read-only PHANTOM 6.0 behavioral analysis."""
    result = analyze_endpoint()
    database.add_event("deep_detection_snapshot", None, None, {
        "process_count": result["process_count"],
        "connection_count": result["connection_count"],
        "finding_count": result["finding_count"],
        "ruleset": result["ruleset"]
    })
    return result


# PHANTOM 7.0 — local threat intelligence and incident management
@app.get("/api/v7/iocs")
def v7_list_iocs():
    return phantom7.list_iocs()

@app.post("/api/v7/iocs")
def v7_add_ioc(request:IOCRequest):
    try:
        return phantom7.add_ioc(request.kind,request.value,request.label)
    except ValueError as e:
        raise HTTPException(status_code=400,detail=str(e))

@app.delete("/api/v7/iocs/{ioc_id}")
def v7_delete_ioc(ioc_id:int):
    if not phantom7.delete_ioc(ioc_id):
        raise HTTPException(status_code=404,detail="Indicator not found")
    return {"deleted":True,"id":ioc_id}

@app.post("/api/v7/intel/scan")
def v7_scan_iocs():
    result=phantom7.scan_local()
    database.add_event("ioc_scan_completed",None,None,{"matches":result["match_count"],"indicators":result["indicator_count"]})
    return result

@app.get("/api/v7/intel/matches")
def v7_matches():
    return phantom7.list_matches()

@app.get("/api/v7/incidents")
def v7_list_incidents():
    return phantom7.list_incidents()

@app.post("/api/v7/incidents")
def v7_create_incident(request:IncidentRequest):
    try:
        result=phantom7.create_incident(request.title,request.severity,request.summary,request.evidence)
        database.add_event("incident_created",None,None,{"incident_id":result["id"],"severity":result["severity"]})
        return result
    except ValueError as e:
        raise HTTPException(status_code=400,detail=str(e))

@app.patch("/api/v7/incidents/{incident_id}")
def v7_update_incident(incident_id:int,request:IncidentUpdate):
    try:
        result=phantom7.update_incident(incident_id,request.status)
    except ValueError as e:
        raise HTTPException(status_code=400,detail=str(e))
    if not result: raise HTTPException(status_code=404,detail="Incident not found")
    return result


@app.on_event("shutdown")
def shutdown_monitor():
    phantom8.stop()

# PHANTOM 8.0 — automated local monitoring, alert center and analytics
@app.get("/api/v8/health")
def v8_health():
    return phantom8.health()

@app.get("/api/v8/alerts")
def v8_alerts():
    return phantom8.list_alerts()

@app.post("/api/v8/alerts/{alert_id}/acknowledge")
def v8_acknowledge_alert(alert_id:int):
    if not phantom8.acknowledge(alert_id):
        raise HTTPException(status_code=404,detail="Alert not found")
    return {"acknowledged":True,"id":alert_id}

@app.get("/api/v8/analytics")
def v8_analytics():
    return phantom8.analytics()


# PHANTOM 9.0 — evidence correlation, local AI analysis and exportable reports
class InvestigationRequest(BaseModel):
    question:str=Field(min_length=1,max_length=1500)

@app.get("/api/v9/evidence")
def v9_evidence():
    return phantom9.build_evidence()

@app.post("/api/v9/ai-investigate")
def v9_ai_investigate(request:InvestigationRequest):
    report,context=phantom9.ai_context()
    question=("Analyse this PHANTOM endpoint evidence. Separate observed facts from hypotheses, "
              "identify related alerts/incidents, explain uncertainty, and recommend safe read-only next checks. "
              "Do not claim malware without evidence. User question: "+request.question)
    try:
        result=investigate_question(question,context)
        return {"evidence_summary":report["summary"],"analysis":result,
                "notice":"Advisory analysis only. Verify findings against the underlying evidence."}
    except Exception as e:
        raise HTTPException(status_code=503,detail=f"Local AI unavailable: {type(e).__name__}: {e}")

@app.get("/api/v9/report.json")
def v9_report_json():
    payload=json.dumps(phantom9.build_evidence(),indent=2,default=str)
    return Response(content=payload,media_type="application/json",
                    headers={"Content-Disposition":"attachment; filename=phantom9-investigation-report.json"})

@app.get("/api/v9/report.html")
def v9_report_html():
    import html
    data=phantom9.build_evidence()
    body=html.escape(json.dumps(data,indent=2,default=str))
    page=f"""<!doctype html><html><head><meta charset='utf-8'><title>PHANTOM 9 Investigation Report</title>
<style>body{{font:14px Segoe UI,Arial;background:#0a1020;color:#f1f4ff;padding:32px}}h1{{color:#42e2cf}}pre{{white-space:pre-wrap;background:#111b30;border:1px solid #2a3c59;padding:20px;border-radius:10px;line-height:1.5}}small{{color:#a99aff}}</style></head>
<body><h1>PHANTOM 9.0 — Investigation Report</h1><small>Generated {html.escape(data['generated_at'])} · Local endpoint evidence</small><pre>{body}</pre></body></html>"""
    return Response(content=page,media_type="text/html",
                    headers={"Content-Disposition":"attachment; filename=phantom9-investigation-report.html"})
