const $=id=>document.getElementById(id);let latest=null,liveData=null,deepLatest=null,refreshInFlight=false;
const esc=v=>String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
async function api(url,opt={}){const r=await fetch(url,opt);if(!r.ok){let m=`Request failed (${r.status})`;try{m=(await r.json()).detail||m}catch{}throw Error(m)}return r.json()}
function toast(t){const e=$("toast");e.textContent=t;e.classList.add("show");setTimeout(()=>e.classList.remove("show"),2500)}
function renderProcesses(d){const rows=d.processes||[];$("live-count").textContent=rows.length;$("live-time").textContent=new Date(d.captured_at).toLocaleTimeString();$("process-table").innerHTML=rows.map(p=>`<tr><td>${esc(p.name)}</td><td>${p.pid??"—"}</td><td>${esc(p.status)}</td><td title="${esc(p.exe)}">${esc(p.exe||"Unavailable")}</td></tr>`).join("")||'<tr><td colspan="4">No process data available.</td></tr>';$("process-preview").innerHTML=rows.slice(0,6).map(p=>`<div class="preview-row"><b>${esc(p.name)}</b><small>PID ${p.pid??"—"}</small></div>`).join("")}
function renderFindings(findings){$("finding-count").textContent=findings.length;$("detection-list").innerHTML=findings.length?findings.map(f=>`<article class="lead"><div><b>${esc(f.process_name)} · PID ${f.pid??"—"}</b><span class="risk">${esc(f.severity)} · ${f.score??"—"}/100</span></div><p>${(f.reasons||[]).map(esc).join("<br>")}</p><small>${esc(f.recommendation||"Verify evidence before action.")}</small></article>`).join(""):'<p class="empty">No behavioral rules matched this snapshot. This does not prove the endpoint is threat-free.</p>';$("finding-preview").innerHTML=findings.length?findings.slice(0,4).map(f=>`<div class="preview-row"><b>${esc(f.process_name)}</b><small>${esc(f.severity)} · ${f.score??"—"}/100</small></div>`).join(""):'<p class="empty">No current investigation leads.</p>'}
function renderNetwork(rows){$("network-table").innerHTML=rows.map(n=>`<tr><td>${esc(n.process)}</td><td>${n.pid??"—"}</td><td>${esc(n.type)}</td><td>${esc(n.local)}</td><td>${esc(n.remote||"—")}</td><td>${esc(n.status)}</td></tr>`).join("")||'<tr><td colspan="6">No visible connections. Permissions may limit visibility.</td></tr>'}
function renderMitre(findings){const seen=new Map();findings.forEach(f=>(f.mitre||[]).forEach(m=>seen.set(m.id,m.name)));$("mitre-list").innerHTML=seen.size?[...seen].map(([id,name])=>`<div class="preview-row"><b>${esc(id)} · ${esc(name)}</b><small>Technique reference from local heuristic rule</small></div>`).join(""):'<p class="empty">No MITRE technique mappings in this snapshot.</p>'}

function renderSocDashboard(d,deep){
 const findings=deep.findings||[], network=d.network||[], processes=liveData?.processes||[];
 const counts={critical:0,high:0,medium:0,low:0};
 findings.forEach(f=>{const k=String(f.severity||"low").toLowerCase();counts[counts[k]!==undefined?k:"low"]++});
 const total=findings.length, colors={critical:"#ff5d68",high:"#ff9a58",medium:"#f4c75e",low:"#48d6a0"};
 $("donut-total").textContent=total;
 let cursor=0;const stops=[];
 Object.entries(counts).forEach(([k,v])=>{const next=cursor+(total?v/total*100:0);stops.push(`${colors[k]} ${cursor}% ${next}%`);cursor=next});
 $("severity-donut").style.background=total?`conic-gradient(${stops.join(",")})`:"conic-gradient(#26372d 0 100%)";
 $("severity-legend").innerHTML=Object.entries(counts).map(([k,v])=>`<span><i class="sev-${k}"></i>${k[0].toUpperCase()+k.slice(1)} <b>${v}</b></span>`).join("");
 const techniques=new Map();findings.forEach(f=>(f.mitre||[]).forEach(m=>techniques.set(m.id,m.name)));
 $("technique-count").textContent=techniques.size;
 $("risk-processes").textContent=d.process_count;$("risk-network").textContent=d.connection_count;$("risk-leads").textContent=total;
 $("inventory-process").textContent=d.process_count;$("inventory-connections").textContent=d.connection_count;
 $("inventory-iocs").textContent=Object.values(d.indicator_counts||{}).reduce((a,b)=>a+b,0);$("inventory-mitre").textContent=techniques.size;
 $("latest-leads").innerHTML=findings.length?findings.slice(0,4).map(f=>`<div class="compact-row"><b>${esc(f.process_name)} · PID ${f.pid??"—"}</b><small class="severity-text">${esc(f.severity)} · ${f.score??"—"}/100</small></div>`).join(""):'<p class="empty">No local rules matched this snapshot. This is not proof of a threat-free endpoint.</p>';
 const procTop=processes.slice(0,5);
 $("activity-bars").innerHTML=procTop.length?procTop.map((p,i)=>`<div class="activity-row"><span>${esc(p.name||"Unknown")}</span><b>PID ${p.pid??"—"}</b></div>`).join(""):'<p class="empty">Waiting for process snapshot…</p>';
 $("dashboard-mitre").innerHTML=techniques.size?[...techniques].slice(0,5).map(([id,name])=>`<div class="compact-row"><b>${esc(id)}</b><small>${esc(name)}</small></div>`).join(""):'<p class="empty">No technique mappings in this snapshot.</p>';
 $("network-total").textContent=network.length;$("network-public").textContent=deep.public_remote_connections??"—";
 $("network-preview").innerHTML=network.slice(0,3).map(n=>`<div class="compact-row"><b>${esc(n.process||"Unknown process")}</b><small>${esc(n.remote||"Remote endpoint unavailable")}</small></div>`).join("")||'<p class="empty">No visible connections.</p>';
 $("coverage-process").textContent=`${deep.processes_checked} / ${deep.processes_checked}`;$("coverage-network").textContent=`${deep.connection_count} / ${deep.connection_count}`;
 $("coverage-process-bar").style.width=deep.processes_checked?"100%":"0%";$("coverage-network-bar").style.width=deep.connection_count?"100%":"0%";
}
async function refresh(){if(refreshInFlight)return;refreshInFlight=true;const b=$("refresh-btn");b.disabled=true;b.textContent="REFRESHING…";try{const d=await api("/api/advanced/overview");latest=d;const deep=await api("/api/detection/deep");deepLatest=deep;$("deep-process-count").textContent=deep.processes_checked;$("deep-network-count").textContent=deep.connection_count;$("deep-findings-count").textContent=deep.finding_count;$("deep-public-count").textContent=deep.public_remote_connections;$("deep-ruleset").textContent=`${deep.ruleset} · ${new Date(deep.captured_at).toLocaleTimeString()}`;$("deep-limitations").innerHTML=deep.limitations.map(x=>`<li>${esc(x)}</li>`).join("");if(deep.findings.length){$("detection-list").innerHTML=deep.findings.map(f=>`<article class="lead"><div><b>${esc(f.process_name)} · PID ${f.pid??"—"}</b><span class="risk">${esc(f.severity)} · ${f.score}/100</span></div><p>${f.reasons.map(esc).join("<br>")}</p><small>Parent: ${esc(f.parent_name)} · User: ${esc(f.username)}</small><p><small>${esc(f.recommendation)}</small></p><details><summary>View command line and evidence</summary><pre>${esc(f.command_line||"Command line unavailable")}</pre><small>${(f.mitre||[]).map(m=>esc(m.id+" · "+m.name)).join(" | ")}</small></details></article>`).join("")}else{$("detection-list").innerHTML='<p class="empty">No PHANTOM 6.0 behavioral rules matched this snapshot. This does not prove the endpoint is threat-free.</p>'}$("process-count").textContent=d.process_count;$("connection-count").textContent=d.connection_count;$("indicator-count").textContent=Object.values(d.indicator_counts||{}).reduce((a,b)=>a+b,0);renderFindings(deep.findings||[]);renderNetwork(d.network||[]);renderMitre(deep.findings||[]);renderSocDashboard(d,deep);$("ioc-counts").textContent=Object.entries(d.indicator_counts||{}).map(([k,v])=>`${k.replace("_"," ")}: ${v}`).join("  ·  ");toast("Security intelligence refreshed");await loadHistory()}catch(e){toast(e.message)}finally{refreshInFlight=false;b.disabled=false;b.textContent="↻  REFRESH INTELLIGENCE"}}
async function poll(){try{liveData=await api("/api/live");renderProcesses(liveData);if(latest&&deepLatest)renderSocDashboard(latest,deepLatest)}catch{}}
async function events(){try{const d=await api("/api/events");$("timeline-list").innerHTML=d.events.length?d.events.map(e=>`<div class="event"><time>${new Date(e.occurred_at).toLocaleString()}</time><b>${esc(e.event_type.replaceAll("_"," "))}</b><small>${esc(e.process_name||JSON.stringify(e.details))}</small></div>`).join(""):'<p class="empty">No events recorded.</p>'}catch{}}
async function loadHistory(){try{const d=await api("/api/history");$("history-list").innerHTML=d.scans.length?d.scans.map(s=>`<div class="event"><time>${new Date(s.scanned_at).toLocaleString()}</time><b>Scan #${s.id}</b><small>${s.process_count} processes · ${s.finding_count} indicators</small></div>`).join(""):'<p class="empty">No scans recorded.</p>';$("scan-trend").innerHTML=d.scans.length?d.scans.slice(0,8).reverse().map(s=>`<div class="trend-column"><i style="height:${Math.max(8,Math.min(100,(s.finding_count||0)*12+8))}%"></i><small>#${s.id}</small></div>`).join(""):'<p class="empty">No saved scan history yet.</p>'}catch{}}
async function hashFile(){const path=$("file-path").value.trim();if(!path){toast("Enter a file path");return}const out=$("hash-result");out.textContent="Inspecting file…";try{const d=await api("/api/file-integrity",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({path})});out.textContent=`File: ${d.file_name}\nSHA-256: ${d.sha256}\nAuthenticode: ${d.signature_status}\nSigner: ${d.signer||"Not available"}\n\n${d.signature_note}`}catch(e){out.textContent=e.message}}
async function chat(){const q=$("chat-question").value.trim();if(!q){toast("Enter a question");return}const out=$("chat-answer"),b=$("chat-btn");b.disabled=true;out.textContent="Waiting for local Qwen response…";let context="";if($("include-context").checked&&latest)context=JSON.stringify({process_count:latest.process_count,connection_count:latest.connection_count,findings:latest.findings,network:(latest.network||[]).slice(0,20)}).slice(0,2400);try{const d=await api("/api/chat",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({question:q,context})});out.textContent=d.explanation||"No response"}catch(e){out.textContent=e.message}finally{b.disabled=false}}

async function loadIocs(){
 try{const d=await api("/api/v7/iocs");$("ioc-total").textContent=`${d.count} INDICATORS`;
 $("ioc-table").innerHTML=d.indicators.length?`<table><thead><tr><th>TYPE</th><th>VALUE</th><th>LABEL</th><th></th></tr></thead><tbody>${d.indicators.map(i=>`<tr><td>${esc(i.kind)}</td><td>${esc(i.value)}</td><td>${esc(i.label||i.source)}</td><td><button class="mini-action" data-del-ioc="${i.id}">Remove</button></td></tr>`).join("")}</tbody></table>`:'<p class="empty">No indicators configured yet. Add verified indicators to begin.</p>';
 }catch(e){toast("IOC list: "+e.message)}
}
async function addIoc(){
 const kind=$("ioc-kind").value,value=$("ioc-value").value.trim(),label=$("ioc-label").value.trim();
 if(!value){toast("Enter an indicator value");return}
 try{await api("/api/v7/iocs",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({kind,value,label})});$("ioc-value").value="";$("ioc-label").value="";await loadIocs();toast("Local indicator added")}
 catch(e){toast(e.message)}
}
async function scanIocs(){
 const b=$("ioc-scan-btn");b.disabled=true;b.textContent="SCANNING…";
 try{const d=await api("/api/v7/intel/scan",{method:"POST"});$("ioc-match-total").textContent=`${d.match_count} MATCHES`;
 $("ioc-match-list").innerHTML=d.matches.length?d.matches.map(m=>`<article class="lead"><div><b>${esc(m.kind.toUpperCase())} · ${esc(m.value)}</b><span class="risk">${esc(m.process_name||"Endpoint match")} · PID ${m.pid??"—"}</span></div><p>${esc(m.detail)}</p><small>Observed: ${esc(m.observed)}</small></article>`).join(""):`<p class="empty">No exact matches found across ${d.processes_checked} processes and ${d.connections_checked} connections. This does not establish that the endpoint is threat-free.</p>`;
 toast(`Local IOC scan complete: ${d.match_count} matches`);
 }catch(e){toast("IOC scan: "+e.message)}finally{b.disabled=false;b.textContent="RUN LOCAL IOC SCAN"}
}
async function loadIncidents(){
 try{const d=await api("/api/v7/incidents");$("incident-total").textContent=`${d.count} CASES`;
 $("incident-list").innerHTML=d.incidents.length?d.incidents.map(i=>`<div class="case-row"><div><b>#${i.id} · ${esc(i.title)}</b><small>${esc(i.severity.toUpperCase())} · Created ${new Date(i.created_at).toLocaleString()}</small><p>${esc(i.summary||"No summary supplied.")}</p></div><select data-case-status="${i.id}">${["open","investigating","contained","resolved","closed"].map(s=>`<option value="${s}" ${s===i.status?"selected":""}>${s}</option>`).join("")}</select></div>`).join(""):'<p class="empty">No incident cases yet. Create a case when evidence needs tracking.</p>';
 }catch(e){toast("Incident register: "+e.message)}
}
async function createIncident(){
 const title=$("incident-title").value.trim();if(!title){toast("Enter a case title");return}
 try{await api("/api/v7/incidents",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({title,severity:$("incident-severity").value,summary:$("incident-summary").value})});$("incident-title").value="";$("incident-summary").value="";await loadIncidents();toast("Investigation case created")}
 catch(e){toast(e.message)}
}
document.addEventListener("click",async e=>{
 const del=e.target.closest("[data-del-ioc]");if(del){try{await api(`/api/v7/iocs/${del.dataset.delIoc}`,{method:"DELETE"});await loadIocs();toast("Indicator removed")}catch(err){toast(err.message)}}
});
document.addEventListener("change",async e=>{
 const sel=e.target.closest("[data-case-status]");if(sel){try{await api(`/api/v7/incidents/${sel.dataset.caseStatus}`,{method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify({status:sel.value})});await loadIncidents();toast("Case status updated")}catch(err){toast(err.message)}}
});
$("ioc-add-btn").addEventListener("click",addIoc);
$("ioc-scan-btn").addEventListener("click",scanIocs);
$("incident-create-btn").addEventListener("click",createIncident);
loadIocs();loadIncidents();


let seenAlertIds=new Set(),automationInitialized=false;
async function loadAutomation(){
 try{
  const [h,a]=await Promise.all([api("/api/v8/health"),api("/api/v8/alerts")]);
  const status=$("monitor-health");
  status.innerHTML=`<i></i> ${h.running?"AUTO MONITOR ACTIVE":"MONITOR OFFLINE"}`;
  status.style.color=h.running?"#42e2cf":"#ff7188";
  $("alert-status-tag").textContent=h.running?`ACTIVE · ${h.interval_seconds}s CYCLE`:"MONITOR OFFLINE";
  $("alert-open-count").textContent=h.unacknowledged_alerts;
  $("alert-total-count").textContent=h.total_alerts;
  $("monitor-last-scan").textContent=h.last_scan?new Date(h.last_scan).toLocaleTimeString():"Pending";
  $("monitor-next-scan").textContent=h.running?`${h.next_scan_seconds}s`:"—";
  $("alert-nav-count").textContent=h.unacknowledged_alerts;
  if(h.last_error){$("alert-status-tag").textContent="MONITOR ERROR";$("alert-status-tag").style.color="#ff7188";}
  $("alert-list").innerHTML=a.alerts.length?a.alerts.map(x=>`<article class="alert-card" data-severity="${esc(x.severity)}"><div class="alert-head"><b>#${x.id} · ${esc(x.title)}</b><span class="alert-severity ${esc(x.severity)}">${esc(x.severity)} · ${esc(x.source)}</span></div><p>${esc(x.summary)}</p><small>First seen ${new Date(x.first_seen).toLocaleString()} · Last seen ${new Date(x.last_seen).toLocaleString()} · ${x.occurrences} observations${x.incident_id?` · Case #${x.incident_id}`:""}</small><div class="alert-actions">${x.acknowledged?'<span class="tag">ACKNOWLEDGED</span>':`<button class="alert-ack" data-ack-alert="${x.id}">ACKNOWLEDGE</button>`}<details><summary>Evidence</summary><pre>${esc(JSON.stringify(x.evidence||{},null,2))}</pre></details></div></article>`).join(""):'<p class="empty">No alerts recorded. Automatic monitoring is active; no medium-or-higher local rules have triggered.</p>';
  // Notify only once per newly observed alert in this browser session.
  for(const x of a.alerts){if(!seenAlertIds.has(x.id)){seenAlertIds.add(x.id);if(automationInitialized&&x.acknowledged===0)toast(`PHANTOM ${x.severity.toUpperCase()}: ${x.title}`)}}
  automationInitialized=true;
 }catch(e){const s=$("monitor-health");if(s){s.textContent="MONITOR STATUS UNAVAILABLE";s.style.color="#ff7188"}}
}
async function loadAnalytics(){
 try{const d=await api("/api/v8/analytics");
  const bars=(obj)=>{const entries=Object.entries(obj||{});const max=Math.max(1,...entries.map(x=>x[1]));return entries.length?entries.map(([k,v])=>`<div class="analytics-bar"><span>${esc(k)}</span><div class="analytics-bar-track"><i style="width:${Math.max(2,v/max*100)}%"></i></div><b>${v}</b></div>`).join(""):'<p class="empty">No recorded alerts yet.</p>'};
  $("analytics-severity").innerHTML=bars(d.by_severity);$("analytics-source").innerHTML=bars(d.by_source);
  $("monitor-runs").innerHTML=d.recent_runs.length?`<table><thead><tr><th>TIME</th><th>PROCESSES</th><th>CONNECTIONS</th><th>BEHAVIOURAL LEADS</th><th>IOC MATCHES</th><th>DURATION</th></tr></thead><tbody>${d.recent_runs.map(r=>`<tr><td>${new Date(r.captured_at).toLocaleString()}</td><td>${r.process_count}</td><td>${r.connection_count}</td><td>${r.finding_count}</td><td>${r.ioc_matches}</td><td>${r.duration_ms} ms</td></tr>`).join("")}</tbody></table>`:'<p class="empty">Automatic monitoring history will appear after the first cycle.</p>';
 }catch(e){$("monitor-runs").textContent=e.message}
}
document.addEventListener("click",async e=>{const b=e.target.closest("[data-ack-alert]");if(b){try{await api(`/api/v8/alerts/${b.dataset.ackAlert}/acknowledge`,{method:"POST"});await loadAutomation();toast("Alert acknowledged")}catch(err){toast(err.message)}}});

$("refresh-btn").addEventListener("click",refresh);$("hash-btn").addEventListener("click",hashFile);$("chat-btn").addEventListener("click",chat);
document.querySelectorAll(".nav-link").forEach(a=>a.addEventListener("click",()=>{document.querySelectorAll(".nav-link").forEach(x=>x.classList.remove("active"));a.classList.add("active");$("page-name").textContent=a.textContent.trim().toUpperCase()}));
document.querySelectorAll(".module-card").forEach(a=>a.addEventListener("click",()=>{const target=a.getAttribute("href").slice(1);document.querySelectorAll(".nav-link").forEach(x=>x.classList.toggle("active",x.dataset.target===target))}));
poll();events();loadHistory();refresh();loadAutomation();loadAnalytics();setInterval(poll,5000);setInterval(events,10000);setInterval(loadAutomation,15000);setInterval(loadAnalytics,60000);

// PHANTOM 9.0 evidence correlation and local AI analyst
async function loadV9Evidence(){
 const box=$("evidence-summary"); if(!box)return;
 try{
  const d=await api("/api/v9/evidence"),s=d.summary||{};
  box.innerHTML=`<div class="evidence-metrics"><div><b>${s.alerts??0}</b><small>Alerts</small></div><div><b>${s.incidents??0}</b><small>Incidents</small></div><div><b>${s.events??0}</b><small>Recent events</small></div><div><b>${s.unacknowledged_alerts??0}</b><small>Unacknowledged</small></div></div><p class="form-hint">Generated ${esc(new Date(d.generated_at).toLocaleString())}</p>`;
  $("correlation-list").innerHTML=(d.correlations||[]).length?d.correlations.map(x=>`<article class="lead"><div><b>#${x.alert_id} · ${esc(x.title)}</b><span class="risk">${esc(x.severity.toUpperCase())}</span></div><p>${esc(x.source)} · ${x.occurrences} observation(s) · ${x.acknowledged?"Acknowledged":"Unacknowledged"}</p><small>Process: ${esc(x.evidence?.process_name||"—")} · PID ${esc(x.evidence?.pid??"—")} · Related cases: ${(x.related_incidents||[]).map(i=>"#"+i.id+" "+esc(i.title)).join(", ")||"None linked"}</small></article>`).join(""):'<p class="empty">No alerts available to correlate yet.</p>';
 }catch(e){box.innerHTML=`<p class="empty">Evidence unavailable: ${esc(e.message)}</p>`}
}
async function runV9AI(){
 const q=$("v9-question").value.trim();if(!q){toast("Enter an investigation question");return}
 const b=$("v9-analyse"),out=$("v9-ai-result");b.disabled=true;b.textContent="ANALYSING…";out.textContent="Sending collected evidence to the configured local AI model…";
 try{
  const d=await api("/api/v9/ai-investigate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({question:q})});
  const a=d.analysis;out.innerHTML=`<div class="ai-answer">${esc(typeof a==="string"?a:JSON.stringify(a,null,2))}</div><p class="form-hint">${esc(d.notice||"Advisory analysis only.")}</p>`;
 }catch(e){out.innerHTML=`<p class="empty">AI analysis unavailable: ${esc(e.message)}. Check that Ollama is running and the configured model is installed.</p>`}
 finally{b.disabled=false;b.textContent="ANALYSE LOCAL EVIDENCE"}
}
if($("evidence-refresh"))$("evidence-refresh").addEventListener("click",loadV9Evidence);
if($("v9-analyse"))$("v9-analyse").addEventListener("click",runV9AI);
loadV9Evidence();setInterval(loadV9Evidence,60000);
