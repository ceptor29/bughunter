from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path

from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# Global state
_projects_dir = Path(".bughunter")
_current_project = ""
_findings_store: list[dict] = []
_scan_running = False
_scan_output: list[str] = []

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Bughunter</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;--text:#c9d1d9;--dim:#8b949e;--blue:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#d29922;--orange:#db6d28}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}

/* Layout */
.app{display:flex;min-height:100vh}
.sidebar{width:220px;background:var(--bg2);border-right:1px solid var(--border);padding:16px 0;flex-shrink:0}
.sidebar .logo{padding:0 16px 16px;font-size:18px;font-weight:700;color:var(--blue);border-bottom:1px solid var(--border);margin-bottom:8px}
.sidebar .logo span{color:var(--dim);font-size:12px;font-weight:400;margin-left:6px}
.sidebar nav a{display:flex;align-items:center;gap:10px;padding:10px 16px;color:var(--dim);font-size:14px;transition:all .15s}
.sidebar nav a:hover,.sidebar nav a.active{color:var(--text);background:var(--bg3)}
.sidebar nav a.active{border-right:2px solid var(--blue)}
.sidebar nav a .icon{width:20px;text-align:center;font-size:16px}
.main{flex:1;padding:24px 32px;max-width:1200px}

/* Cards */
.card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:16px}
.card h2{font-size:16px;margin-bottom:16px;color:var(--text)}
.card h3{font-size:14px;margin-bottom:12px;color:var(--dim)}

/* Forms */
.form-group{margin-bottom:14px}
.form-group label{display:block;font-size:12px;color:var(--dim);margin-bottom:4px;text-transform:uppercase;letter-spacing:.5px}
.form-group input,.form-group select,.form-group textarea{width:100%;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:6px;font-size:14px;font-family:inherit}
.form-group input:focus,.form-group select:focus,.form-group textarea:focus{outline:none;border-color:var(--blue)}
.form-row{display:flex;gap:12px}.form-row .form-group{flex:1}
textarea{min-height:80px;resize:vertical;font-family:monospace;font-size:13px}

/* Buttons */
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border:1px solid var(--border);background:var(--bg3);color:var(--text);border-radius:6px;cursor:pointer;font-size:13px;font-family:inherit;transition:all .15s}
.btn:hover{background:var(--border)}
.btn-primary{background:var(--blue);border-color:var(--blue);color:#fff}
.btn-primary:hover{opacity:.9}
.btn-danger{border-color:var(--red);color:var(--red)}
.btn-danger:hover{background:rgba(248,81,73,.15)}
.btn-success{border-color:var(--green);color:var(--green)}
.btn-success:hover{background:rgba(63,185,80,.15)}
.btn-sm{padding:4px 10px;font-size:12px}

/* Tables */
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:10px 12px;border-bottom:2px solid var(--border);color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
td{padding:8px 12px;border-bottom:1px solid var(--border)}
tr:hover{background:var(--bg3)}

/* Badges */
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600}
.badge-critical{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3)}
.badge-high{background:rgba(210,109,40,.15);color:var(--orange);border:1px solid rgba(210,109,40,.3)}
.badge-medium{background:rgba(210,153,34,.15);color:var(--yellow);border:1px solid rgba(210,153,34,.3)}
.badge-low{background:rgba(139,148,158,.15);color:var(--dim);border:1px solid rgba(139,148,158,.3)}
.badge-info{background:rgba(88,166,255,.15);color:var(--blue);border:1px solid rgba(88,166,255,.3)}
.badge-ok{background:rgba(63,185,80,.15);color:var(--green);border:1px solid rgba(63,185,80,.3)}
.badge-err{background:rgba(248,81,73,.15);color:var(--red);border:1px solid rgba(248,81,73,.3)}

/* Stats row */
.stats{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap}
.stat{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:16px 20px;min-width:140px}
.stat .num{font-size:28px;font-weight:700;color:var(--blue)}
.stat .label{font-size:12px;color:var(--dim);margin-top:2px}
.stat.crit .num{color:var(--red)}
.stat.high .num{color:var(--orange)}
.stat.med .num{color:var(--yellow)}
.stat.low .num{color:var(--dim)}

/* Log output */
.log{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:12px;font-family:monospace;font-size:12px;max-height:300px;overflow-y:auto;white-space:pre-wrap;color:var(--dim);line-height:1.6}

/* Tabs */
.tabs{display:flex;gap:0;border-bottom:2px solid var(--border);margin-bottom:16px}
.tab{padding:10px 16px;cursor:pointer;color:var(--dim);font-size:14px;border-bottom:2px solid transparent;margin-bottom:-2px;transition:all .15s}
.tab:hover{color:var(--text)}
.tab.active{color:var(--blue);border-bottom-color:var(--blue)}
.tab-content{display:none}.tab-content.active{display:block}

/* Toast */
.toast{position:fixed;bottom:24px;right:24px;padding:12px 20px;border-radius:8px;font-size:13px;z-index:1000;animation:slideIn .3s ease}
.toast-ok{background:rgba(63,185,80,.9);color:#fff}
.toast-err{background:rgba(248,81,73,.9);color:#fff}
@keyframes slideIn{from{transform:translateY(20px);opacity:0}to{transform:translateY(0);opacity:1}}
.page{display:none}.page.active{display:block}
</style>
</head>
<body>
<div class="app">
  <div class="sidebar">
    <div class="logo">bughunter<span>v0.1</span></div>
    <nav>
      <a href="#" onclick="showPage('dashboard')" class="active" id="nav-dashboard"><span class="icon">&#9632;</span> Dashboard</a>
      <a href="#" onclick="showPage('scan')" id="nav-scan"><span class="icon">&#9654;</span> New Scan</a>
      <a href="#" onclick="showPage('findings')" id="nav-findings"><span class="icon">&#9888;</span> Findings</a>
      <a href="#" onclick="showPage('auth')" id="nav-auth"><span class="icon">&#128273;</span> Auth Tokens</a>
      <a href="#" onclick="showPage('scope')" id="nav-scope"><span class="icon">&#9898;</span> Scope</a>
      <a href="#" onclick="showPage('modules')" id="nav-modules"><span class="icon">&#9881;</span> Modules</a>
      <a href="#" onclick="showPage('projects')" id="nav-projects"><span class="icon">&#128193;</span> Projects</a>
      <a href="#" onclick="showPage('hunt')" id="nav-hunt"><span class="icon">&#128269;</span> Manual Hunt</a>
    </nav>
  </div>
  <div class="main">

    <!-- DASHBOARD -->
    <div class="page active" id="page-dashboard">
      <h1 style="margin-bottom:20px">Dashboard</h1>
      <div class="stats" id="dash-stats"></div>
      <div class="card">
        <h2>Recent Findings</h2>
        <table><thead><tr><th>Severity</th><th>Title</th><th>Module</th><th>URL</th></tr></thead>
        <tbody id="dash-findings"></tbody></table>
        <p id="dash-empty" style="color:var(--dim);padding:20px;text-align:center">No findings yet. Run a scan first.</p>
      </div>
      <div class="card">
        <h2>Scan Log</h2>
        <div class="log" id="dash-log">No scan running.</div>
      </div>
    </div>

    <!-- NEW SCAN -->
    <div class="page" id="page-scan">
      <h1 style="margin-bottom:20px">New Scan</h1>
      <div class="card">
        <h2>Target</h2>
        <div class="form-row">
          <div class="form-group" style="flex:2"><label>Target domain</label><input id="scan-target" placeholder="example.com"></div>
          <div class="form-group"><label>Profile</label>
            <select id="scan-profile"><option value="safe">safe</option><option value="active">active</option><option value="unrestricted">unrestricted</option></select>
          </div>
        </div>
        <div class="form-row">
          <div class="form-group"><label>Config file</label><input id="scan-config" placeholder="bughunter.yaml"></div>
          <div class="form-group"><label>Manifest (optional)</label><input id="scan-manifest" placeholder="manifest.yaml"></div>
        </div>
        <div class="form-row">
          <div class="form-group"><label><input type="checkbox" id="scan-passive"> Passive only (no HTTP)</label></div>
          <div class="form-group"><label>Rate limit (rps)</label><input id="scan-rps" type="number" value="10"></div>
          <div class="form-group"><label>Concurrency</label><input id="scan-conc" type="number" value="20"></div>
        </div>
        <div style="display:flex;gap:8px;margin-top:8px">
          <button class="btn btn-primary" onclick="startScan()" id="scan-start-btn">&#9654; Start Scan</button>
          <button class="btn btn-danger" onclick="stopScan()" id="scan-stop-btn" style="display:none">&#9632; Stop</button>
        </div>
      </div>
      <div class="card">
        <h2>Scan Output</h2>
        <div class="log" id="scan-log">Waiting to start...</div>
      </div>
    </div>

    <!-- FINDINGS -->
    <div class="page" id="page-findings">
      <h1 style="margin-bottom:20px">Findings</h1>
      <div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap">
        <select id="f-sev" onchange="filterFindings()" style="background:var(--bg);border:1px solid var(--border);color:var(--text);padding:6px 12px;border-radius:6px;font-size:13px">
          <option value="">All Severity</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="informational">Info</option>
        </select>
        <select id="f-mod" onchange="filterFindings()" style="background:var(--bg);border:1px solid var(--border);color:var(--text);padding:6px 12px;border-radius:6px;font-size:13px"><option value="">All Modules</option></select>
        <input id="f-search" oninput="filterFindings()" placeholder="Search..." style="background:var(--bg);border:1px solid var(--border);color:var(--text);padding:6px 12px;border-radius:6px;font-size:13px;flex:1;min-width:200px">
        <button class="btn btn-sm" onclick="exportJSON()">Export JSON</button>
        <button class="btn btn-sm" onclick="exportCSV()">Export CSV</button>
      </div>
      <table><thead><tr><th>Severity</th><th>Title</th><th>Module</th><th>Confidence</th><th>URL</th><th>Evidence</th></tr></thead>
      <tbody id="findings-table"></tbody></table>
      <div id="finding-detail" class="card" style="display:none;margin-top:16px">
        <div style="display:flex;justify-content:space-between;align-items:start">
          <h2 id="fd-title"></h2>
          <button class="btn btn-sm" onclick="copyForReport()">&#128203; Copy for Report</button>
        </div>
        <div class="form-row" style="margin-bottom:12px">
          <div><span class="label" style="color:var(--dim);font-size:12px">Module</span><br><span id="fd-module"></span></div>
          <div><span class="label" style="color:var(--dim);font-size:12px">Severity</span><br><span id="fd-severity"></span></div>
          <div><span class="label" style="color:var(--dim);font-size:12px">Confidence</span><br><span id="fd-confidence"></span></div>
        </div>
        <div class="form-group"><label>URL</label><div id="fd-url" style="font-family:monospace;font-size:13px;word-break:break-all"></div></div>
        <div class="form-group"><label>Invariant</label><div id="fd-invariant"></div></div>
        <div class="form-group"><label>Evidence</label><div id="fd-evidence" class="log" style="max-height:150px"></div></div>
        <div class="form-group"><label>Remediation</label><div id="fd-remediation"></div></div>
        <div class="form-group"><label>How to Verify</label><div id="fd-steps" style="background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:12px;font-size:13px"></div></div>
        <div style="display:flex;gap:6px;margin-top:12px">
          <button class="btn btn-danger btn-sm" onclick="setDisp('false_positive')">False Positive</button>
          <button class="btn btn-sm" style="border-color:var(--yellow);color:var(--yellow)" onclick="setDisp('accepted_risk')">Accepted Risk</button>
          <button class="btn btn-success btn-sm" onclick="setDisp('fixed')">Fixed</button>
        </div>
      </div>
    </div>

    <!-- AUTH TOKENS -->
    <div class="page" id="page-auth">
      <h1 style="margin-bottom:20px">Auth Tokens</h1>
      <div class="card">
        <h2>Add Token</h2>
        <div class="form-row">
          <div class="form-group"><label>Name</label><input id="at-name" placeholder="my-api-key"></div>
          <div class="form-group"><label>Type</label>
            <select id="at-type"><option value="bearer">Bearer</option><option value="header">Header</option><option value="cookie">Cookie</option><option value="query_param">Query Param</option><option value="basic">Basic</option><option value="jwt">JWT</option></select>
          </div>
        </div>
        <div class="form-group"><label>Value</label><input id="at-value" placeholder="eyJ... or Bearer token..."></div>
        <div class="form-row">
          <div class="form-group"><label>Scope (URL regex, optional)</label><input id="at-scope" placeholder=".*example\\.com.*"></div>
          <div class="form-group"><label>Header/Cookie name</label><input id="at-header" placeholder="Authorization"></div>
        </div>
        <button class="btn btn-primary" onclick="addToken()">Add Token</button>
        <button class="btn" onclick="checkTokens()">Check Health</button>
      </div>
      <div class="card">
        <h2>Existing Tokens</h2>
        <table><thead><tr><th>Name</th><th>Type</th><th>Scope</th><th>Expires</th><th>Status</th><th></th></tr></thead>
        <tbody id="tokens-table"></tbody></table>
        <p id="tokens-empty" style="color:var(--dim);padding:12px;text-align:center">No tokens configured.</p>
      </div>
      <div class="card">
        <h2>Validate JWT</h2>
        <div class="form-group"><label>Token</label><input id="jwt-input" placeholder="Paste JWT token here..."></div>
        <button class="btn" onclick="validateJWT()">Validate</button>
        <div id="jwt-result" class="log" style="margin-top:8px;display:none"></div>
      </div>
    </div>

    <!-- SCOPE -->
    <div class="page" id="page-scope">
      <h1 style="margin-bottom:20px">Scope Editor</h1>
      <div class="card">
        <h2>Check URL</h2>
        <div class="form-row">
          <div class="form-group" style="flex:2"><label>URL</label><input id="scope-url" placeholder="https://example.com/api/v1"></div>
          <div class="form-group"><label>&nbsp;</label><button class="btn btn-primary" onclick="checkScope()">Check</button></div>
        </div>
        <div id="scope-result" style="margin-top:8px"></div>
      </div>
      <div class="card">
        <h2>Edit Scope Config</h2>
        <div class="form-group"><label>Allowed Hosts (one per line)</label><textarea id="scope-hosts" rows="3"></textarea></div>
        <div class="form-group"><label>Excluded Hosts (one per line)</label><textarea id="scope-excluded" rows="2"></textarea></div>
        <div class="form-row">
          <div class="form-group"><label>Allowed Schemes</label><input id="scope-schemes" value="https, http"></div>
          <div class="form-group"><label>Allowed Ports</label><input id="scope-ports" value="443, 80"></div>
        </div>
        <div class="form-row">
          <div class="form-group"><label><input type="checkbox" id="scope-private"> Allow private IPs</label></div>
          <div class="form-group"><label>Max redirects</label><input id="scope-redir" type="number" value="3"></div>
        </div>
        <button class="btn btn-primary" onclick="saveScope()">Save Scope</button>
      </div>
    </div>

    <!-- MODULES -->
    <div class="page" id="page-modules">
      <h1 style="margin-bottom:20px">Modules</h1>
      <div class="card">
        <h2>External Tools</h2>
        <table><thead><tr><th>Tool</th><th>Status</th><th>Path</th><th>Purpose</th></tr></thead>
        <tbody id="doctor-table"></tbody></table>
      </div>
      <div class="card">
        <h2>Built-in Modules</h2>
        <table><thead><tr><th>ID</th><th>Risk</th><th>Version</th><th>Description</th></tr></thead>
        <tbody id="modules-table"></tbody></table>
      </div>
    </div>

    <!-- PROJECTS -->
    <div class="page" id="page-projects">
      <h1 style="margin-bottom:20px">Projects</h1>
      <div class="card">
        <h2>Create Project</h2>
        <div class="form-row">
          <div class="form-group" style="flex:2"><label>Project name</label><input id="proj-name" placeholder="my-target"></div>
          <div class="form-group"><label>&nbsp;</label><button class="btn btn-primary" onclick="createProject()">Init Project</button></div>
        </div>
        <div id="proj-result" style="margin-top:8px"></div>
      </div>
      <div class="card">
        <h2>Existing Projects</h2>
        <table><thead><tr><th>Name</th><th>Path</th><th></th></tr></thead>
        <tbody id="projects-table"></tbody></table>
      </div>
    </div>

    <!-- MANUAL HUNT GUIDE -->
    <div class="page" id="page-hunt">
      <h1 style="margin-bottom:20px">Manual Hunting Guide</h1>
      <p style="color:var(--dim);margin-bottom:16px">These bugs can't be detected automatically. Follow the steps manually.</p>
      <div id="hunt-categories"></div>
    </div>

  </div>
</div>

<script>
let findings=[], currentFinding=null, scanPolling=null;

// Navigation
function showPage(name){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.sidebar nav a').forEach(a=>a.classList.remove('active'));
  document.getElementById('page-'+name).classList.add('active');
  document.getElementById('nav-'+name).classList.add('active');
  if(name==='dashboard')loadDashboard();
  if(name==='findings')loadFindings();
  if(name==='auth')loadTokens();
  if(name==='scope')loadScopeConfig();
  if(name==='modules')loadModules();
  if(name==='projects')loadProjects();
  if(name==='hunt')loadHuntGuide();
}

function toast(msg,ok=true){const t=document.createElement('div');t.className='toast '+(ok?'toast-ok':'toast-err');t.textContent=msg;document.body.appendChild(t);setTimeout(()=>t.remove(),3000)}

// Dashboard
async function loadDashboard(){
  try{
    const r=await fetch('/api/stats');const s=await r.json();
    document.getElementById('dash-stats').innerHTML=`
      <div class="stat"><div class="num">${s.total}</div><div class="label">Total</div></div>
      <div class="stat crit"><div class="num">${s.critical}</div><div class="label">Critical</div></div>
      <div class="stat high"><div class="num">${s.high}</div><div class="label">High</div></div>
      <div class="stat med"><div class="num">${s.medium}</div><div class="label">Medium</div></div>
      <div class="stat low"><div class="num">${s.low}</div><div class="label">Low</div></div>`;
    const r2=await fetch('/api/findings');findings=await r2.json();
    const tb=document.getElementById('dash-findings');
    if(findings.length===0){tb.innerHTML='';document.getElementById('dash-empty').style.display='block';return}
    document.getElementById('dash-empty').style.display='none';
    tb.innerHTML=findings.slice(0,10).map(f=>`<tr><td><span class="badge badge-${f.severity}">${f.severity}</span></td><td>${esc(f.title)}</td><td>${esc(f.module)}</td><td style="font-size:12px;color:var(--dim)">${esc(f.url)}</td></tr>`).join('');
  }catch(e){}
}

// Scan
async function startScan(){
  const target=document.getElementById('scan-target').value.trim();
  if(!target){toast('Enter a target',false);return}
  const body={
    target,profile:document.getElementById('scan-profile').value,
    config:document.getElementById('scan-config').value||'bughunter.yaml',
    manifest:document.getElementById('scan-manifest').value||null,
    passive_only:document.getElementById('scan-passive').checked,
    rate_limit:parseFloat(document.getElementById('scan-rps').value)||10,
    concurrency:parseInt(document.getElementById('scan-conc').value)||20
  };
  document.getElementById('scan-start-btn').style.display='none';
  document.getElementById('scan-stop-btn').style.display='inline-flex';
  document.getElementById('scan-log').textContent='Starting scan...\\n';
  try{
    const r=await fetch('/api/scan/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d=await r.json();
    if(d.ok){toast('Scan started');pollScan()}else{toast(d.error||'Scan failed',false);resetScanBtn()}
  }catch(e){toast('Failed to start scan',false);resetScanBtn()}
}
function resetScanBtn(){document.getElementById('scan-start-btn').style.display='inline-flex';document.getElementById('scan-stop-btn').style.display='none'}
async function stopScan(){await fetch('/api/scan/stop',{method:'POST'});toast('Stopping...')}
function pollScan(){
  if(scanPolling)clearInterval(scanPolling);
  scanPolling=setInterval(async()=>{
    try{const r=await fetch('/api/scan/status');const d=await r.json();
    document.getElementById('scan-log').textContent=d.output.join('\\n');
    document.getElementById('scan-log').scrollTop=99999;
    if(!d.running){clearInterval(scanPolling);resetScanBtn();if(d.output.length>0)toast('Scan complete');loadFindings()}}catch(e){}
  },1000);
}

// Findings
async function loadFindings(){
  try{const r=await fetch('/api/findings');findings=await r.json();renderFindings();populateModFilter()}catch(e){}
}
function renderFindings(filter){
  let data=findings;
  const sev=document.getElementById('f-sev').value;
  const mod=document.getElementById('f-mod').value;
  const q=(document.getElementById('f-search').value||'').toLowerCase();
  if(sev)data=data.filter(f=>f.severity===sev);
  if(mod)data=data.filter(f=>f.module===mod);
  if(q)data=data.filter(f=>(f.title+f.url+f.evidence+f.module).toLowerCase().includes(q));
  document.getElementById('findings-table').innerHTML=data.map((f,i)=>`<tr onclick="showFinding(${findings.indexOf(f)})" style="cursor:pointer"><td><span class="badge badge-${f.severity}">${f.severity}</span></td><td>${esc(f.title)}</td><td>${esc(f.module)}</td><td>${esc(f.confidence)}</td><td style="max-width:200px;word-break:break-all;font-size:12px;color:var(--dim)">${esc(f.url)}</td><td style="font-size:12px;color:var(--dim)">${esc((f.evidence||'').substring(0,80))}</td></tr>`).join('');
}
function filterFindings(){renderFindings()}
function populateModFilter(){const mods=[...new Set(findings.map(f=>f.module))].sort();const sel=document.getElementById('f-mod');sel.innerHTML='<option value="">All Modules</option>'+mods.map(m=>`<option>${m}</option>`).join('')}
function showFinding(i){
  currentFinding=findings[i];const f=currentFinding;
  document.getElementById('fd-title').textContent=f.title;
  document.getElementById('fd-module').textContent=f.module;
  document.getElementById('fd-severity').innerHTML=`<span class="badge badge-${f.severity}">${f.severity}</span>`;
  document.getElementById('fd-confidence').textContent=f.confidence;
  document.getElementById('fd-url').textContent=f.url;
  document.getElementById('fd-invariant').textContent=f.invariant||'';
  document.getElementById('fd-evidence').textContent=f.evidence||'';
  document.getElementById('fd-remediation').textContent=f.remediation||'';
  document.getElementById('fd-steps').innerHTML=(f.verification_steps||[]).map((s,j)=>`${j+1}. ${esc(s)}`).join('<br>')||'No verification steps available.';
  document.getElementById('finding-detail').style.display='block';
}
async function copyForReport(){
  if(!currentFinding)return;const f=currentFinding;
  const text=`## [${f.severity}] ${f.title}

**URL:** ${f.url}
**Module:** ${f.module}
**Confidence:** ${f.confidence}

**Evidence:**
${f.evidence||'N/A'}

**Security Invariant:**
${f.invariant||'N/A'}

**Remediation:**
${f.remediation||'N/A'}

**Verification Steps:**
${(f.verification_steps||[]).map((s,i)=>`${i+1}. ${s}`).join('\\n')||'N/A'}
`;
  await navigator.clipboard.writeText(text);toast('Copied to clipboard — paste into your report');
}
async function setDisp(kind){
  if(!currentFinding)return;const reason=prompt('Reason:');
  if(reason===null)return;
  await fetch('/api/disposition',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({finding_id:currentFinding.id||currentFinding.fingerprint,kind,reason})});
  toast('Disposition saved');
}
function exportJSON(){window.location.href='/api/export/json'}
function exportCSV(){window.location.href='/api/export/csv'}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}

// Auth tokens
async function loadTokens(){
  try{const r=await fetch('/api/tokens');const d=await r.json();
  document.getElementById('tokens-table').innerHTML=d.tokens.map(t=>`<tr><td>${esc(t.name)}</td><td>${t.type}</td><td style="font-size:12px">${esc(t.scope||'(default)')}</td><td>${t.expires||'(none)'}</td><td><span class="badge badge-${t.expired?'err':'ok'}">${t.expired?'expired':'valid'}</span></td><td><button class="btn btn-danger btn-sm" onclick="removeToken('${t.name}')">Remove</button></td></tr>`).join('');
  document.getElementById('tokens-empty').style.display=d.tokens.length?'none':'block';
  }catch(e){}
}
async function addToken(){
  const body={name:document.getElementById('at-name').value,type:document.getElementById('at-type').value,value:document.getElementById('at-value').value,scope:document.getElementById('at-scope').value,header_name:document.getElementById('at-header').value};
  if(!body.name||!body.value){toast('Name and value required',false);return}
  const r=await fetch('/api/tokens/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const d=await r.json();toast(d.ok?'Token added':d.error,false);loadTokens();
}
async function removeToken(name){await fetch('/api/tokens/remove',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})});toast('Token removed');loadTokens()}
async function checkTokens(){const r=await fetch('/api/tokens/check');const d=await r.json();toast(d.issues.length?d.issues.join(', '):'All tokens healthy',d.issues.length===0)}
async function validateJWT(){
  const token=document.getElementById('jwt-input').value;if(!token){toast('Paste a token',false);return}
  const r=await fetch('/api/tokens/validate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token})});
  const d=await r.json();const el=document.getElementById('jwt-result');el.style.display='block';el.textContent=JSON.stringify(d,null,2);
}

// Scope
async function loadScopeConfig(){
  try{const r=await fetch('/api/scope/config');const d=await r.json();
  document.getElementById('scope-hosts').value=(d.allowed_hosts||[]).join('\\n');
  document.getElementById('scope-excluded').value=(d.excluded_hosts||[]).join('\\n');
  document.getElementById('scope-schemes').value=(d.allowed_schemes||['https']).join(', ');
  document.getElementById('scope-ports').value=(d.allowed_ports||[443]).join(', ');
  document.getElementById('scope-private').checked=d.allow_private_ips||false;
  document.getElementById('scope-redir').value=d.max_redirects||3;
  }catch(e){}
}
async function checkScope(){
  const url=document.getElementById('scope-url').value;if(!url){toast('Enter a URL',false);return}
  const r=await fetch('/api/scope/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
  const d=await r.json();
  document.getElementById('scope-result').innerHTML=`<span class="badge badge-${d.allowed?'ok':'err'}">${d.allowed?'ALLOWED':'DENIED'}</span> ${d.reason?' — '+d.reason:''}`;
}
async function saveScope(){
  const body={
    allowed_hosts:document.getElementById('scope-hosts').value.split('\\n').map(s=>s.trim()).filter(Boolean),
    excluded_hosts:document.getElementById('scope-excluded').value.split('\\n').map(s=>s.trim()).filter(Boolean),
    allowed_schemes:document.getElementById('scope-schemes').value.split(',').map(s=>s.trim()).filter(Boolean),
    allowed_ports:document.getElementById('scope-ports').value.split(',').map(s=>parseInt(s.trim())).filter(Boolean),
    allow_private_ips:document.getElementById('scope-private').checked,
    max_redirects:parseInt(document.getElementById('scope-redir').value)||3
  };
  const r=await fetch('/api/scope/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const d=await r.json();toast(d.ok?'Scope saved':d.error,false);
}

// Modules
async function loadModules(){
  try{const r=await fetch('/api/modules');const d=await r.json();
  document.getElementById('doctor-table').innerHTML=d.doctor.map(t=>`<tr><td>${esc(t.name)}</td><td><span class="badge badge-${t.installed?'ok':'err'}">${t.installed?'installed':'not found'}</span></td><td style="font-size:12px;color:var(--dim)">${esc(t.path||'')}</td><td style="font-size:12px">${esc(t.description)}</td></tr>`).join('');
  document.getElementById('modules-table').innerHTML=d.modules.map(m=>`<tr><td style="font-family:monospace;font-size:12px">${esc(m.id)}</td><td><span class="badge badge-${m.risk==='passive'?'info':m.risk==='safe'?'ok':m.risk==='active'?'medium':'err'}">${m.risk}</span></td><td>${m.version}</td><td style="font-size:12px">${esc(m.description)}</td></tr>`).join('');
  }catch(e){}
}

// Projects
async function loadProjects(){
  try{const r=await fetch('/api/projects');const d=await r.json();
  document.getElementById('projects-table').innerHTML=d.projects.map(p=>`<tr><td>${esc(p.name)}</td><td style="font-size:12px;color:var(--dim)">${esc(p.path)}</td><td><button class="btn btn-sm" onclick="selectProject('${esc(p.name)}')">Select</button></td></tr>`).join('');
  }catch(e){}
}
async function createProject(){
  const name=document.getElementById('proj-name').value.trim();if(!name){toast('Enter a name',false);return}
  const r=await fetch('/api/projects/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})});
  const d=await r.json();toast(d.ok?'Project created':d.error,d.ok);loadProjects();
}
function selectProject(name){document.getElementById('scan-config').value=`.bughunter/${name}/bughunter.yaml`;showPage('scan');toast('Project selected: '+name)}

// Manual Hunt Guide
async function loadHuntGuide(){
  try{const r=await fetch('/api/hunt-guide');const d=await r.json();
  const el=document.getElementById('hunt-categories');
  el.innerHTML=Object.entries(d).map(([cat,tasks])=>`
    <div class="card">
      <h2 style="text-transform:capitalize">${esc(cat)}</h2>
      ${tasks.map(t=>`
        <div style="border:1px solid var(--border);border-radius:6px;padding:14px;margin-bottom:10px">
          <div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:8px">
            <strong>${esc(t.title)}</strong>
            <div>
              <span class="badge badge-${t.severity_if_found}">${t.severity_if_found} if found</span>
              <span style="color:var(--dim);font-size:12px;margin-left:8px">${t.estimated_time}</span>
            </div>
          </div>
          <p style="color:var(--dim);font-size:13px;margin-bottom:8px">${esc(t.description)}</p>
          <details>
            <summary style="cursor:pointer;color:var(--blue);font-size:13px">Show steps (${t.steps.length})</summary>
            <ol style="margin-top:8px;padding-left:20px;font-size:13px;line-height:1.8">
              ${t.steps.map(s=>`<li>${esc(s)}</li>`).join('')}
            </ol>
          </details>
          ${t.tools_needed.length?`<div style="margin-top:6px;font-size:12px;color:var(--dim)">Tools: ${t.tools_needed.map(x=>`<span class="badge badge-info" style="margin-right:4px">${esc(x)}</span>`).join('')}</div>`:''}
        </div>
      `).join('')}
    </div>
  `).join('');
  }catch(e){document.getElementById('hunt-categories').innerHTML='<p style="color:var(--dim)">Failed to load hunt guide.</p>'}
}

// Init
loadDashboard();
</script>
</body>
</html>"""


def _run_cmd(cmd: list[str]) -> tuple[int, str]:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        return result.returncode, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return 1, "Command timed out"
    except Exception as e:
        return 1, str(e)


def _run_scan_async(target: str, config: str, profile: str, manifest: str | None,
                    passive_only: bool, rate_limit: float, concurrency: int) -> None:
    global _scan_running, _scan_output
    _scan_running = True
    _scan_output = []

    python = sys.executable
    cmd = [python, "-m", "bughunter.cli", "scan", target, "--config", config]
    if manifest:
        cmd.extend(["--manifest", manifest])
    if passive_only:
        cmd.append("--passive-only")
    cmd.extend(["--rate-limit", str(rate_limit), "--concurrency", str(concurrency)])

    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
        for line in proc.stdout:
            _scan_output.append(line.rstrip())
        proc.wait()
        _scan_output.append(f"\nExit code: {proc.returncode}")
    except Exception as e:
        _scan_output.append(f"Error: {e}")
    finally:
        _scan_running = False
        _load_findings_from_disk(config)


def _load_findings_from_disk(config: str) -> None:
    global _findings_store
    try:
        p = Path(config)
        reports_dir = Path(f"reports_{p.parent.name.replace('.bughunter_', '')}")
        for d in Path(".").glob("reports_*"):
            if d.is_dir() and (d / "findings.json").exists():
                reports_dir = d
                break
        findings_file = reports_dir / "findings.json"
        if findings_file.exists():
            with open(findings_file) as f:
                data = json.load(f)
            _findings_store = data.get("findings", []) if isinstance(data, dict) else data
    except Exception:
        pass


def create_app(findings: list[dict] | None = None, target: str = "",
               projects_dir: str | Path = ".bughunter") -> Flask:
    global _findings_store, _current_project, _projects_dir
    if findings:
        _findings_store = findings
    _current_project = target
    _projects_dir = Path(projects_dir)
    return app


@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/stats")
def api_stats():
    return jsonify({
        "total": len(_findings_store),
        "critical": sum(1 for f in _findings_store if f.get("severity") == "critical"),
        "high": sum(1 for f in _findings_store if f.get("severity") == "high"),
        "medium": sum(1 for f in _findings_store if f.get("severity") == "medium"),
        "low": sum(1 for f in _findings_store if f.get("severity") == "low"),
        "informational": sum(1 for f in _findings_store if f.get("severity") == "informational"),
    })


@app.route("/api/findings")
def api_findings():
    return jsonify(_findings_store)


@app.route("/api/disposition", methods=["POST"])
def api_disposition():
    data = request.json
    fid = data.get("finding_id", "")
    for f in _findings_store:
        if f.get("id") == fid or f.get("fingerprint") == fid:
            f["disposition"] = data.get("kind", "")
            f["disposition_reason"] = data.get("reason", "")
            break
    return jsonify({"ok": True})


@app.route("/api/export/json")
def api_export_json():
    return jsonify(_findings_store), 200, {"Content-Disposition": "attachment; filename=findings.json"}


@app.route("/api/export/csv")
def api_export_csv():
    import csv
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["severity", "title", "module", "confidence", "url", "evidence", "invariant", "remediation", "disposition"])
    for f in _findings_store:
        writer.writerow([f.get(k, "") for k in ["severity", "title", "module", "confidence", "url", "evidence", "invariant", "remediation", "disposition"]])
    return output.getvalue(), 200, {"Content-Type": "text/csv", "Content-Disposition": "attachment; filename=findings.csv"}


# Scan endpoints
@app.route("/api/scan/start", methods=["POST"])
def api_scan_start():
    global _scan_running, _scan_output
    if _scan_running:
        return jsonify({"error": "Scan already running"}), 409
    data = request.json
    target = data.get("target", "")
    if not target:
        return jsonify({"error": "Target required"}), 400

    config = data.get("config", "bughunter.yaml")
    config_path = Path(config)
    if not config_path.exists():
        config_path = _projects_dir / target / "bughunter.yaml"
        if not config_path.exists():
            return jsonify({"error": f"Config not found: {config}"}), 400
        config = str(config_path)

    thread = threading.Thread(target=_run_scan_async, args=(
        target, config, data.get("profile", "safe"),
        data.get("manifest"), data.get("passive_only", False),
        data.get("rate_limit", 10), data.get("concurrency", 20),
    ), daemon=True)
    thread.start()
    return jsonify({"ok": True})


@app.route("/api/scan/stop", methods=["POST"])
def api_scan_stop():
    global _scan_running
    _scan_running = False
    return jsonify({"ok": True})


@app.route("/api/scan/status")
def api_scan_status():
    return jsonify({"running": _scan_running, "output": _scan_output[-200:]})


# Auth token endpoints
@app.route("/api/tokens")
def api_tokens():
    from bughunter.auth.tokens import TokenManager
    tm = TokenManager()
    auth_file = _projects_dir / "auth.yaml"
    if auth_file.exists():
        tm.load_from_yaml(auth_file)
    tokens = []
    for t in tm.all_tokens:
        tokens.append({
            "name": t.name, "type": t.auth_type.value,
            "scope": t.scope, "expired": t.is_expired,
            "expires": str(t.expires_at) if t.expires_at > 0 else "(none)",
        })
    return jsonify({"tokens": tokens})


@app.route("/api/tokens/add", methods=["POST"])
def api_token_add():
    from bughunter.auth.tokens import AuthToken, AuthType, TokenManager
    data = request.json
    tm = TokenManager()
    auth_file = _projects_dir / "auth.yaml"
    if auth_file.exists():
        tm.load_from_yaml(auth_file)
    try:
        token = AuthToken(
            name=data["name"], auth_type=AuthType(data["type"]),
            value=data["value"], scope=data.get("scope", ""),
            header_name=data.get("header_name", "Authorization"),
        )
        tm.register_token(token)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/tokens/remove", methods=["POST"])
def api_token_remove():
    from bughunter.auth.tokens import TokenManager
    data = request.json
    tm = TokenManager()
    auth_file = _projects_dir / "auth.yaml"
    if auth_file.exists():
        tm.load_from_yaml(auth_file)
    tm.remove_token(data.get("name", ""))
    return jsonify({"ok": True})


@app.route("/api/tokens/check")
def api_token_check():
    from bughunter.auth.policy import AuthPolicyManager
    from bughunter.auth.tokens import TokenManager
    tm = TokenManager()
    pm = AuthPolicyManager(tm)
    auth_file = _projects_dir / "auth.yaml"
    if auth_file.exists():
        tm.load_from_yaml(auth_file)
        pm.load_from_yaml(auth_file)
    issues = pm.check_token_health()
    return jsonify({"issues": [i["message"] for i in issues]})


@app.route("/api/tokens/validate", methods=["POST"])
def api_token_validate():
    import base64
    data = request.json
    token = data.get("token", "")
    parts = token.split(".")
    if len(parts) == 3:
        try:
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            exp = payload.get("exp", 0)
            remaining = exp - time.time() if exp else 0
            return jsonify({
                "valid": True, "iss": payload.get("iss"), "sub": payload.get("sub"),
                "aud": payload.get("aud"), "exp": exp,
                "expired": remaining <= 0 if exp else False,
                "remaining_seconds": max(0, remaining),
            })
        except Exception as e:
            return jsonify({"valid": False, "error": str(e)})
    return jsonify({"valid": True, "type": "non-JWT", "length": len(token)})


# Scope endpoints
@app.route("/api/scope/config")
def api_scope_config():
    import yaml
    for p in _projects_dir.rglob("bughunter.yaml"):
        with open(p) as f:
            cfg = yaml.safe_load(f) or {}
        return jsonify(cfg.get("scope", {}))
    return jsonify({})


@app.route("/api/scope/check", methods=["POST"])
def api_scope_check():
    from urllib.parse import urlparse
    data = request.json
    url = data.get("url", "")
    parsed = urlparse(url)
    host = parsed.hostname or ""
    for p in _projects_dir.rglob("bughunter.yaml"):
        import yaml
        with open(p) as f:
            cfg = yaml.safe_load(f) or {}
        scope = cfg.get("scope", {})
        allowed = scope.get("allowed_hosts", [])
        excluded = scope.get("excluded_hosts", [])
        if host in excluded:
            return jsonify({"allowed": False, "reason": f"Host {host} is excluded"})
        for pattern in allowed:
            if pattern.startswith("*.") and host.endswith(pattern[1:]):
                return jsonify({"allowed": True, "reason": f"Matches wildcard {pattern}"})
            if host == pattern:
                return jsonify({"allowed": True, "reason": f"Matches {pattern}"})
        if allowed:
            return jsonify({"allowed": False, "reason": f"Host {host} not in allowed list"})
        return jsonify({"allowed": True, "reason": "No host restrictions configured"})
    return jsonify({"allowed": True, "reason": "No config found"})


@app.route("/api/scope/save", methods=["POST"])
def api_scope_save():
    import yaml
    data = request.json
    for p in _projects_dir.rglob("bughunter.yaml"):
        with open(p) as f:
            cfg = yaml.safe_load(f) or {}
        cfg["scope"] = data
        with open(p, "w") as f:
            yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
        return jsonify({"ok": True, "path": str(p)})
    return jsonify({"error": "No config found"}), 404


# Modules / Doctor endpoints
@app.route("/api/modules")
def api_modules():
    import shutil
    tools = [
        ("subfinder", "Passive subdomain enumeration"),
        ("amass", "Deep subdomain enumeration"),
        ("httpx", "Mass HTTP probing"),
        ("nuclei", "Template-based scanning"),
        ("naabu", "Port scanning"),
        ("nmap", "Port scanning"),
        ("ffuf", "Content discovery"),
        ("arjun", "Parameter discovery"),
    ]
    doctor = [{"name": t[0], "installed": shutil.which(t[0]) is not None,
               "path": shutil.which(t[0]) or "", "description": t[1]} for t in tools]
    modules = [
        {"id": "passive.certificate_names", "risk": "passive", "version": "0.1.0", "description": "Certificate transparency name enumeration"},
        {"id": "passive.provider_sources", "risk": "passive", "version": "0.1.0", "description": "Passive subdomain sources"},
        {"id": "recon.dns_resolution", "risk": "safe", "version": "0.1.0", "description": "DNS resolution (A/AAAA/CNAME/MX/TXT)"},
        {"id": "recon.http_probe", "risk": "safe", "version": "0.1.0", "description": "HTTP alive check, titles, tech fingerprinting"},
        {"id": "recon.crawl", "risk": "safe", "version": "0.1.0", "description": "Bounded same-origin page crawl"},
        {"id": "surface.endpoint_inventory", "risk": "safe", "version": "0.1.0", "description": "Endpoint and parameter extraction"},
        {"id": "surface.component_inventory", "risk": "safe", "version": "0.1.0", "description": "Component and version detection"},
        {"id": "surface.dependency_advisories", "risk": "safe", "version": "0.1.0", "description": "OSV dependency advisory lookup"},
        {"id": "detect.exposed_artifacts", "risk": "safe", "version": "0.1.0", "description": "Exposed sensitive files"},
        {"id": "detect.repository_metadata", "risk": "safe", "version": "0.1.0", "description": "Exposed repository metadata"},
        {"id": "detect.takeover", "risk": "safe", "version": "0.1.0", "description": "Subdomain takeover candidates"},
        {"id": "detect.security_controls", "risk": "safe", "version": "0.1.0", "description": "Security header and control checks"},
        {"id": "detect.graphql_surface", "risk": "safe", "version": "0.1.0", "description": "GraphQL introspection and surface"},
        {"id": "detect.component_exposure", "risk": "safe", "version": "0.1.0", "description": "Vulnerable component detection via OSV"},
        {"id": "detect.xss", "risk": "active", "version": "0.1.0", "description": "Cross-site scripting"},
        {"id": "detect.sqli", "risk": "active", "version": "0.1.0", "description": "SQL injection"},
        {"id": "detect.ssrf", "risk": "active", "version": "0.1.0", "description": "Server-side request forgery"},
        {"id": "detect.ssti", "risk": "active", "version": "0.1.0", "description": "Server-side template injection"},
        {"id": "detect.crlf", "risk": "active", "version": "0.1.0", "description": "CRLF header injection"},
        {"id": "detect.traversal", "risk": "active", "version": "0.1.0", "description": "Path traversal detection"},
        {"id": "detect.redirect", "risk": "active", "version": "0.1.0", "description": "Open redirect detection"},
        {"id": "authn.oauth_review", "risk": "stateful", "version": "0.1.0", "description": "OAuth flow review"},
        {"id": "authn.jwt_review", "risk": "local", "version": "0.1.0", "description": "JWT token review"},
        {"id": "authz.session_differential", "risk": "stateful", "version": "0.1.0", "description": "Cross-account session differential"},
        {"id": "expert.race", "risk": "high_risk", "version": "0.1.0", "description": "Race condition detection"},
        {"id": "expert.upload", "risk": "stateful", "version": "0.1.0", "description": "File upload filter testing"},
        {"id": "expert.xxe", "risk": "high_risk", "version": "0.1.0", "description": "XML external entity detection"},
        {"id": "expert.cache_poison", "risk": "high_risk", "version": "0.1.0", "description": "Cache poisoning detection"},
        {"id": "expert.websocket", "risk": "stateful", "version": "0.1.0", "description": "WebSocket origin checks"},
        {"id": "expert.smuggling", "risk": "lab", "version": "0.1.0", "description": "Request smuggling (lab only)"},
    ]
    return jsonify({"doctor": doctor, "modules": modules})


# Projects endpoints
@app.route("/api/projects")
def api_projects():
    projects = []
    if _projects_dir.exists():
        for p in _projects_dir.iterdir():
            if p.is_dir() and (p / "bughunter.yaml").exists():
                projects.append({"name": p.name, "path": str(p)})
    return jsonify({"projects": projects})


@app.route("/api/projects/create", methods=["POST"])
def api_project_create():
    data = request.json
    name = data.get("name", "")
    if not name:
        return jsonify({"error": "Name required"}), 400
    cmd = [sys.executable, "-m", "bughunter.cli", "init", name]
    code, output = _run_cmd(cmd)
    if code == 0:
        return jsonify({"ok": True, "output": output})
    return jsonify({"error": output}), 400


@app.route("/api/hunt-guide")
def api_hunt_guide():
    from bughunter.guidance.hunting_guide import get_hunting_guide
    return jsonify(get_hunting_guide())


@app.route("/api/verify-steps", methods=["POST"])
def api_verify_steps():
    from bughunter.guidance.hunting_guide import get_verification_steps
    data = request.json
    steps = get_verification_steps(data.get("module", ""), data.get("title", ""))
    return jsonify({"steps": steps})
