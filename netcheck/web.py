from __future__ import annotations

import json
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .scanner import recent_scans


class NetcheckHandler(BaseHTTPRequestHandler):
    def _send_json(self, payload: dict | list, code: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/":
            self._render_index()
            return
        if path == "/api/overview":
            scans = recent_scans(limit=25)
            self._send_json({"scans": scans})
            return
        if path == "/events":
            self._stream_events()
            return
        self.send_error(404)

    def _render_index(self) -> None:
        html = """<!doctype html>
<html>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>NetCheck Dashboard</title>
  <style>
    :root{--bg:#0b1020;--panel:#121a34;--muted:#93a4c6;--text:#edf2ff;--border:#253156;--ok:#35d399;--low:#60a5fa;--med:#fbbf24;--high:#fb7185;--critical:#ef4444}
    *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,Segoe UI,Arial,sans-serif}
    .wrap{max-width:1200px;margin:0 auto;padding:24px} h1{margin:0 0 8px} .sub{color:var(--muted);margin-bottom:20px}
    .grid{display:grid;gap:14px} .stats{grid-template-columns:repeat(6,minmax(110px,1fr))}
    .two{grid-template-columns:2fr 1fr} .panel{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:14px}
    .k{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}.v{font-size:22px;font-weight:700;margin-top:6px}
    .sev{display:flex;gap:10px;flex-wrap:wrap}.pill{border-radius:999px;padding:4px 10px;font-size:12px;border:1px solid var(--border)}
    .critical{color:var(--critical)} .high{color:var(--high)} .medium{color:var(--med)} .low{color:var(--low)} .info{color:var(--ok)}
    table{width:100%;border-collapse:collapse} th,td{padding:8px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top}
    th{font-size:12px;color:var(--muted);text-transform:uppercase} .mono{font-family:Consolas,Menlo,monospace;font-size:12px}
    .timeline{max-height:320px;overflow:auto}.empty{color:var(--muted)}
    @media (max-width:950px){.stats,.two{grid-template-columns:1fr 1fr}.wrap{padding:12px}} @media (max-width:640px){.stats,.two{grid-template-columns:1fr}}
  </style>
</head>
<body>
  <div class='wrap'>
    <h1>NetCheck Dashboard</h1>
    <div class='sub'>Live local network risk overview (updates automatically).</div>

    <div class='grid stats'>
      <div class='panel'><div class='k'>Risk score</div><div class='v' id='risk'>--</div></div>
      <div class='panel'><div class='k'>Total findings</div><div class='v' id='findings'>--</div></div>
      <div class='panel'><div class='k'>Critical</div><div class='v critical' id='critical'>0</div></div>
      <div class='panel'><div class='k'>High</div><div class='v high' id='high'>0</div></div>
      <div class='panel'><div class='k'>Medium</div><div class='v medium' id='medium'>0</div></div>
      <div class='panel'><div class='k'>Low/Info</div><div class='v low' id='lowinfo'>0</div></div>
    </div>

    <div class='grid two' style='margin-top:14px'>
      <div class='panel'>
        <h3 style='margin-top:0'>Active Network</h3>
        <div id='network' class='mono empty'>No scan data yet.</div>
      </div>
      <div class='panel'>
        <h3 style='margin-top:0'>Severity Mix</h3>
        <div id='severityPills' class='sev empty'>No findings yet.</div>
      </div>
    </div>

    <div class='grid two' style='margin-top:14px'>
      <div class='panel'>
        <h3 style='margin-top:0'>Findings</h3>
        <table>
          <thead><tr><th>Severity</th><th>Category</th><th>Title</th><th>Confidence</th></tr></thead>
          <tbody id='findingsTable'><tr><td colspan='4' class='empty'>No data.</td></tr></tbody>
        </table>
      </div>
      <div class='panel'>
        <h3 style='margin-top:0'>Timeline</h3>
        <div id='timeline' class='timeline mono empty'>No historical scans.</div>
      </div>
    </div>
  </div>

<script>
const ids = ['critical','high','medium','low'];

function severityCounts(findings){
  const c={critical:0,high:0,medium:0,low:0,info:0};
  for(const f of findings||[]){const s=(f.severity||'').toLowerCase();if(c[s]!==undefined)c[s]+=1;}
  return c;
}

function render(scans){
  const latest = scans?.[0];
  if(!latest){ return; }
  const findings = latest.findings || [];
  const counts = severityCounts(findings);

  document.getElementById('risk').textContent = latest.risk_score ?? '--';
  document.getElementById('findings').textContent = findings.length;
  document.getElementById('critical').textContent = counts.critical;
  document.getElementById('high').textContent = counts.high;
  document.getElementById('medium').textContent = counts.medium;
  document.getElementById('lowinfo').textContent = counts.low + counts.info;

  const ctx = latest.context || {};
  document.getElementById('network').innerHTML = `
SSID: ${ctx.ssid || 'n/a'}<br>
BSSID: ${ctx.bssid || 'n/a'}<br>
Adapter: ${ctx.adapter || 'n/a'}<br>
Auth: ${ctx.auth || 'n/a'} / ${ctx.encryption || 'n/a'}<br>
IP: ${ctx.ip || 'n/a'}<br>
Gateway: ${ctx.gateway || 'n/a'}<br>
DNS: ${(ctx.dns || []).join(', ') || 'n/a'}
`;

  const pills = document.getElementById('severityPills');
  pills.classList.remove('empty');
  pills.innerHTML = `
<span class='pill critical'>Critical: ${counts.critical}</span>
<span class='pill high'>High: ${counts.high}</span>
<span class='pill medium'>Medium: ${counts.medium}</span>
<span class='pill low'>Low: ${counts.low}</span>
<span class='pill info'>Info: ${counts.info}</span>`;

  const body = document.getElementById('findingsTable');
  if(!findings.length){
    body.innerHTML = "<tr><td colspan='4' class='empty'>No findings.</td></tr>";
  }else{
    body.innerHTML = findings.map(f => `<tr>
      <td class='${(f.severity||'').toLowerCase()}'>${f.severity}</td>
      <td>${f.category||''}</td>
      <td>${f.title||''}</td>
      <td>${f.confidence||''}</td>
    </tr>`).join('');
  }

  const timeline = document.getElementById('timeline');
  timeline.classList.remove('empty');
  timeline.innerHTML = scans.slice(0,20).map(s=>`• ${s.created_at}  risk=${s.risk_score}  findings=${(s.findings||[]).length}`).join('<br>');
}

async function refresh(){
  const res = await fetch('/api/overview');
  const json = await res.json();
  render(json.scans || []);
}

refresh();
const ev = new EventSource('/events');
ev.onmessage = () => refresh();
</script>
</body>
</html>"""
        data = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _stream_events(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        last_seen = None
        try:
            while True:
                scans = recent_scans(limit=1)
                latest_id = scans[0]["id"] if scans else None
                if latest_id != last_seen:
                    self.wfile.write(f"data: {latest_id}\n\n".encode("utf-8"))
                    self.wfile.flush()
                    last_seen = latest_id
                time.sleep(2)
        except BrokenPipeError:
            return


def run_server(host: str = "127.0.0.1", port: int = 8765, auto_open: bool = True) -> None:
    server = ThreadingHTTPServer((host, port), NetcheckHandler)
    url = f"http://{host}:{port}/"
    print(f"NetCheck web running at {url}")
    if auto_open:
        threading.Thread(target=lambda: webbrowser.open(url), daemon=True).start()
    server.serve_forever()
