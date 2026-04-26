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
        html = """<!doctype html><html><head><meta charset='utf-8'><title>NetCheck</title>
<style>body{font-family:Arial;margin:2rem;background:#0f1220;color:#f5f5f5} .card{background:#1b2140;padding:1rem;border-radius:8px;margin-bottom:1rem}</style>
</head><body><h1>NetCheck Dashboard</h1><div class='card'><p>Overview risk score, findings, timeline.</p><pre id='out'>Loading...</pre></div>
<script>
const out=document.getElementById('out');
async function refresh(){const r=await fetch('/api/overview');const j=await r.json();out.textContent=JSON.stringify(j.scans[0]||{},null,2);}refresh();
const ev=new EventSource('/events');ev.onmessage=(e)=>{refresh();};
</script></body></html>"""
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
