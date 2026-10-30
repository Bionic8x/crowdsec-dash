"""
A stand-in for Notifiarr's Passthrough endpoint, for the test stack. Point the dashboard at it
with NOTIFIARR_URL=http://mock-notifiarr:8000/api/v1/notification/passthrough.

  POST /api/v1/notification/passthrough/<key>   records the message, answers like Notifiarr
  GET  /messages                                every message so far (key replaced by key_ok)
  POST /reset                                   forget them
  POST /fail/on, /fail/off                      answer 503 to simulate an outage
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KEY = os.environ.get("NOTIFIARR_API_KEY", "")
messages = []
failing = False


class Handler(BaseHTTPRequestHandler):
    def _json(self, code, data):
        body = json.dumps(data, indent=1).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/messages":
            return self._json(200, messages)
        self._json(404, {"error": "not found"})

    def do_POST(self):
        global failing, messages
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path == "/reset":
            messages = []
            return self._json(200, {"ok": True})
        if self.path in ("/fail/on", "/fail/off"):
            failing = self.path.endswith("on")
            return self._json(200, {"failing": failing})
        prefix = "/api/v1/notification/passthrough/"
        if not self.path.startswith(prefix):
            return self._json(404, {"result": "error", "details": {"response": "not found"}})
        if failing:
            return self._json(503, {"result": "error", "details": {"response": "simulated outage"}})
        try:
            payload = json.loads(body)
            int(payload["discord"]["ids"]["channel"])
        except (ValueError, KeyError, TypeError):
            return self._json(400, {"result": "error", "details": {"response": "bad payload"}})
        messages.append({"key_ok": self.path[len(prefix):] == KEY, "payload": payload})
        self._json(200, {"result": "success", "details": {"response": "Pass through payload processed."}})

    def log_message(self, fmt, *args):  # one short line per request, without the key
        print(self.command, self.path.split("/passthrough/")[0], args[1] if len(args) > 1 else "", flush=True)


ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
