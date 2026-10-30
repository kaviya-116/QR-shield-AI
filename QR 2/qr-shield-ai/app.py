"""QR Shield AI backend. Run: python app.py"""
import os
from flask import Flask, jsonify, request, send_from_directory
from analyzer import full_report, real_key, trace_redirects

try:  # optional .env support without extra dependencies
    for line in open(".env"):
        if "=" in line and not line.startswith("#"):
            k, v = line.strip().split("=", 1)
            os.environ.setdefault(k, v)
except FileNotFoundError:
    pass

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
PURPOSES = {"payment", "event", "login", "advertisement", "general"}


@app.after_request
def headers(r):
    r.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline'; "
                                            "img-src 'self' data: blob:; media-src blob:; connect-src 'self'; frame-ancestors 'none'")
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Referrer-Policy"] = "no-referrer"
    return r


def body():
    d = request.get_json(silent=True) or {}
    url = d.get("url") if isinstance(d.get("url"), str) else ""
    return url, d


@app.get("/")
def index():
    return send_from_directory("static", "index.html")


@app.get("/api/status")
def status():
    demo = not real_key() or os.getenv("DEMO_MODE", "auto").lower() in ("1", "true", "yes")
    return jsonify(threat_intel="demo" if demo else "virustotal", live_redirects=os.getenv("ALLOW_LIVE_REDIRECTS") == "1")


@app.post("/api/analyze")
def analyze():
    url, d = body()
    purpose = d.get("purpose") if d.get("purpose") in PURPOSES else "general"
    expected = d.get("expected_domain") if isinstance(d.get("expected_domain"), str) else ""
    return jsonify(full_report(url, purpose, expected[:253]))


@app.post("/api/redirects")
def redirects():
    url, _ = body()
    if not url.lower().startswith(("http://", "https://")) or len(url) > 4096:
        return jsonify(error="Only http(s) URLs can be traced."), 400
    return jsonify(trace_redirects(url))


@app.errorhandler(413)
def too_big(e):
    return jsonify(error="Request too large."), 413


@app.errorhandler(Exception)
def oops(e):
    code = getattr(e, "code", 500)
    return jsonify(error="Request failed." if code == 500 else str(e)), code if isinstance(code, int) else 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
