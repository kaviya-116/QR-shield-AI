# QR Shield AI

Scan a QR code, see where it really leads, and get an explainable risk report before you visit anything.
Flask backend + vanilla HTML/CSS/JS frontend + jsQR decoding.

## Run locally
```bash
python -m venv .venv
.venv\Scripts\activate          # Windows   (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt
copy .env.example .env          # macOS/Linux: cp .env.example .env
python app.py
```
Open http://127.0.0.1:5000. Camera access works on localhost. jsQR loads from cdnjs, so you need internet once
(offline: save https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js as `static/vendor/jsQR.js`; it is loaded first when present).

## Test
`python -m unittest discover -s tests -v`

## Threat intelligence (VirusTotal)
1. Create a free VirusTotal account and copy your API key.
2. Put it in `.env`: `VT_API_KEY=...` (the key stays server-side; `.env` is git-ignored).
3. Restart. The sidebar changes from "DEMO MODE" to "VirusTotal".
Only scheme + host + path are sent to VirusTotal (no query, fragment, credentials). Free keys are rate-limited; limits show as GRAY.
Without a key, DEMO MODE runs: no real lookup happens and it is labelled everywhere.
Demo fixtures: hostnames containing `demo-threat` give RED; `demo-unavailable` gives GRAY.

## Redirect tracing
Default is a simulated, clearly labelled chain. `ALLOW_LIVE_REDIRECTS=1` enables live HEAD-only tracing that blocks
private/loopback/metadata IPs, re-validates every hop, connects to the validated IP (anti DNS rebinding), allows only
http(s) on ports 80/443, and stops after 6 hops. Run it behind a firewall/egress policy if you deploy publicly.

## Try these links (paste box on the Scanner page)
- `https://www.wikipedia.org/` → GREEN (demo mode)
- `https://paypal.secure-login.top/verify?otp=1` with purpose Login → AMBER
- `http://192.168.1.5/pay` with purpose Payment → AMBER
- `https://demo-threat.test/` → RED (demo fixture)
- `javascript:alert(1)` → rejected, GRAY

## Layout
`app.py` routes and headers · `analyzer.py` URL rules, scoring, VirusTotal adapter, redirect tracer · `static/` UI · `tests/`
Scoring weights live in `WEIGHTS` in `analyzer.py`; the amber cut-off is `AMBER_THRESHOLD`.
