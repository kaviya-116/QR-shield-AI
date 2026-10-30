"""URL analysis, transparent risk scoring, threat-intel adapter, SSRF-guarded redirect tracer."""
import base64, ipaddress, json, os, re, socket, ssl, urllib.error, urllib.request
from urllib.parse import parse_qsl, urljoin, urlsplit

# Configurable weights: every triggered indicator adds its weight (score capped at 100).
WEIGHTS = dict(ip_host=35, userinfo=35, punycode=25, non_ascii=30, shortener=15, many_subdomains=15,
               long_url=10, odd_encoding=15, sensitive_params=30, risky_tld=15, no_https=15,
               brand_misuse=30, keyword_host=10, purpose_mismatch=25, odd_port=10, embedded_url=10)
AMBER_AT = int(os.getenv("AMBER_THRESHOLD", "25"))
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly"}
RISKY_TLDS = {"zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "click", "country", "work", "support", "rest"}
BRANDS = {"paypal", "google", "microsoft", "apple", "amazon", "paytm", "phonepe", "gpay", "sbi", "hdfc", "icici", "netflix", "facebook", "instagram", "whatsapp"}
KEYWORDS = {"login", "signin", "secure", "verify", "update", "wallet", "bonus", "account", "reward"}
SENSITIVE = {"password", "passwd", "pwd", "otp", "pin", "cvv", "ssn", "card", "cardnumber", "aadhaar", "pan"}
MULTI = {"co.uk", "com.au", "co.in", "org.in", "gov.in", "ac.in", "co.jp", "com.br"}


def registered_domain(host):
    p = host.split(".")
    if len(p) >= 3 and ".".join(p[-2:]) in MULTI:
        return ".".join(p[-3:])
    return ".".join(p[-2:]) if len(p) >= 2 else host


def analyze_url(raw, purpose="general", expected_domain=""):
    raw = (raw or "").strip()
    bad = lambda why: {"ok": False, "error": why, "host": None, "indicators": [], "context": [], "score": 0}
    if not raw:
        return bad("Empty input.")
    if len(raw) > 4096:
        return bad("Input is longer than 4096 characters.")
    if re.search(r"[\x00-\x1f]", raw):
        return bad("URL contains control characters.")
    try:
        u = urlsplit(raw)
        host, port = (u.hostname or "").lower(), u.port
    except ValueError:
        return bad("Malformed URL.")
    if u.scheme.lower() not in ("http", "https"):
        return bad(f"Unsupported protocol '{u.scheme}:'. Only http(s) links are analyzed, and nothing is opened.")
    if not host:
        return bad("No hostname found in URL.")

    ind, ctx = [], []
    def add(key, label, detail):
        ind.append({"id": key, "label": label, "weight": WEIGHTS[key], "detail": detail})

    reg = registered_domain(host)
    sld = reg.split(".")[0]
    is_ip = False
    try:
        ipaddress.ip_address(host.strip("[]")); is_ip = True
    except ValueError:
        pass
    if is_ip:
        add("ip_host", "IP address used as hostname", "Legitimate services rarely ask people to visit a bare IP address.")
    elif re.fullmatch(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+))*", host):
        is_ip = True
        add("ip_host", "Numeric hostname disguised as an IP", "Decimal/hex hostnames are an obfuscation trick.")
    if u.username is not None or "@" in u.netloc:
        add("userinfo", "Credentials/@ in URL", "Text before '@' can make a link look like it belongs to another site.")
    nonascii = any(ord(c) > 127 for c in host)
    puny = any(l.startswith("xn--") for l in host.split("."))
    if nonascii:
        add("non_ascii", "Non-ASCII characters in hostname", "Look-alike characters can imitate well-known domains.")
    if puny:
        add("punycode", "Internationalized (punycode) domain", "xn-- labels may hide look-alike characters. Not proof of abuse by itself.")
    if len(host.split(".")) - len(reg.split(".")) >= 3:
        add("many_subdomains", "Unusually deep subdomain chain", "Long subdomain chains can push the real domain out of sight.")
    short = reg in SHORTENERS
    if short:
        add("shortener", "URL-shortening service", "The final destination is hidden until the link is followed.")
    if reg.split(".")[-1] in RISKY_TLDS and not is_ip:
        add("risky_tld", f"Top-level domain .{reg.split('.')[-1]} is often abused", "Weak signal: many legitimate sites also use it.")
    if u.scheme.lower() == "http":
        add("no_https", "No HTTPS encryption", "Traffic to this site is not encrypted.")
    if len(raw) > 200:
        add("long_url", "Unusually long URL", f"{len(raw)} characters.")
    if "%" in u.netloc or raw.count("%") > 8 or "\\" in raw:
        add("odd_encoding", "Unusual encoding or syntax", "Heavy percent-encoding or backslashes can disguise the real target.")
    q = parse_qsl(u.query, keep_blank_values=True)
    sens = sorted({k.lower() for k, _ in q if k.lower() in SENSITIVE})
    if sens:
        add("sensitive_params", "Sensitive field names in query", "Parameters: " + ", ".join(sens))
    if any(re.match(r"https?://", v, re.I) for _, v in q):
        add("embedded_url", "Another URL embedded in a parameter", "Can indicate an open redirect.")
    brand = next((b for b in BRANDS if b in host and b != sld and b not in sld.split("-")), None)
    if brand and not is_ip:
        add("brand_misuse", f"Brand name '{brand}' in an unrelated domain", f"Registered domain is {reg}.")
    kw = sorted(k for k in KEYWORDS if k in host.replace("-", ".").split("."))
    if kw and not is_ip:
        add("keyword_host", "Urgency/credential words in hostname", ", ".join(kw))
    if port not in (None, 80, 443):
        add("odd_port", "Non-standard port", f"Port {port}.")

    exp = (expected_domain or "").strip().lower().lstrip("*.")
    if exp and host != exp and not host.endswith("." + exp):
        ctx.append(f"You expected {exp}, but the QR points to {host}.")
    if purpose == "payment" and (short or is_ip or u.scheme.lower() == "http"):
        ctx.append("Payment QR codes normally use a direct, encrypted link to a known provider; this one is shortened, an IP, or unencrypted.")
    if purpose == "login" and (brand or puny or nonascii or kw):
        ctx.append("Login QR codes should lead to the exact official domain; this host has look-alike or credential-bait patterns.")
    if purpose in ("event", "advertisement") and sens:
        ctx.append("An event or advertisement link should not need passwords, PINs, OTPs or card data.")
    if ctx:
        add("purpose_mismatch", "Destination does not fit the stated QR purpose",
            " ".join(ctx) + " A mismatch is a warning signal, not proof of malice.")
    score = min(100, sum(i["weight"] for i in ind))
    return {"ok": True, "host": host, "registered": reg, "scheme": u.scheme.lower(), "indicators": ind, "context": ctx, "score": score,
            "https_note": "HTTPS only means the connection is encrypted. It does not mean the site is trustworthy."}


def _clean(url):
    u = urlsplit(url)
    return f"{u.scheme}://{(u.hostname or '')}{':' + str(u.port) if u.port else ''}{u.path}"


def real_key():
    k = os.getenv("VT_API_KEY", "").strip()
    return "" if (not k or k.lower().startswith("your_") or "placeholder" in k.lower()) else k


def check_intel(url):
    """VirusTotal v3 URL lookup (server-side key). Sends only scheme+host+path (no query, fragment or userinfo)."""
    key, mode = real_key(), os.getenv("DEMO_MODE", "auto").lower()
    host = urlsplit(url).hostname or ""
    if not key or mode in ("1", "true", "yes"):
        if "demo-threat" in host:
            return {"source": "demo", "status": "demo_malicious", "detail": "DEMO fixture: simulated 'malicious' verdict. No real lookup happened."}
        if "demo-unavailable" in host:
            return {"source": "demo", "status": "error", "detail": "DEMO fixture: simulated service outage."}
        return {"source": "demo", "status": "demo_no_report", "detail": "DEMO MODE: no external reputation lookup was performed."}
    uid = base64.urlsafe_b64encode(_clean(url).encode()).decode().strip("=")
    req = urllib.request.Request("https://www.virustotal.com/api/v3/urls/" + uid, headers={"x-apikey": key, "accept": "application/json"})
    err = lambda d: {"source": "virustotal", "status": "error", "detail": d}
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            data = json.loads(r.read(1_000_000))
        stats = data["data"]["attributes"]["last_analysis_stats"]
        mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"source": "virustotal", "status": "unknown", "detail": "VirusTotal has no report for this URL. That does not mean it is safe."}
        return err("Rate limit reached; try again later." if e.code == 429 else f"VirusTotal returned HTTP {e.code}.")
    except (urllib.error.URLError, TimeoutError, OSError):
        return err("VirusTotal was unreachable or timed out.")
    except (ValueError, KeyError, TypeError):
        return err("VirusTotal returned an unexpected response.")
    if mal >= int(os.getenv("VT_MIN_MALICIOUS", "2")):
        return {"source": "virustotal", "status": "malicious", "detail": f"{mal} engine(s) flag this URL as malicious ({sus} suspicious)."}
    return {"source": "virustotal", "status": "clean", "detail": f"No known-malicious verdict ({mal} malicious, {sus} suspicious engines). Not a guarantee."}


def verdict(local, intel):
    if not local["ok"]:
        return "gray"
    if intel["status"] in ("malicious", "demo_malicious"):
        return "red"
    if local["score"] >= AMBER_AT:
        return "amber"
    return "gray" if intel["status"] == "error" else "green"


def full_report(url, purpose, expected):
    local = analyze_url(url, purpose, expected)
    intel = check_intel(url) if local["ok"] else {"source": "none", "status": "skipped", "detail": "Skipped: URL could not be evaluated."}
    sources = ["local analysis"] + ([intel["source"]] if intel["source"] in ("virustotal", "demo") else [])
    return {**local, "intel": intel, "category": verdict(local, intel), "sources": sources, "purpose": purpose,
            "factors": [{k: i[k] for k in ("label", "weight")} for i in local["indicators"]]}


# ---------- Redirect tracing (SSRF-guarded) ----------
class Unsafe(Exception):
    pass


def _public_ip(host, port):
    try:
        ips = {i[4][0] for i in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
    except socket.gaierror:
        raise Unsafe("DNS lookup failed")
    for ip in ips:
        a = ipaddress.ip_address(ip.split("%")[0])
        a = getattr(a, "ipv4_mapped", None) or a
        if not a.is_global or a.is_multicast:
            raise Unsafe("Host resolves to a private/local address (blocked)")
    return sorted(ips)[0]


def _head(url):
    if re.search(r"[\x00-\x20]", url.strip()):
        raise Unsafe("Whitespace/control characters in URL")
    u = urlsplit(url)
    if u.scheme not in ("http", "https") or u.username or u.port not in (None, 80, 443) or not u.hostname:
        raise Unsafe("Blocked scheme, credentials or port")
    port = u.port or (443 if u.scheme == "https" else 80)
    host = u.hostname.encode("idna").decode()
    ip = _public_ip(host, port)  # connect to the validated IP itself: defeats DNS rebinding
    s = socket.create_connection((ip, port), timeout=4)
    try:
        if u.scheme == "https":
            s = ssl.create_default_context().wrap_socket(s, server_hostname=host)
        s.settimeout(4)
        path = (u.path or "/") + ("?" + u.query if u.query else "")
        s.sendall(f"HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: QRShield/1.0\r\nConnection: close\r\n\r\n".encode())
        head = s.recv(8192).decode("latin-1")
    finally:
        s.close()
    lines = head.split("\r\n")
    status = int(lines[0].split()[1])
    loc = next((l.split(":", 1)[1].strip() for l in lines[1:] if l.lower().startswith("location:")), None)
    return status, loc


def _hop(url, state, note, demo=False):
    u = urlsplit(url)
    host = (u.hostname or "?").lower()
    return {"host": host, "registered": registered_domain(host), "display": f"{u.scheme}://{host}{u.path}", "state": state, "note": note, "demo": demo}


def trace_redirects(url):
    if os.getenv("ALLOW_LIVE_REDIRECTS") != "1":
        host = urlsplit(url).hostname or "unknown"
        hops = [_hop(url, "start", "Starting URL from the QR code.", True),
                _hop("https://track.demo-redirect.test/r", "redirect", "SIMULATED intermediate tracker.", True),
                _hop("https://landing.demo-final.test/", "final", "SIMULATED final destination.", True)]
        mode, note = "demo", "DEMO MODE: this chain is simulated, not observed. Set ALLOW_LIVE_REDIRECTS=1 for live, guarded tracing."
    else:
        hops, cur, mode, note = [], url, "live", "Observed with HEAD requests; every hop validated before connecting."
        for n in range(6):
            try:
                status, loc = _head(cur)
            except Unsafe as e:
                hops.append(_hop(cur, "blocked", str(e))); break
            except Exception:
                hops.append(_hop(cur, "unverified", "Could not connect or read a valid response.")); break
            if status in (301, 302, 303, 307, 308) and loc:
                hops.append(_hop(cur, "start" if n == 0 else "redirect", f"HTTP {status} redirect."))
                cur = urljoin(cur, loc)
                continue
            hops.append(_hop(cur, "start" if n == 0 else "final", f"HTTP {status}; final observed destination."))
            break
        else:
            hops.append(_hop(cur, "unverified", "Redirect limit reached; final destination not established."))
    for a, b in zip(hops, hops[1:]):
        if a["registered"] != b["registered"]:
            b["flag"] = f"Domain changed: {a['registered']} to {b['registered']}"
    return {"mode": mode, "note": note, "hops": hops}
