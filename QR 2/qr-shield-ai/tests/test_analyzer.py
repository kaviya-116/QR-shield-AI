"""Run: python -m unittest discover -s tests -v   (or pytest)"""
import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.pop("VT_API_KEY", None)
from analyzer import analyze_url, full_report, trace_redirects, _public_ip, Unsafe

ids = lambda r: {i["id"] for i in r["indicators"]}

class T(unittest.TestCase):
    def test_clean_https(self):
        r = full_report("https://www.wikipedia.org/wiki/QR_code", "general", "")
        self.assertEqual(r["category"], "green"); self.assertEqual(r["intel"]["source"], "demo")
    def test_ip_host(self): self.assertIn("ip_host", ids(analyze_url("http://192.168.1.5/login")))
    def test_userinfo(self): self.assertIn("userinfo", ids(analyze_url("https://paypal.com@evil.example/")))
    def test_punycode(self): self.assertIn("punycode", ids(analyze_url("https://xn--pple-43d.com/")))
    def test_shortener_payment(self):
        self.assertTrue({"shortener", "purpose_mismatch"} <= ids(analyze_url("https://bit.ly/abc", "payment")))
    def test_event_sensitive(self):
        self.assertIn("purpose_mismatch", ids(analyze_url("https://events.example.org/r?otp=1", "event")))
    def test_expected_domain(self):
        self.assertTrue(analyze_url("https://other.com/", "payment", "mybank.com")["context"])
    def test_brand_misuse(self): self.assertIn("brand_misuse", ids(analyze_url("https://paypal.secure-login.top/")))
    def test_real_brand_ok(self): self.assertNotIn("brand_misuse", ids(analyze_url("https://www.paypal.com/")))
    def test_rejects(self):
        for u in ["javascript:alert(1)", "data:text/html,x", "file:///etc/passwd", "", "http://"]:
            self.assertFalse(analyze_url(u)["ok"]); self.assertEqual(full_report(u, "general", "")["category"], "gray")
    def test_weak_not_red(self): self.assertNotEqual(full_report("http://example.com/", "general", "")["category"], "red")
    def test_demo_threat(self): self.assertEqual(full_report("https://demo-threat.test/", "general", "")["category"], "red")
    def test_demo_outage(self): self.assertEqual(full_report("https://demo-unavailable.test/", "general", "")["category"], "gray")
    def test_redirect_demo(self):
        t = trace_redirects("https://a.example/x"); self.assertTrue(t["mode"] == "demo" and all(h["demo"] for h in t["hops"]))
    def test_ssrf(self):
        for h in ["127.0.0.1", "localhost", "169.254.169.254", "10.0.0.1"]:
            with self.assertRaises(Unsafe): _public_ip(h, 80)
    def test_placeholder_key_is_demo(self):
        os.environ["VT_API_KEY"] = "your_virustotal_api_key_here"
        try: self.assertEqual(full_report("https://example.org/", "general", "")["intel"]["source"], "demo")
        finally: os.environ.pop("VT_API_KEY")
    def test_api(self):
        from app import app
        c = app.test_client()
        self.assertEqual(c.post("/api/analyze", json={"url": "javascript:x"}).get_json()["category"], "gray")
        self.assertEqual(c.post("/api/redirects", json={"url": "file:///x"}).status_code, 400)
        self.assertIn("Content-Security-Policy", c.get("/api/status").headers)

if __name__ == "__main__": unittest.main()
