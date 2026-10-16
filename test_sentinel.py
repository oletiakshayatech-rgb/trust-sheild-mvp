from app.sentinel import assess_url, build
HI = ("High", "Critical"); L = lambda u: assess_url(u)["risk_level"]
def test_official_low(): assert L("https://www.google.com/search") == "Low"
def test_homoglyph(): assert L("http://g00gle-login.test/verify") in HI
def test_brand_in_subdomain_trick(): assert L("https://paytm.com.evil.test/") in HI
def test_ip_login(): assert L("http://192.168.0.5/login") in HI
def test_unknown_benign(): assert L("https://example.org/about") == "Low"
def test_missing_threat_intel_is_stated(): assert "threat-intelligence" in assess_url("https://example.org")["missing"][0]
def test_attack_vs_benign_graph():
    a, b = build("college", 3), build("announce", 2)
    assert any(e["hot"] for e in a["graph"]["edges"]) and a["path"] and a["assessment"]["risk_level"] == "Critical"
    assert not any(e["hot"] for e in b["graph"]["edges"]) and not b["path"] and b["assessment"]["risk_level"] == "Low"
    assert b["timeline"][3]["detail"].startswith("No escalation")
def test_graph_integrity():
    for sid in ("college", "contact", "announce"):
        g = build(sid, 3)["graph"]; ids = {n["id"] for n in g["nodes"]}
        assert all(e["from"] in ids and e["to"] in ids for e in g["edges"])
def test_unverified_not_fraud_wording(): assert "Unverified" not in build("announce", 1)["assessment"]["identity"]["note"] or "not confirmed impersonation" in build("announce", 1)["assessment"]["identity"]["note"]
