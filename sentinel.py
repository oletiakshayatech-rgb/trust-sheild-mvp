"""Sentinel: URL assessment, attack-graph construction, event log. Demo data is labelled as such."""
import itertools, re
from collections import deque
from urllib.parse import urlsplit
from .trust import full_assess, SCENARIOS
BRANDS = {"sbi": "sbi.co.in", "hdfcbank": "hdfcbank.com", "paytm": "paytm.com", "google": "google.com", "examplecollege": "examplecollege.edu"}
TH = {"medium": 3, "high": 5, "critical": 8}
KW = re.compile(r"login|verify|secure|update|otp|account", re.I)
HOMO = str.maketrans("0135", "oles")

def _lev(a, b):
    p = list(range(len(b) + 1))
    for i, x in enumerate(a, 1):
        c = [i]
        for j, y in enumerate(b, 1): c.append(min(p[j] + 1, c[-1] + 1, p[j - 1] + (x != y)))
        p = c
    return p[-1]

def assess_url(raw):
    sp = urlsplit(raw if "://" in raw else "http://" + raw)
    host = (sp.hostname or "").lower(); sig, facts = [], []
    add = lambda i, w, t: sig.append({"id": i, "weight": w, "explanation": t})
    off = next((d for d in BRANDS.values() if host == d or host.endswith("." + d)), None)
    deob = host.translate(HOMO)
    if off: facts.append(f"Host matches configured official domain {off} (a domain match is not proof of identity).")
    else:
        hit = next(((b, d) for b, d in BRANDS.items() if b in deob), None)
        if hit: add("brand_in_unofficial_domain", 5, f"Contains '{hit[0]}' but is not the configured official domain {hit[1]}.")
        else:
            for lab in deob.split("."):
                b = next((b for b in BRANDS if len(b) >= 5 and lab != b and _lev(lab, b) <= 2), None)
                if b: add("lookalike_domain", 4, f"Label '{lab}' is within 2 edits of '{b}'."); break
    if "xn--" in host: add("punycode", 3, "Punycode host: may hide look-alike characters.")
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host): add("ip_host", 3, "Raw IP address instead of a domain name.")
    if sp.username is not None: add("userinfo", 3, "URL contains '@' credentials-style prefix that can disguise the real host.")
    if host.count(".") >= 4: add("many_subdomains", 1, "Unusually many subdomain levels.")
    if host.count("-") >= 2: add("hyphen_heavy", 1, "Several hyphens in host name.")
    base = sum(s["weight"] for s in sig)
    if base:  # context signals only count alongside structural ones
        if KW.search(host + sp.path): add("sensitive_keywords", 1, "Login/verification wording in host or path.")
        if sp.scheme == "http": add("no_tls", 1, "Not using HTTPS.")
    score = sum(s["weight"] for s in sig)
    lvl = "Critical" if score >= TH["critical"] else "High" if score >= TH["high"] else "Medium" if score >= TH["medium"] else "Low"
    return {"url_host": host, "risk_level": lvl, "score": score, "signals": sig, "facts": facts,
            "inferred": [s["explanation"] for s in sig],
            "missing": ["No threat-intelligence lookup configured or performed.", "Domain age/registration not checked."],
            "limitations": ["Heuristic: unknown brands and novel tricks are not covered.", "Low never guarantees safety."]}

EVENTS, _ids = deque(maxlen=200), itertools.count(1)
def push(source, kind, summary, level):
    e = {"id": next(_ids), "source": source, "label": "LIVE-EXTENSION" if source == "extension" else "DEMO-SIMULATION",
         "kind": kind, "summary": summary, "level": level}
    EVENTS.append(e); return e

DEMO = SCENARIOS + [{"id": "announce", "title": "C: Legitimate announcement (benign)",
  "profile": {"name": "Event organiser", "role": "Student affairs", "expected_channel": "college portal",
              "verification_method": "Check the official event page", "trusted_reference": "", "expected_requests": []},
  "messages": [{"from": "Organiser", "channel": "college portal notice", "text": "Hi, the workshop begins at 4 PM."},
               {"from": "Organiser", "channel": "college portal notice", "text": "Please check the official event page for the meeting link."}]}]

def build(sid, step):
    sc = next((s for s in DEMO if s["id"] == sid), None)
    if not sc: return None
    step = max(1, min(step, len(sc["messages"]))); ms = sc["messages"][:step]; p = sc["profile"]
    a = full_assess(" ".join(m["text"] for m in ms), p, ms[-1]["channel"]); i = a["identity"]
    hot = a["risk_level"] in ("High", "Critical"); asks = a["action_risk"]["requests"]
    chan_bad = any("differs" in m for m in i["mismatches"])
    st = "verified" if i["status"] == "Verified" else "suspicious" if (i["mismatches"] and asks) else "unverified" if i["mismatches"] else "unknown"
    N = [{"id": "user", "label": "You", "type": "person", "state": "unknown", "detail": "Local user (self).", "provenance": "session"},
         {"id": "sender", "label": p["name"], "type": "person", "state": st, "detail": f"Claimed sender. Identity status: {i['status']}.", "provenance": "claimed in message; not verified"},
         {"id": "role", "label": p["role"], "type": "role", "state": "unknown", "detail": "Role claimed/configured for this contact.", "provenance": "Trust Graph profile (user-configured demo data)"},
         {"id": "channel", "label": ms[-1]["channel"], "type": "channel", "state": "suspicious" if chan_bad else "unknown",
          "detail": f"Expected: {p['expected_channel']}. " + ("Differs from expectation." if chan_bad else "Matches expectation (not proof)."), "provenance": "observed channel (demo)"}]
    E = [{"from": "sender", "to": "user", "label": "contacts", "hot": False}, {"from": "sender", "to": "role", "label": "claims", "hot": False},
         {"from": "sender", "to": "channel", "label": "via", "hot": chan_bad and hot}]
    for k in asks:
        N.append({"id": "req_" + k, "label": "asks: " + k, "type": "request", "state": "suspicious", "detail": next(x["evidence"] for x in a["indicators"] if x["id"] == k), "provenance": "rule:" + k})
        E.append({"from": "sender", "to": "req_" + k, "label": "requests", "hot": hot})
    for x in a["behaviour"]:
        if x["kind"] == "pressure" or x["id"] in ("authority", "emotional"):
            N.append({"id": "ind_" + x["id"], "label": x["id"], "type": "indicator", "state": "suspicious", "detail": x["evidence"], "provenance": "rule:" + x["id"]})
            E.append({"from": "sender", "to": "ind_" + x["id"], "label": "exhibits", "hot": hot})
    path = ["sender", "user"] + [n["id"] for n in N if n["id"][:4] in ("req_", "ind_")] + (["channel"] if chan_bad else []) if hot else []
    tl = [{"stage": "Initial interaction", "detail": f"{len(ms)} message(s) via {ms[-1]['channel']}"},
          {"stage": "Identity evidence assessed", "detail": i["status"]},
          {"stage": "Behavioural indicators", "detail": ", ".join(x["id"] for x in a["behaviour"]) or "none detected"},
          {"stage": "Risk escalation", "detail": a["risk_level"] if hot else "No escalation supported by the evidence"},
          {"stage": "Recommended intervention", "detail": a["safe_action"]}]
    return {"id": sid, "title": sc["title"], "labelled": "DEMO DATA: deterministic simulation, not a real attack", "step": step, "total": len(sc["messages"]),
            "timeline": tl, "assessment": a, "graph": {"nodes": N, "edges": E}, "path": path,
            "facts": [x["evidence"] for x in a["indicators"]] + i["evidence"], "inferred": a["reasons"] + ["Overall risk: " + a["risk_level"]],
            "missing": i["missing"] + ["No trusted identity provider is connected."]}
