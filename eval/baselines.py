"""Baselines B0 (WAF-style) and B1 (static score-based advisor).

FREEZE THIS FILE BEFORE THE FIRST EVALUATION RUN (git commit it). Tuning weights after
seeing results would handicap/favour a system and invalidates the comparison.
"""

# ---- B0: ModSecurity + OWASP CRS style, IP-keyed, no actor memory -----------------
# CRS anomaly points: CRITICAL=5, ERROR=4, WARNING=3, NOTICE=2; inbound block threshold=5.
# Only alert names that the CRS has request-level rules for score points. Behavioural
# alerts (brute force, scraping, burst rates) are not CRS request rules -> 0 points.
# ASSUMPTION: verify against real ModSecurity logs from the PoC (see README).
CRS_POINTS = {
    "sqli": 5, "xss": 5, "rce": 5, "phpi": 5,                    # CRS 942/941/932/933 (critical)
    "path_traversal": 5, "ssrf_attempt": 5, "log4shell_jndi": 5,  # CRS 930/934/944 (critical)
    "header_smuggling": 5, "scanner_detected": 5,                 # CRS 921/913 (critical)
}
B0_THRESHOLD = 5


def b0_actions(s):
    """Block the request IP once the accumulated anomaly score for THAT IP hits threshold.
    The request comes from s['request_ip'] (a fresh IP for returning attackers)."""
    ip = s["request_ip"]
    score = sum(CRS_POINTS.get(o["attackType"], 0) for o in s["observations"] if o["ip"] == ip)
    acts = ["BLOCK"] if score >= B0_THRESHOLD else ["allow"]
    return {"tier1": acts, "full": acts}, score


# ---- B1: static score-based advisor (same feature record, guardrails and matrix) ---
KEYWORDS = [  # first match wins per label
    ("injection_attack", ("inject",)),
    ("credential_stuffing", ("brute", "credential", "stuffing", "login_fail")),
    ("bot_scraping", ("scrap", "crawl")),
    ("reconnaissance", ("scan", "recon", "enum", "probe")),
    ("automated_exploitation", ("exploit", "botnet")),
]
BASE = {"injection_attack": 55, "credential_stuffing": 40, "bot_scraping": 30,
        "reconnaissance": 25, "automated_exploitation": 60, "unknown": 10}
W_REPEAT, CAP_REPEAT = 5, 6       # per extra observation
W_IP, CAP_IP = 4, 5               # per extra distinct IP
W_CC, CAP_CC = 6, 3               # per extra distinct country
W_PROXY, W_VM, W_PRIVATE = 8, 6, 3
TIER1_WEAK_AT, TIER1_PENALTY = 4, 15   # many full hashes under one tier-1 = weak evidence
KNOWN_CONFIDENCE = 90


EXACT_INJECTION = {"sqli", "xss", "rce", "phpi"}   # exact match: "rce" is a substring of "brute_force"


def _category(label):
    l = (label or "").lower().strip()
    if l in EXACT_INJECTION:
        return "injection_attack"
    for cat, kws in KEYWORDS:
        if any(k in l for k in kws):
            return cat
    return "unknown"


def b1_classify(fr):
    labels = fr["history"]["attack_labels_seen"] or [fr["current_event"]["reported_attack_label"]]
    cats = [_category(l) for l in labels]
    cat = max(cats, key=lambda c: BASE[c])                 # most severe category seen
    sev = BASE[cat]
    sev += W_REPEAT * min(max(fr["meta"]["total_observations"] - 1, 0), CAP_REPEAT)
    sev += W_IP * min(max(fr["history"]["distinct_ip_count"] - 1, 0), CAP_IP)
    sev += W_CC * min(max(len(fr["history"]["distinct_countries"]) - 1, 0), CAP_CC)
    sev += W_PROXY * bool(fr["current_event"]["proxy"])
    sev += W_VM * bool(fr["device_signals"]["vm_detected"])
    sev += W_PRIVATE * bool(fr["current_event"]["is_private_browsing"])
    if fr["identity_match"]["distinct_full_hashes_under_this_tier1"] >= TIER1_WEAK_AT:
        sev -= TIER1_PENALTY
    sev = max(0, min(100, sev))
    return {"category": cat, "confidence": KNOWN_CONFIDENCE if cat != "unknown" else 0,
            "severity": sev, "evidence": []}
