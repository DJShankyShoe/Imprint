"""Shared helpers for the Imprint evaluation harness (no network, no MongoDB)."""
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
IMPRINT = REPO / "scripts" / "imprint"
OUT = Path(os.environ.get("EVAL_OUT", HERE / "out"))

RANK = {"allow": 0, "CAPTCHA": 1, "RATE_LIMIT": 2, "OTP": 3, "HONEYPOT": 4, "BLOCK": 5}
BUCKET_MID = {"low": 15, "medium": 45, "high": 72, "critical": 92}
BUCKETS = ["low", "medium", "high", "critical"]


def setup_env():
    """Point the real Imprint modules at this repo's rules and a local audit log.
    Must run BEFORE importing classify/advisor (they read env at import time)."""
    OUT.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("IMPRINT_RULES_DIR", str(IMPRINT / "rules"))
    os.environ.setdefault("IMPRINT_ENV_FILE", str(REPO / ".env"))
    os.environ.setdefault("IMPRINT_AUDIT_LOG", str(OUT / "classifier_audit.jsonl"))
    if str(IMPRINT) not in sys.path:
        sys.path.insert(0, str(IMPRINT))


def load_scenarios(path=None):
    with open(path or HERE / "scenarios.json", encoding="utf-8") as f:
        return json.load(f)


def level(actions):
    """Strength of an action list (max rank)."""
    return max(RANK[a] for a in actions)


def decision_tier(s):
    """Which stored action list the enforcement module would apply."""
    return s["match_tier"] if s["match_tier"] in ("full", "tier1") else "full"


def build_doc(s):
    return {"full_hash": s["id"] + "_full", "tier1_hash": s["id"] + "_t1",
            "observations": s["observations"]}


def build_fp(s):
    fp = s["fingerprint"]
    return {
        "components": {
            "platform": {"value": fp["platform"]},
            "webGlBasics": {"value": {"rendererUnmasked": fp["webgl_renderer"],
                                      "vendorUnmasked": fp["webgl_vendor"]}},
            "wasmSupport": {"value": {"supported": True}},
            "canvas": {"value": "c0ffee"},
            "fonts": {"value": "f0f0f0"},
        },
        "additionalData": {"vmDetection": {"isVM": bool(fp["vm"])}},
    }


class FakeCol:
    """Just enough of a pymongo collection for advisor.update_actions."""
    def __init__(self, doc, distinct):
        self.doc, self.n = doc, distinct

    def find_one(self, q, proj=None):
        return self.doc

    def distinct(self, field, q=None):
        return [f"h{i}" for i in range(self.n)]

    def update_one(self, q, u):
        self.doc.update(u.get("$set", {}))


def insert_status(s):
    return "updated" if s["match_tier"] == "full" else "inserted"


def expected_actions(s, advisor, matrix, signals):
    """Actions implied by the analyst label (malicious scenarios only), using the
    repo's own matrix + tier-1 rule. Benign scenarios: anything <= CAPTCHA is correct."""
    lab = s["label"]
    if not lab["malicious"]:
        return None
    confirmed = advisor.match_confirmed_signal(s["trigger_alert"], signals)
    corr = bool(confirmed) and 2 <= s["distinct_full_hashes"] <= 3
    cls = {"category": lab["category"], "severity": BUCKET_MID[lab["severity_bucket"]]}
    return advisor.apply_matrix(cls, decision_tier(s), matrix, corr)
