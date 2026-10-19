"""Test setup: point the real Imprint modules at the repo rules and temp paths.
Environment must be set BEFORE importing classify/advisor/service."""
import copy
import os
import sys
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
IMPRINT = REPO / "scripts" / "imprint"
TMP = Path(tempfile.mkdtemp(prefix="imprint_tests_"))

os.environ["IMPRINT_RULES_DIR"] = str(IMPRINT / "rules")
os.environ["IMPRINT_ENV_FILE"] = str(TMP / "none.env")
os.environ["IMPRINT_AUDIT_LOG"] = str(TMP / "audit.jsonl")
os.environ["IMPRINT_PAYLOAD_KEY_DIR"] = str(TMP / "k1")
os.environ["IMPRINT_SESSION_KEY_DIR"] = str(TMP / "k2")
os.environ["IMPRINT_SITE_TOKEN"] = "site-token"
os.environ["IMPRINT_ALERT_TOKEN"] = "alert-token"
os.environ["MONGO_USER"] = "u"
os.environ["MONGO_PASSWORD"] = "p"
sys.path.insert(0, str(IMPRINT))

BASE_FP = {
    "components": {
        "platform": {"value": "Win32"},
        "colorDepth": {"value": 24},
        "browserInfo": {"value": {"os": "Windows", "mobile": False, "browser": "Chrome"}},
        "userAgent": {"value": "Mozilla/5.0 A"},
        "wasmSupport": {"value": {"supported": True, "simd": True}},
        "webGlBasics": {"value": {"rendererUnmasked": "RTX 3060", "vendorUnmasked": "NVIDIA"}},
        "canvas": {"value": "canvas-A"},
    },
    "additionalData": {
        "vmDetection": {"isVM": False},
        "network": {"query": "1.2.3.4", "country": "SG"},
    },
}


@pytest.fixture
def fp():
    """Factory for fingerprint payloads; overrides are applied by dotted path."""
    def make(**over):
        d = copy.deepcopy(BASE_FP)
        for path, val in over.items():
            keys = path.split("__")
            cur = d
            for k in keys[:-1]:
                cur = cur.setdefault(k, {})
            cur[keys[-1]] = val
        return d
    return make


def cls(category="injection_attack", confidence=90, severity=50, evidence=None):
    return {"category": category, "confidence": confidence, "severity": severity,
            "evidence": evidence or []}


@pytest.fixture
def advisor():
    import advisor as a
    return a


@pytest.fixture
def rules(advisor):
    return advisor.load_decision_matrix(), advisor.load_confirmed_signals()


def pytest_collection_modifyitems(items):
    for item in items:
        name = Path(str(item.fspath)).stem
        for layer in ("unit", "component", "adversarial", "integration"):
            if name == f"test_{layer}":
                item.add_marker(getattr(pytest.mark, layer))
