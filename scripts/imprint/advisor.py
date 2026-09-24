#!/usr/bin/python3
"""
Imprint Mitigation Advisor - Classification to actions

FEATURES:
- Feature record built from the stored fingerprint
- Guardrails applied after the model answers
- Actions from the static decision matrix
- Actions stored for tier1 and full matches

WORKFLOW:
1. Called by the service when a SIEM alert comes in
2. Builds feature record and classifies it
3. Applies confidence floor and confirmed signals
4. Maps result through the decision matrix (tier1 capped)
5. Stores actions in the fingerprint document
"""

import json
import os
from datetime import datetime, timezone

from classify import CATEGORIES, ClassifierUnavailable, audit_log, classify
from fingerprint_hash import get_nested_value

# ============================================================================
# CONFIGURATION
# ============================================================================

RULES_DIR = os.environ.get("IMPRINT_RULES_DIR", "/opt/imprint/rules")
DECISION_MATRIX_FILE = os.path.join(RULES_DIR, "decision_matrix.json")
CONFIRMED_SIGNALS_FILE = os.path.join(RULES_DIR, "confirmed_signals.json")

VALID_ACTIONS = {"allow", "CAPTCHA", "OTP", "RATE_LIMIT", "HONEYPOT", "BLOCK"}
BUCKETS = ["low", "medium", "high", "critical"]

# Severity buckets: low < 30, medium 30-59, high 60-84, critical >= 85
SEVERITY_BUCKET_MINIMUMS = {"critical": 85, "high": 60, "medium": 30, "low": 0}

# Below this confidence the category becomes unknown
CONFIDENCE_FLOOR = 50

# Fallback actions when the classifier is down
FAILSAFE_ACTIONS = ["CAPTCHA"]

# Actions a tier1 match can't reach on its own
TIER1_FORBIDDEN_ACTIONS = {"HONEYPOT", "BLOCK"}

# Tier1 can reach them with a confirmed signal and 2-3 attacking fingerprints
# under the same tier1 hash (same actor rotating fingerprints)
TIER1_CORROBORATION_MIN_DISTINCT = 2
TIER1_CORROBORATION_MAX_DISTINCT = 3


# ============================================================================
# RULE FILES
# ============================================================================

def load_decision_matrix(path=DECISION_MATRIX_FILE):
    """
    Load and validate the decision matrix

    Args:
        path: path to decision_matrix.json

    Returns:
        decision matrix dict
    """
    with open(path, "r") as f:
        matrix = json.load(f)
    for category in CATEGORIES:
        row = matrix.get(category)
        if not isinstance(row, dict):
            raise ValueError(f"decision matrix missing category: {category}")
        for bucket in BUCKETS:
            actions = row.get(bucket)
            if not isinstance(actions, list) or not actions:
                raise ValueError(f"decision matrix missing {category}.{bucket}")
            bad = [a for a in actions if a not in VALID_ACTIONS]
            if bad:
                raise ValueError(f"decision matrix {category}.{bucket} has invalid actions: {bad}")
    return matrix


def load_confirmed_signals(path=CONFIRMED_SIGNALS_FILE):
    """
    Load confirmed signals (alert name, category, severity floor)

    Args:
        path: path to confirmed_signals.json

    Returns:
        dict keyed by alert name (lowercase)
    """
    try:
        with open(path, "r") as f:
            raw = json.load(f)
    except FileNotFoundError:
        return {}
    signals = {}
    for name, cfg in raw.items():
        if not isinstance(cfg, dict) or cfg.get("category") not in CATEGORIES:
            raise ValueError(f"confirmed signal {name!r} has invalid category")
        signals[name.strip().lower()] = {
            "category": cfg["category"],
            "severity_floor": max(0, min(100, int(cfg.get("severity_floor", 0)))),
        }
    return signals


def match_confirmed_signal(alert_name, signals):
    """Match alert name against confirmed signals"""
    if not isinstance(alert_name, str):
        return None
    return signals.get(alert_name.strip().lower())


# ============================================================================
# FEATURE RECORD
# ============================================================================

def observation_activity(observations):
    """
    How long this fingerprint has been attacking

    Observation times are when alerts fired, not the raw attack rate (alert
    suppression throttles them), so only the span is reported.

    Args:
        observations: observation list from the fingerprint doc

    Returns:
        dict with the first and last observation in UTC
    """
    times = sorted(o["timestamp"] for o in observations if o.get("timestamp"))
    if not times:
        return {"first_utc": None, "last_utc": None}
    iso = lambda t: datetime.fromtimestamp(t / 1000, timezone.utc).isoformat(timespec="seconds")
    return {"first_utc": iso(times[0]), "last_utc": iso(times[-1])}


def build_feature_record(fingerprint_doc, fingerprint_data, distinct_full_hashes, match_tier):
    """
    Build classifier input from the stored fingerprint and current payload

    Args:
        fingerprint_doc: fingerprint document
        fingerprint_data: parsed fingerprint JSON from raw_log
        distinct_full_hashes: distinct full_hash count under this tier1_hash
        match_tier: "full", "tier1" or "none"

    Returns:
        feature record dict
    """
    observations = fingerprint_doc.get("observations") or []
    current = observations[-1] if observations else {}
    webgl = get_nested_value(fingerprint_data, "components.webGlBasics.value", {}) or {}

    labels = []
    for o in observations:
        label = o.get("attackType")
        if label and label not in labels:
            labels.append(label)

    return {
        "meta": {
            "full_hash": fingerprint_doc.get("full_hash"),
            "tier1_hash": fingerprint_doc.get("tier1_hash"),
            "total_observations": len(observations),
        },
        "current_event": {
            "reported_attack_label": current.get("attackType"),
            "ip": current.get("ip"),
            "country": current.get("country"),
            "proxy": bool(current.get("proxy")),
            "is_private_browsing": bool(current.get("isPrivate")),
            "user_agent": current.get("userAgent"),
            "browser": current.get("browserName"),
            "os": current.get("os"),
            "timezone": current.get("timezone"),
        },
        "device_signals": {
            "platform": get_nested_value(fingerprint_data, "components.platform.value"),
            "vm_detected": bool(get_nested_value(fingerprint_data, "additionalData.vmDetection.isVM", False)),
            "wasm_supported": bool(get_nested_value(fingerprint_data, "components.wasmSupport.value.supported", False)),
            "webgl_renderer": webgl.get("rendererUnmasked") or webgl.get("renderer"),
            "webgl_vendor": webgl.get("vendorUnmasked") or webgl.get("vendor"),
            "canvas_hash_present": bool(get_nested_value(fingerprint_data, "components.canvas.value")),
            "font_hash_present": bool(get_nested_value(fingerprint_data, "components.fonts.value")),
        },
        "identity_match": {
            "match_tier": match_tier,
            "distinct_full_hashes_under_this_tier1": distinct_full_hashes,
            "full_hash_ever_repeated": len(observations) > 1,
        },
        "history": {
            "attack_labels_seen": labels,
            "distinct_ip_count": len({o.get("ip") for o in observations if o.get("ip")}),
            "distinct_countries": sorted({o.get("country") for o in observations if o.get("country")}),
            "activity": observation_activity(observations),
        },
    }


# ============================================================================
# GUARDRAILS & DECISION MATRIX
# ============================================================================

def severity_bucket(severity):
    """Map severity score (0-100) to bucket name"""
    for bucket in ("critical", "high", "medium", "low"):
        if severity >= SEVERITY_BUCKET_MINIMUMS[bucket]:
            return bucket
    return "low"


def apply_guardrails(classification, confirmed_signal):
    """
    Apply confidence floor and confirmed-signal override

    Args:
        classification: validated output of classify()
        confirmed_signal: matched confirmed signal, or None

    Returns:
        (adjusted classification, list of guardrails that fired)
    """
    adjusted = dict(classification)
    fired = []

    # Low confidence - fall back to unknown
    if adjusted["confidence"] < CONFIDENCE_FLOOR and adjusted["category"] != "unknown":
        fired.append(f"confidence_floor: {adjusted['category']} ({adjusted['confidence']}) -> unknown")
        adjusted["category"] = "unknown"

    # Confirmed signal - force category and severity floor
    if confirmed_signal:
        if adjusted["category"] != confirmed_signal["category"]:
            fired.append(f"confirmed_signal_category: {adjusted['category']} -> {confirmed_signal['category']}")
            adjusted["category"] = confirmed_signal["category"]
        if adjusted["severity"] < confirmed_signal["severity_floor"]:
            fired.append(f"confirmed_signal_floor: {adjusted['severity']} -> {confirmed_signal['severity_floor']}")
            adjusted["severity"] = confirmed_signal["severity_floor"]

    return adjusted, fired


def apply_matrix(classification, tier, matrix, tier1_corroborated=False):
    """
    Map a classification to an action list

    Args:
        classification: adjusted classification (after guardrails)
        tier: "tier1" or "full"
        matrix: loaded decision matrix
        tier1_corroborated: allow tier1 to reach HONEYPOT/BLOCK

    Returns:
        list of actions
    """
    row = matrix[classification["category"]]
    bucket = severity_bucket(classification["severity"])
    actions = row[bucket]

    # Tier1 ceiling - step down until there's no HONEYPOT/BLOCK
    if tier == "tier1" and not tier1_corroborated:
        idx = BUCKETS.index(bucket)
        while idx >= 0 and TIER1_FORBIDDEN_ACTIONS.intersection(row[BUCKETS[idx]]):
            idx -= 1
        actions = row[BUCKETS[idx]] if idx >= 0 else FAILSAFE_ACTIONS

    return list(actions)


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def update_actions(collection, full_hash, tier1_hash, fingerprint_data, alert_name, insert_status):
    """
    Classify fingerprint and store actions for both match tiers

    Args:
        collection: fingerprints collection
        full_hash: full hash of the fingerprint just inserted/updated
        tier1_hash: tier1 hash of the fingerprint
        fingerprint_data: parsed fingerprint JSON from raw_log
        alert_name: Splunk alert name (attack type)
        insert_status: status returned by insert_fingerprint()

    Returns:
        dict {"tier1": [...], "full": [...]}
    """
    matrix = load_decision_matrix()
    confirmed_signal = match_confirmed_signal(alert_name, load_confirmed_signals())

    doc = collection.find_one({"full_hash": full_hash}, {"raw_fingerprint": 0})
    if not doc:
        raise RuntimeError(f"fingerprint {full_hash[:16]}... not found after insert")

    # Distinct full hashes sharing this tier1 hash
    distinct_full_hashes = len(collection.distinct("full_hash", {"tier1_hash": tier1_hash}))
    if insert_status.startswith("updated"):
        match_tier = "full"
    elif distinct_full_hashes > 1:
        match_tier = "tier1"
    else:
        match_tier = "none"

    feature_record = build_feature_record(doc, fingerprint_data, distinct_full_hashes, match_tier)
    tier1_corroborated = (bool(confirmed_signal) and
                          TIER1_CORROBORATION_MIN_DISTINCT <= distinct_full_hashes <= TIER1_CORROBORATION_MAX_DISTINCT)

    classifier_error = None
    try:
        classification = classify(feature_record)
    except ClassifierUnavailable as e:
        classifier_error = str(e)
        classification = None

    if classification is not None:
        adjusted, fired = apply_guardrails(classification, confirmed_signal)
        actions = {
            "tier1": apply_matrix(adjusted, "tier1", matrix, tier1_corroborated),
            "full": apply_matrix(adjusted, "full", matrix),
        }
    elif confirmed_signal:
        # Classifier down - use confirmed signal
        adjusted = {"category": confirmed_signal["category"], "confidence": 0,
                    "severity": confirmed_signal["severity_floor"], "evidence": []}
        fired = ["classifier_unavailable: using confirmed signal only"]
        actions = {
            "tier1": apply_matrix(adjusted, "tier1", matrix, tier1_corroborated),
            "full": apply_matrix(adjusted, "full", matrix),
        }
    else:
        # Classifier down - fail-safe
        adjusted = None
        fired = ["classifier_unavailable: fail-safe"]
        actions = {"tier1": list(FAILSAFE_ACTIONS), "full": list(FAILSAFE_ACTIONS)}

    collection.update_one(
        {"full_hash": full_hash},
        {"$set": {"actions": actions,
                  "updated_at": int(datetime.now().timestamp() * 1000)}},
    )

    audit_log({
        "event": "decision",
        "full_hash": full_hash,
        "alert_name": alert_name,
        "confirmed_signal": confirmed_signal,
        "tier1_corroborated": tier1_corroborated,
        "classification": classification,
        "classifier_error": classifier_error,
        "adjusted": adjusted,
        "guardrails_fired": fired,
        "actions": actions,
    })
    return actions
