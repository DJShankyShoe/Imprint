"""advisor.update_actions against an in-memory (mongomock) collection."""
import json
import mongomock
import pytest
from conftest import cls
import classify


def seed(col, n_full, tier1="T1", first=1):
    for i in range(first, first + n_full):
        col.insert_one({"full_hash": f"F{i}", "tier1_hash": tier1,
                        "observations": [{"timestamp": 1_700_000_000_000, "ip": f"10.0.0.{i}",
                                          "attackType": "x"}]})


@pytest.fixture
def col():
    return mongomock.MongoClient().db.fingerprints


def run(advisor, monkeypatch, col, output, alert="sqli", status="inserted", full="F1"):
    def fake(_record):
        if isinstance(output, Exception):
            raise output
        return output
    monkeypatch.setattr(advisor, "classify", fake)
    return advisor.update_actions(col, full, "T1", {}, alert, status)


def test_actions_stored_for_both_tiers(advisor, monkeypatch, col):
    seed(col, 1)
    acts = run(advisor, monkeypatch, col, cls("injection_attack", severity=92))
    stored = col.find_one({"full_hash": "F1"})["actions"]
    assert stored == acts and set(acts) == {"tier1", "full"}


def test_full_match_detected_on_updated_status(advisor, monkeypatch, col):
    seed(col, 1)
    run(advisor, monkeypatch, col, cls("injection_attack", severity=92), status="updated")
    rec = [json.loads(l) for l in open(classify.AUDIT_LOG)][-1]
    assert rec["event"] == "decision" and rec["full_hash"] == "F1"


def test_tier1_match_when_shared_hardware(advisor, monkeypatch, col):
    seed(col, 3)
    seen = {}
    monkeypatch.setattr(advisor, "classify", lambda r: seen.setdefault("r", r) and cls())
    advisor.update_actions(col, "F1", "T1", {}, "sqli", "inserted")
    assert seen["r"]["identity_match"]["match_tier"] == "tier1"
    assert seen["r"]["identity_match"]["distinct_full_hashes_under_this_tier1"] == 3


def test_match_tier_none_for_single_new_device(advisor, monkeypatch, col):
    seed(col, 1)
    seen = {}
    monkeypatch.setattr(advisor, "classify", lambda r: seen.setdefault("r", r) and cls())
    advisor.update_actions(col, "F1", "T1", {}, "sqli", "inserted")
    assert seen["r"]["identity_match"]["match_tier"] == "none"


def test_failsafe_captcha_when_classifier_down(advisor, monkeypatch, col):
    seed(col, 1)
    acts = run(advisor, monkeypatch, col, classify.ClassifierUnavailable("timeout"), alert="Unknown Alert")
    assert acts == {"tier1": ["CAPTCHA"], "full": ["CAPTCHA"]}


def test_confirmed_signal_used_when_classifier_down(advisor, monkeypatch, col):
    seed(col, 1)
    acts = run(advisor, monkeypatch, col, classify.ClassifierUnavailable("down"), alert="sqli")
    assert acts["full"] == ["HONEYPOT"]


def test_low_confidence_falls_to_unknown_in_audit(advisor, monkeypatch, col):
    seed(col, 1)
    run(advisor, monkeypatch, col, cls("reconnaissance", confidence=20, severity=90), alert="scan")
    rec = [json.loads(l) for l in open(classify.AUDIT_LOG)][-1]
    assert rec["adjusted"]["category"] == "unknown"
    assert any("confidence_floor" in g for g in rec["guardrails_fired"])


def test_audit_record_complete(advisor, monkeypatch, col):
    seed(col, 1)
    run(advisor, monkeypatch, col, cls("bot_scraping", severity=20), alert="scraper")
    rec = [json.loads(l) for l in open(classify.AUDIT_LOG)][-1]
    for k in ("full_hash", "alert_name", "classification", "adjusted", "guardrails_fired", "actions"):
        assert k in rec


def test_corroboration_window_2_to_3_hashes(advisor, monkeypatch, col):
    for n, expect_block in ((1, False), (2, True), (3, True), (4, False)):
        c = mongomock.MongoClient().db[f"c{n}"]
        seed(c, n)
        acts = run(advisor, monkeypatch, c, cls("injection_attack", severity=95), alert="sqli")
        assert ("BLOCK" in acts["tier1"]) == expect_block, n
        assert acts["full"] == ["BLOCK"]


def test_missing_document_raises(advisor, monkeypatch, col):
    monkeypatch.setattr(advisor, "classify", lambda r: cls())
    with pytest.raises(RuntimeError):
        advisor.update_actions(col, "NOPE", "T1", {}, "sqli", "inserted")
