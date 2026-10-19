"""Real Flask service (scripts/imprint/service.py) against in-memory MongoDB."""
import json
import time
import mongomock
import pymongo
import pytest
from conftest import cls

SITE = {"Authorization": "Bearer site-token"}
ALERT = {"Authorization": "Bearer alert-token"}
UID_A = "11111111-1111-4111-8111-111111111111"
UID_A2 = "22222222-2222-4222-8222-222222222222"   # same attacker, new UID
UID_B = "33333333-3333-4333-8333-333333333333"   # bystander, same hardware class


@pytest.fixture(scope="module")
def svc():
    pymongo.MongoClient = mongomock.MongoClient   # service does `from pymongo import MongoClient`
    import service
    service.app.config["TESTING"] = True
    return service


@pytest.fixture
def env(svc, fp, advisor, monkeypatch):
    svc.db.drop_collection("fingerprints"); svc.db.drop_collection("raw_logs")
    svc.db[svc.FINGERPRINTS_COLLECTION].create_index("full_hash", unique=True)
    svc._rate_hits.clear()
    box = {"out": cls("injection_attack", severity=92)}
    monkeypatch.setattr(advisor, "classify", lambda r: box["out"])

    def visit(uid, data):
        svc.db[svc.RAW_LOGS_COLLECTION].insert_one(
            {"uid": uid, "timestamp": int(time.time() * 1000),
             "raw_log": f"[2026-01-01 00:00:00 +0000] {uid} {json.dumps(data)}"})
    return svc.app.test_client(), visit, box


def test_healthz(env):
    assert env[0].get("/healthz").get_json()["ok"] is True


def test_site_token_cannot_call_alert_endpoint(env):
    c, _, _ = env
    r = c.post("/api/v1/alert", json={"alert_name": "sqli", "field_value": UID_A}, headers=SITE)
    assert r.status_code == 401


def test_alert_token_cannot_read_decision(env):
    assert env[0].get(f"/api/v1/decision?uid={UID_A}", headers=ALERT).status_code == 401


def test_missing_token_rejected(env):
    assert env[0].get(f"/api/v1/decision?uid={UID_A}").status_code == 401


def test_invalid_uid_rejected(env):
    assert env[0].get("/api/v1/decision?uid=not-a-uid", headers=SITE).status_code == 400


def test_unknown_uid_has_no_actions(env):
    r = env[0].get(f"/api/v1/decision?uid={UID_A}", headers=SITE).get_json()
    assert r["match"] == "unknown" and r["actions"] == []


def test_alert_for_unknown_uid_404(env):
    r = env[0].post("/api/v1/alert", json={"alert_name": "sqli", "field_value": UID_A}, headers=ALERT)
    assert r.status_code == 404


def test_full_flow_alert_to_decision(env, fp):
    c, visit, _ = env
    visit(UID_A, fp())
    r = c.post("/api/v1/alert", json={"alert_name": "sqli", "field_value": UID_A}, headers=ALERT).get_json()
    assert r["ok"] and r["actions"]["full"] == ["BLOCK"]
    d = c.get(f"/api/v1/decision?uid={UID_A}", headers=SITE).get_json()
    assert d["match"] == "full" and d["actions"] == ["BLOCK"]


def test_attacker_returns_with_new_uid_same_device(env, fp):
    c, visit, _ = env
    visit(UID_A, fp())
    c.post("/api/v1/alert", json={"alert_name": "sqli", "field_value": UID_A}, headers=ALERT)
    visit(UID_A2, fp(additionalData__network={"query": "8.8.8.8", "country": "US"}))  # new IP, no new alert
    d = c.get(f"/api/v1/decision?uid={UID_A2}", headers=SITE).get_json()
    assert d["match"] == "full" and d["actions"] == ["BLOCK"]


def test_bystander_on_same_hardware_class_not_blocked(env, fp):
    c, visit, _ = env
    visit(UID_A, fp())
    c.post("/api/v1/alert", json={"alert_name": "sqli", "field_value": UID_A}, headers=ALERT)
    visit(UID_B, fp(components__canvas={"value": "canvas-B"}))   # same tier-1, different full hash
    d = c.get(f"/api/v1/decision?uid={UID_B}", headers=SITE).get_json()
    assert d["match"] == "tier1"
    assert not ({"HONEYPOT", "BLOCK"} & set(d["actions"]))


def test_unrelated_device_unaffected(env, fp):
    c, visit, _ = env
    visit(UID_A, fp())
    c.post("/api/v1/alert", json={"alert_name": "sqli", "field_value": UID_A}, headers=ALERT)
    visit(UID_B, fp(components__platform={"value": "MacIntel"}))
    d = c.get(f"/api/v1/decision?uid={UID_B}", headers=SITE).get_json()
    assert d["match"] == "none" and d["actions"] == []


def test_classifier_outage_stores_failsafe(env, fp, advisor, monkeypatch):
    c, visit, _ = env
    import classify
    monkeypatch.setattr(advisor, "classify",
                        lambda r: (_ for _ in ()).throw(classify.ClassifierUnavailable("down")))
    visit(UID_A, fp())
    r = c.post("/api/v1/alert", json={"alert_name": "Unknown Alert", "field_value": UID_A}, headers=ALERT).get_json()
    assert r["actions"] == {"tier1": ["CAPTCHA"], "full": ["CAPTCHA"]}
