#!/usr/bin/python3
"""
Imprint Service - Fingerprint collection, actions and SIEM alerts

FEATURES:
- One-time collection slots (single use, short TTL)
- JWE payload decryption
- Server-side geolocation (ip-api.com)
- Actions lookup for page loads
- SIEM alert webhook with the mitigation advisor

ENDPOINTS:
- POST /api/v1/slots                     (site token)   Create collection slot
- POST /api/v1/collect/<slot>?s=<secret> (site token)   Store fingerprint
- GET  /api/v1/decision?uid=<uid>        (site token)   Get actions for a visitor
- GET  /api/v1/fingerprints/<uid>        (site token)   Check if fingerprint exists
- POST /api/v1/alert                     (alert token)  SIEM alert
- GET  /api/v1/export/observations       (alert token)  Export observations (SIEM dashboard)
- GET  /healthz                                         Health check
"""

import base64
import fcntl
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import threading
import time
import urllib.request
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from bson import ObjectId
from flask import Flask, jsonify, request
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

from imprint_env import DB_NAME, mongo_uri
from fingerprint_hash import compute_hashes

# ============================================================================
# CONFIGURATION
# ============================================================================

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("imprint.service")

RAW_LOGS_COLLECTION = "raw_logs"
FINGERPRINTS_COLLECTION = "fingerprints"
SLOTS_COLLECTION = "slots"

# RSA key directories
PAYLOAD_KEY_DIR = os.environ.get("IMPRINT_PAYLOAD_KEY_DIR", "/keys/payload")
SESSION_KEY_DIR = os.environ.get("IMPRINT_SESSION_KEY_DIR", "/keys/session")

# One-time slot lifetime (seconds)
SLOT_TTL_SECONDS = int(os.environ.get("IMPRINT_SLOT_TTL", "30"))

# Collect rate limit (per client IP, per minute)
COLLECT_RATE_LIMIT = int(os.environ.get("IMPRINT_COLLECT_RATE_LIMIT", "30"))
COLLECT_RATE_WINDOW = 60

# Max request body size
MAX_BODY_BYTES = 512 * 1024

# Export skips observations newer than this (ms)
EXPORT_LAG_MS = 5000

# Fallback actions
FAILSAFE_ACTIONS = ["CAPTCHA"]

UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
SLOT_RE = re.compile(r'^[0-9a-f]{32}$')
RAW_LOG_RE = re.compile(r'^\[([\d:A-Za-z\s+-]+)\]\s+([a-f0-9-]+)\s+(\{.+\})$', re.S)


# ============================================================================
# KEYS
# ============================================================================

def load_or_create_keypair(key_dir, private_name, public_name):
    """
    Load RSA key pair (generated on first start)

    Args:
        key_dir: directory holding the PEM files
        private_name: private key file name
        public_name: public key file name

    Returns:
        (private_key, public_pem_str)
    """
    os.makedirs(key_dir, exist_ok=True)
    private_path = os.path.join(key_dir, private_name)
    public_path = os.path.join(key_dir, public_name)

    # Lock so only one worker generates the keys
    with open(os.path.join(key_dir, ".lock"), "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if not os.path.exists(private_path):
            logger.info(f"Generating RSA key pair in {key_dir}")
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            with open(public_path, "wb") as f:
                f.write(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                      serialization.PublicFormat.SubjectPublicKeyInfo))
            os.chmod(public_path, 0o644)
            with open(private_path, "wb") as f:
                f.write(key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.TraditionalOpenSSL,
                                          serialization.NoEncryption()))
            os.chmod(private_path, 0o640)

    with open(private_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(public_path, "r") as f:
        public_pem = f.read().strip()
    return private_key, public_pem


def b64url_decode(data):
    """Base64 URL decode (handles missing padding)"""
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def rsa_oaep_decrypt(private_key, data):
    """Decrypt with RSA-OAEP (SHA-1, same as fingerprint.js)"""
    return private_key.decrypt(data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                                                  algorithm=hashes.SHA1(), label=None))


def decrypt_payload(private_key, body):
    """
    Decrypt JWE payload from fingerprint.js

    Args:
        private_key: payload private key
        body: parsed JSON request body

    Returns:
        plaintext string "uid json"
    """
    aes_key = rsa_oaep_decrypt(private_key, b64url_decode(str(body["ek"])))
    plaintext = AESGCM(aes_key).decrypt(b64url_decode(str(body["iv"])), b64url_decode(str(body["ct"])), None)
    return plaintext.decode("utf-8")


def decrypt_session_token(private_key, token):
    """
    Decrypt sess_jwe token to extract UID

    Args:
        private_key: session private key
        token: JWE token string (e.g., "eyJ0eXAi...")

    Returns:
        UID string if successful, None otherwise
    """
    parts = token.split(".")
    if len(parts) != 5:
        return None
    _, ek, iv, ciphertext, tag = parts
    aes_key = rsa_oaep_decrypt(private_key, b64url_decode(ek))
    plaintext = AESGCM(aes_key).decrypt(b64url_decode(iv), b64url_decode(ciphertext) + b64url_decode(tag), None)
    return json.loads(plaintext.decode("utf-8")).get("UID")


# ============================================================================
# GEOLOCATION
# ============================================================================

GEO_FALLBACK = {
    "status": "fail", "country": "unknown", "city": "unknown", "isp": "unknown", "org": "unknown",
    "as": "unknown", "proxy": False, "hosting": False, "mobile": False,
}


def get_geo_info(ip):
    """
    Get geolocation info for an IP (ip-api.com)

    Args:
        ip: visitor IP address

    Returns:
        dict with geo info (fallback values on failure)
    """
    fallback = dict(GEO_FALLBACK, query=ip or "unknown")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return fallback
    try:
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip}?fields=21233405", timeout=3) as resp:
            geo = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        logger.warning(f"Geo lookup failed for {ip}: {e}")
        return fallback
    if not isinstance(geo, dict):
        return fallback
    # Fill in missing fields on failed lookups
    return geo if geo.get("status") == "success" else dict(fallback, **geo)


# ============================================================================
# FINGERPRINT STORAGE
# ============================================================================

def parse_raw_log(raw_log_string):
    """
    Parse raw log string to extract fingerprint JSON

    Format: [timestamp] UID {json}

    Returns:
        dict with fingerprint data, or None if parsing fails
    """
    match = RAW_LOG_RE.match((raw_log_string or "").strip())
    if not match:
        return None
    try:
        return json.loads(match.group(3))
    except json.JSONDecodeError:
        return None


def latest_fingerprint_data(uid):
    """Get fingerprint JSON from the latest raw_log for a UID"""
    raw_log = db[RAW_LOGS_COLLECTION].find_one({"uid": uid}, sort=[("timestamp", -1)])
    return parse_raw_log(raw_log.get("raw_log")) if raw_log else None


def extract_observation_data(data):
    """Extract observation data from fingerprint"""
    network = data.get('additionalData', {}).get('network', {})
    incognito = data.get('additionalData', {}).get('incognito', {})
    vm_detection = data.get('additionalData', {}).get('vmDetection', {})
    browser_info = data.get('components', {}).get('browserInfo', {}).get('value', {})
    timezone_info = data.get('additionalData', {}).get('timezone', {})
    user_agent = data.get('components', {}).get('userAgent', {}).get('value', '')

    return {
        'timestamp': int(datetime.now().timestamp() * 1000),
        'ip': network.get('query', ''),
        'country': network.get('country', ''),
        'attackType': None,  # Set by observation_override
        'proxy': network.get('proxy', False),
        'isPrivate': incognito.get('isPrivate', False),
        'browserName': browser_info.get('browser', ''),
        'vm': vm_detection.get('isVM', False),
        'userAgent': user_agent,
        'os': browser_info.get('os', ''),
        'timezone': timezone_info.get('timezone', '')
    }


def insert_fingerprint(fingerprint_data, observation_override=None):
    """
    Insert or update fingerprint in MongoDB

    Args:
        fingerprint_data: Parsed fingerprint JSON (from raw_log)
        observation_override: Dict with attackType and optional overrides

    Returns:
        dict with status, full_hash and tier1_hash
    """
    collection = db[FINGERPRINTS_COLLECTION]
    tier1_hash, full_hash = compute_hashes(fingerprint_data)

    observation = extract_observation_data(fingerprint_data)
    if observation_override:
        observation.update(observation_override)

    now = int(datetime.now().timestamp() * 1000)
    push = {'$push': {'observations': observation}, '$set': {'updated_at': now}}

    if collection.find_one({'full_hash': full_hash}, {'_id': 1}):
        collection.update_one({'full_hash': full_hash}, push)
        return {'status': 'updated', 'full_hash': full_hash, 'tier1_hash': tier1_hash}

    try:
        collection.insert_one({
            'full_hash': full_hash,
            'tier1_hash': tier1_hash,
            'actions': [],
            'raw_fingerprint': fingerprint_data,
            'observations': [observation],
            'created_at': now,
            'updated_at': now
        })
        return {'status': 'inserted', 'full_hash': full_hash, 'tier1_hash': tier1_hash}
    except DuplicateKeyError:
        # Race condition - add observation instead
        collection.update_one({'full_hash': full_hash}, push)
        return {'status': 'updated_after_race', 'full_hash': full_hash, 'tier1_hash': tier1_hash}


def update_fingerprint_actions(insert_result, fingerprint_data, alert_name):
    """Update fingerprint actions with the mitigation advisor"""
    collection = db[FINGERPRINTS_COLLECTION]
    try:
        from advisor import update_actions
        return update_actions(collection, insert_result['full_hash'], insert_result['tier1_hash'],
                              fingerprint_data, alert_name, insert_result['status'])
    except Exception as e:
        logger.error(f"Mitigation advisor failed, storing fail-safe actions: {e}", exc_info=True)
        actions = {'tier1': list(FAILSAFE_ACTIONS), 'full': list(FAILSAFE_ACTIONS)}
        collection.update_one({'full_hash': insert_result['full_hash']},
                              {'$set': {'actions': actions, 'updated_at': int(datetime.now().timestamp() * 1000)}})
        return actions


def lookup_actions(fingerprint_data):
    """
    Lookup fingerprint actions by hash (full first, then tier1)

    Returns:
        (match, actions) where match is "full", "tier1" or "none"
    """
    tier1_hash, full_hash = compute_hashes(fingerprint_data)
    collection = db[FINGERPRINTS_COLLECTION]
    projection = {"actions": 1}

    fingerprint = collection.find_one({"full_hash": full_hash}, projection, sort=[("updated_at", -1)])
    match = "full"
    if not fingerprint:
        fingerprint = collection.find_one({"tier1_hash": tier1_hash}, projection, sort=[("updated_at", -1)])
        match = "tier1"
    if not fingerprint:
        return "none", []

    actions = fingerprint.get("actions")
    if isinstance(actions, dict) and isinstance(actions.get(match), list):
        return match, actions[match]
    return match, list(FAILSAFE_ACTIONS)


# ============================================================================
# REQUEST HELPERS
# ============================================================================

_rate_lock = threading.Lock()
_rate_hits = defaultdict(deque)


def rate_limited(key):
    """Check collect rate limit for a client"""
    now = time.monotonic()
    with _rate_lock:
        hits = _rate_hits[key]
        while hits and now - hits[0] > COLLECT_RATE_WINDOW:
            hits.popleft()
        if len(hits) >= COLLECT_RATE_LIMIT:
            return True
        hits.append(now)
        return False


def require_token(env_key):
    """Check Bearer token from the Authorization header"""
    expected = os.environ.get(env_key, "")
    header = request.headers.get("Authorization", "")
    supplied = header[7:] if header.startswith("Bearer ") else ""
    return bool(expected) and hmac.compare_digest(supplied.encode(), expected.encode())


def error(status, message):
    return jsonify({"ok": False, "error": message}), status


# ============================================================================
# APP
# ============================================================================

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES

client = MongoClient(mongo_uri(), serverSelectionTimeoutMS=5000)
db = client[DB_NAME]

payload_private_key, payload_public_pem = load_or_create_keypair(PAYLOAD_KEY_DIR, "payload_private.pem", "payload_public.pem")
session_private_key, _ = load_or_create_keypair(SESSION_KEY_DIR, "server_private.pem", "server_public.pem")

# Create indexes (TTL index removes expired slots)
try:
    db[SLOTS_COLLECTION].create_index("expires_at", expireAfterSeconds=0)
    db[RAW_LOGS_COLLECTION].create_index("uid")
    db[RAW_LOGS_COLLECTION].create_index("timestamp")
    db[FINGERPRINTS_COLLECTION].create_index("full_hash", unique=True)
    db[FINGERPRINTS_COLLECTION].create_index("tier1_hash")
    db[FINGERPRINTS_COLLECTION].create_index("updated_at")
    db[FINGERPRINTS_COLLECTION].create_index("observations.timestamp")
except Exception as e:
    logger.warning(f"Index creation skipped: {e}")

for token_key in ("IMPRINT_SITE_TOKEN", "IMPRINT_ALERT_TOKEN"):
    if not os.environ.get(token_key):
        logger.warning(f"{token_key} is not set - endpoints using it will reject every request")


@app.get("/healthz")
def healthz():
    try:
        client.admin.command("ping")
        return jsonify({"ok": True})
    except Exception:
        return error(503, "mongodb unavailable")


@app.post("/api/v1/slots")
def create_slot():
    """Create one-time collection slot"""
    if not require_token("IMPRINT_SITE_TOKEN"):
        return error(401, "unauthorized")
    slot, secret = secrets.token_hex(16), secrets.token_hex(16)
    db[SLOTS_COLLECTION].insert_one({
        "_id": slot,
        "secret_hash": hashlib.sha256(secret.encode()).hexdigest(),
        "expires_at": datetime.now(timezone.utc) + timedelta(seconds=SLOT_TTL_SECONDS),
    })
    return jsonify({"ok": True, "slot": slot, "secret": secret, "ttl": SLOT_TTL_SECONDS,
                    "public_key": payload_public_pem})


@app.post("/api/v1/collect/<slot>")
def collect(slot):
    """Store fingerprint submitted to a slot"""
    if not require_token("IMPRINT_SITE_TOKEN"):
        return error(401, "unauthorized")
    client_ip = request.headers.get("X-Client-IP", "")
    if rate_limited(client_ip or request.remote_addr):
        return error(429, "rate limited")

    # Consume slot (single use)
    secret = request.args.get("s", "")
    if not SLOT_RE.match(slot) or not secret:
        return error(404, "not found")
    consumed = db[SLOTS_COLLECTION].find_one_and_delete({
        "_id": slot,
        "secret_hash": hashlib.sha256(secret.encode()).hexdigest(),
        "expires_at": {"$gt": datetime.now(timezone.utc)},
    })
    if not consumed:
        return error(404, "not found")

    raw = request.get_data(cache=False, as_text=True)
    if not raw:
        return error(400, "empty body")

    # Decrypt JWE payload (or plaintext)
    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        body = None
    if isinstance(body, dict) and {"ek", "iv", "ct"} <= body.keys():
        try:
            raw = decrypt_payload(payload_private_key, body)
        except Exception:
            return error(403, "decryption failed")

    match = re.match(r'^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\s+(.*)$', raw.strip(), re.S | re.I)
    if not match:
        return error(400, "uid not found")
    uid = match.group(1).lower()
    try:
        payload = json.loads(match.group(2))
    except json.JSONDecodeError:
        return error(400, "invalid json")
    if not isinstance(payload, dict):
        return error(400, "invalid json")

    # Add geolocation info
    if not isinstance(payload.get("additionalData"), dict):
        payload["additionalData"] = {}
    payload["additionalData"]["network"] = get_geo_info(client_ip)

    now_ms = int(time.time() * 1000)
    stamp = datetime.now(timezone.utc).strftime("%d:%b:%Y:%H:%M:%S +0000")
    json_str = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    db[RAW_LOGS_COLLECTION].insert_one({
        "timestamp": now_ms,
        "uid": uid,
        "raw_log": f"[{stamp}] {uid} {json_str}",
        "inserted_at": now_ms,
    })
    logger.info(f"Fingerprint stored for UID {uid}")
    return jsonify({"ok": True, "uid": uid})


@app.get("/api/v1/decision")
def decision():
    """Get actions for a visitor"""
    if not require_token("IMPRINT_SITE_TOKEN"):
        return error(401, "unauthorized")
    uid = request.args.get("uid", "").lower()
    if not UUID_RE.match(uid):
        return error(400, "invalid uid")
    data = latest_fingerprint_data(uid)
    if data is None:
        return jsonify({"ok": True, "match": "unknown", "actions": []})
    match, actions = lookup_actions(data)
    return jsonify({"ok": True, "match": match, "actions": actions})


@app.get("/api/v1/fingerprints/<uid>")
def fingerprint_exists(uid):
    """Check if a fingerprint exists for a UID"""
    if not require_token("IMPRINT_SITE_TOKEN"):
        return error(401, "unauthorized")
    uid = uid.lower()
    if not UUID_RE.match(uid):
        return error(400, "invalid uid")
    exists = db[RAW_LOGS_COLLECTION].count_documents({"uid": uid}, limit=1) > 0
    return jsonify({"ok": True, "exists": exists})


@app.get("/api/v1/export/observations")
def export_observations():
    """
    Export observations newer than a checkpoint (SIEM dashboard input)

    Query:
        since: observation timestamp checkpoint (ms)
        after_id: fingerprint _id of the last exported observation at that timestamp
        after_index: its position in the observations list
        limit: page size (max 1000)

    Returns:
        list of observations with fingerprint hashes and actions
    """
    if not require_token("IMPRINT_ALERT_TOKEN"):
        return error(401, "unauthorized")
    try:
        since = int(request.args.get("since", "0"))
        after_index = int(request.args.get("after_index", "-1"))
        limit = max(1, min(int(request.args.get("limit", "1000")), 1000))
    except ValueError:
        return error(400, "invalid since / after_index / limit")
    after_id = request.args.get("after_id", "")

    # Skip the last few seconds (observations still being written)
    until = int(time.time() * 1000) - EXPORT_LAG_MS

    # Resume after the checkpoint (timestamp, fingerprint _id, index)
    resume = [{"observation.timestamp": {"$gt": since}}]
    if ObjectId.is_valid(after_id):
        oid = ObjectId(after_id)
        resume += [{"observation.timestamp": since, "_id": {"$gt": oid}},
                   {"observation.timestamp": since, "_id": oid, "index": {"$gt": after_index}}]

    pipeline = [
        {"$match": {"observations.timestamp": {"$gte": since}}},
        {"$project": {"full_hash": 1, "tier1_hash": 1, "actions": 1, "observations": 1}},
        {"$unwind": {"path": "$observations", "includeArrayIndex": "index"}},
        {"$addFields": {"observation": "$observations"}},
        {"$match": {"$or": resume, "observation.timestamp": {"$lte": until}}},
        {"$sort": {"observation.timestamp": 1, "_id": 1, "index": 1}},
        {"$limit": limit},
    ]
    observations = []
    for doc in db[FINGERPRINTS_COLLECTION].aggregate(pipeline):
        actions = doc.get("actions") if isinstance(doc.get("actions"), dict) else {}
        observations.append(dict(doc["observation"],
                                 fingerprint_id=str(doc["_id"]),
                                 index=doc["index"],
                                 full_hash=doc.get("full_hash"),
                                 tier1_hash=doc.get("tier1_hash"),
                                 actions_full=actions.get("full") or [],
                                 actions_tier1=actions.get("tier1") or []))
    return jsonify({"ok": True, "observations": observations})


@app.post("/api/v1/alert")
def alert():
    """
    SIEM alert webhook

    JSON body:
        alert_name: attack type (e.g., sqli)
        field_value: UID or JWE token
        data_format: plain or encrypted
    """
    if not require_token("IMPRINT_ALERT_TOKEN"):
        return error(401, "unauthorized")
    body = request.get_json(silent=True) or {}
    alert_name = str(body.get("alert_name") or "Unknown Alert")[:128]
    field_value = str(body.get("field_value") or "").strip()
    data_format = body.get("data_format", "plain")
    if not field_value:
        return error(400, "field_value required")

    if data_format == "encrypted":
        try:
            uid = decrypt_session_token(session_private_key, field_value)
        except Exception:
            uid = None
        if not uid:
            return error(400, "could not decrypt session token")
    else:
        uid = field_value
    uid = uid.lower()
    if not UUID_RE.match(uid):
        return error(400, "invalid uid")

    fingerprint_data = latest_fingerprint_data(uid)
    if fingerprint_data is None:
        return error(404, f"no fingerprint for uid {uid}")

    result = insert_fingerprint(fingerprint_data, {'attackType': alert_name})
    actions = update_fingerprint_actions(result, fingerprint_data, alert_name)
    logger.info(f"Alert '{alert_name}' for UID {uid}: {result['status']} {result['full_hash'][:16]}... -> {actions}")
    return jsonify({"ok": True, "uid": uid, "status": result["status"],
                    "full_hash": result["full_hash"], "actions": actions})
