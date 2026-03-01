#!/usr/bin/python3

import json 
import sys
import re
import hashlib
from urllib.parse import quote_plus
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

# MongoDB connection settings
MONGO_USER = "honeyprint_user"
MONGO_PASSWORD = "adminSh@nkk_P@55w0rd"
MONGO_HOST = "localhost"
MONGO_PORT = 27017
MONGO_AUTH_DB = "honeyprint"

MONGO_USER_ENCODED = quote_plus(MONGO_USER)
MONGO_PASSWORD_ENCODED = quote_plus(MONGO_PASSWORD)
MONGO_URI = f"mongodb://{MONGO_USER_ENCODED}:{MONGO_PASSWORD_ENCODED}@{MONGO_HOST}:{MONGO_PORT}/{MONGO_AUTH_DB}?authSource={MONGO_AUTH_DB}"

DB_NAME = "honeyprint"
RAW_LOGS_COLLECTION = "raw_logs"
FINGERPRINTS_COLLECTION = "fingerprints"

fingerprint_log_file = "/var/log/scythe/fingerprint.txt"
signature_path = "/opt/signatures/"
rules_file = "/opt/honeyprint/rules/default.json"
scores_file = "/opt/honeyprint/rules/scores.json"

uniqueID = sys.argv[1]

with open(fingerprint_log_file, 'r') as log:
    fingerprints = log.read()

with open(rules_file, 'r') as f:
    rules = json.load(f) 

with open(scores_file, 'r') as f:
    scores = json.load(f) 


TIER1_FIELDS = [
        "components.platform.value",
        "components.colorDepth.value",
        "components.browserInfo.value.os",
        "components.browserInfo.value.mobile",
        "components.touchSupport.value.maxTouchPoints",
        "components.touchSupport.value.touchEvent",
        "components.touchSupport.value.touchStart",
        "additionalData.vmDetection.isVM",
        "components.vendor.value",
        "components.deviceMemory.value",
        "components.wasmSupport.value.supported",
        "components.wasmSupport.value.simd",
        "components.wasmSupport.value.sharedArrayBuffer",
        "components.audio.value",
        "components.audioContext.value.sampleRate",
        "components.audioContext.value.maxChannelCount",
        "components.audioContext.value.baseLatency",
        "components.fontPreferences.value.default",
        "components.fontPreferences.value.serif",
        "components.fontPreferences.value.sans",
        "components.fontPreferences.value.mono",
        "components.sensorSupport.value.deviceMotion",
        "components.sensorSupport.value.deviceOrientation",
        "components.sensorSupport.value.ambientLight",
        "components.sensorSupport.value.gyroscope",
        "components.sensorSupport.value.accelerometer",
        "components.sensorSupport.value.linearAcceleration",
        "components.sensorSupport.value.gravitySensor",
        "components.sensorSupport.value.magnetometer",
        "components.sensorSupport.value.absoluteOrientationSensor",
        "components.sensorSupport.value.relativeOrientationSensor",
        "components.performanceFeatures.value.entryTypes",
        "components.heapInfo.value.supported",
        "components.heapInfo.value.jsHeapSizeLimit",
        "components.heapInfo.value.limitMB",
        "components.webGlBasics.value.rendererUnmasked",
        "components.webGl2Basics.value.rendererUnmasked",
        "additionalData.battery.supported",
        "components.plugins.value",
        ]

TIER2_FIELDS = [
        "components.canvas.value",
        "components.canvasEmoji.value",
        "components.math.value.acos",
        "components.math.value.asin",
        "components.math.value.atan",
        "components.math.value.sin",
        "components.math.value.cos",
        "components.math.value.tan",
        "components.math.value.exp",
        "components.math.value.log1p",
        "components.math.value.powPI",
        "components.webGlExtensions.value.extensions",
        "components.webGlExtensions.value.parameters",
        "components.webGlExtensions.value.contextAttributes",
        "components.webGl2Extensions.value.supported",
        "components.webGl2Extensions.value.extensions",
        "components.webGl2Extensions.value.parameters",
        "components.webGl2Extensions.value.contextAttributes",
        ]

def get_nested_value(data, path):
    """Get value from nested dictionary using dot notation"""
    keys = path.split('.')
    value = data
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return None
    return value


def serialize_value(value):
    """Convert value to string for hashing"""
    if value is None:
        return "null"
    elif isinstance(value, bool):
        return str(value).lower()
    elif isinstance(value, (int, float)):
        return str(value)
    elif isinstance(value, str):
        return value
    elif isinstance(value, (list, dict)):
        return json.dumps(value, sort_keys=True)
    else:
        return str(value)


def compute_tier_hash(data, field_list):
    """Compute SHA256 hash from specified fields"""
    values = [f"{field}:{serialize_value(get_nested_value(data, field))}" for field in field_list]
    combined = "|".join(values)
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()

def find_raw_fingerprint(client, uid): 
    try:
        db = client[DB_NAME]
        logs_collection = db[RAW_LOGS_COLLECTION]

        log = logs_collection.find_one(
                {"uid": uid},
                sort=[('timestamp', -1)]
                )
    # Extract JSON
        json_data = re.search(f"\\[\\d+:\\w+:\\d+:\\d+:\\d+:\\d+\\s(\\W|\\D)\\d+]\\s{uniqueID}\\s(.*)", log["raw_log"]).group(2)
        json_data = json.loads(json_data)
    except Exception as e:
        print(f"Failed to find UID: {e}")
        return -1

    # Compute hashes
    tier1_hash = compute_tier_hash(json_data, TIER1_FIELDS)
    full_hash = compute_tier_hash(json_data, TIER1_FIELDS + TIER2_FIELDS)
    return (tier1_hash, full_hash)



def lookup_fingerprint(client, full_hash, tier1_hash):
    """
    Lookup fingerprint by hash

    Args:
        client: MongoDB client
        hash_type: type of hash ("full_hash" or "tier1_hash")
        hash: hash of fingerprint

    Returns:
        dict with the following fields:

        status  Integer status code
        -1  Error
        none   Not found aka new device, low confidence
        tier1   Tier_1 hash hit aka similar device, medium confidence
        full   Full hash hit aka same fingerprint, high confidence

        actions List of actions from db
        attack_types Type of attack
    """
    try:
        db = client[DB_NAME]
        fingerprints_collection = db[FINGERPRINTS_COLLECTION]

        fingerprint = fingerprints_collection.find_one(
                {"full_hash": full_hash},
                sort=[('timestamp', -1)]
                )
        match = -1
        actions = []
        attack_type = []

        if not fingerprint:
            fingerprint = fingerprints_collection.find_one(
                    {"tier1_hash": tier1_hash},
                    sort=[('timestamp', -1)]
                    )
            if not fingerprint:
                match = "none" 
            else:
                match = "tier1"
                actions = fingerprint["actions"]
                attack_type = [ i['attackType'] for i in fingerprint["observations"] ]
        else:
            match = "full"
            actions = fingerprint["actions"]
            attack_type = [ i['attackType'] for i in fingerprint["observations"] ]
                
        return {
                "match": match,
                "actions": actions,
                "attack_types": list(set(attack_type))
                }
        
    except Exception as e:
        print(f"Error occurred during hash lookup: {e}")
        return {
                "match": -1,
                }

def compute_risk(attack_types, match, attempts=0):
    """
    Compute total risk based on attack types, match type and behavior
    """
    risk = 0

    # Use highest attack risk if multiple attack types
    attack_scores = rules.get("attack_risk", {})
    for attack in attack_types:
        risk = max(risk, attack_scores.get(attack, attack_scores.get("unknown", 20)))

    # Add match risk
    match_scores = rules.get("match_risk", {})
    risk += match_scores.get(match, 0)

    # Behavior risk (optional for future use)
    behavior_cfg = rules.get("behavior_risk", {})
    per_attempt = behavior_cfg.get("per_attempt", 0)
    max_attempt = behavior_cfg.get("max_attempt_risk", 0)
    risk += min(attempts * per_attempt, max_attempt)

    return min(risk, 100)

def risk_to_actions(risk):
    """
    Map risk score to actions using threshold table
    """
    thresholds = scores.get("risk_thresholds", {})

    # Convert keys to sorted integers
    sorted_thresholds = sorted(
        [(int(k), v) for k, v in thresholds.items()],
        key=lambda x: x[0]
    )

    selected_actions = ["allow"]

    for threshold, actions in sorted_thresholds:
        if risk >= threshold:
            selected_actions = actions
        else:
            break

    return selected_actions

def determine_action():
    # Connect to MongoDB
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        #print("Connected to MongoDB")
    except Exception as e:
        print(f"Could not connect to MongoDB: {e}")
        sys.exit(1)
    

    # Compute hashes
    tier1_hash, full_hash = find_raw_fingerprint(client, uniqueID)
    
    # Lookup hash in db
    result = lookup_fingerprint(client, full_hash, tier1_hash)
    if result["match"] != -1:
        if result["actions"] != []:
            # print(f"Actions found: {result['actions']}")
            return result["actions"]
        else:
            risk_score = compute_risk(result["attack_types"], result["match"], 1)
            threshold_level =  risk_to_actions(risk_score)
            print(f"Attack types: {result['attack_types']}, Risk score: {risk_score}, Threshold: {threshold_level}")
            return scores["level_actions"][str(threshold_level)]
    else:
        sys.exit(1)

if __name__ == "__main__":
    print(determine_action())
