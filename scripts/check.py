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

uniqueID = sys.argv[1]

with open(fingerprint_log_file, 'r') as log:
    fingerprints = log.read()

with open(rules_file, 'r') as f:
    rules = json.load(f) 


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

def lookup_fingerprint_actions(client, full_hash, tier1_hash):
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
        attack_type Type of attack
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
        attack_type = ""

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
                attack_type = fingerprint["observations"][0]["attackType"]
        else:
            match = "full"
            actions = fingerprint["actions"]
            attack_type = fingerprint["observations"][0]["attackType"]
                
        return {
                "match": match,
                "actions": actions,
                "attack_type": attack_type
                }
        
    except Exception as e:
        print(f"Error occurred during hash lookup: {e}")
        return {
                "match": -1,
                }

def determine_action(attack_type, match):
    return rules[attack_type][match]

def main():
    # Connect to MongoDB
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        print("Connected to MongoDB")
    except Exception as e:
        print(f"Could not connect to MongoDB: {e}")
        sys.exit(1)
    
    # Extract JSON
    try:
        json_data = re.search(f"\\[\\d+:\\w+:\\d+:\\d+:\\d+:\\d+\\s(\\W|\\D)\\d+]\\s{uniqueID}\\s(.*)", fingerprints).group(2)
        json_data = json.loads(json_data)
    except Exception as e:
        print(f"Failed to find UID: {e}")
        sys.exit(1)

    # Compute hashes
    tier1_hash = compute_tier_hash(json_data, TIER1_FIELDS)
    full_hash = compute_tier_hash(json_data, TIER1_FIELDS + TIER2_FIELDS)
    
    # Lookup hash in db
    result = lookup_fingerprint_actions(client, full_hash, tier1_hash)
    if result["match"] != -1:
        if result["actions"] != []:
            print(f"Actions found: {result['actions']}")
            return result["actions"]
        else:
            return determine_action(result["attack_type"], result["match"])
    else:
        sys.exit(1)

if __name__ == "__main__":
    print(main())
