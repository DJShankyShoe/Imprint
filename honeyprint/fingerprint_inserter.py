#!/usr/bin/env python3
"""
Fingerprint MongoDB Inserter
Processes raw fingerprint JSON and inserts into MongoDB with Tier 1/Tier 2 hashing
"""

import json
import hashlib
from datetime import datetime
from urllib.parse import quote_plus
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

# MongoDB connection settings
MONGO_USER = "honeyprint_user"
MONGO_PASSWORD = "adminSh@nkk_P@55w0rd"
MONGO_HOST = "localhost"
MONGO_PORT = 27017
MONGO_AUTH_DB = "honeyprint"

# URL-encode username and password
MONGO_USER_ENCODED = quote_plus(MONGO_USER)
MONGO_PASSWORD_ENCODED = quote_plus(MONGO_PASSWORD)

# Build connection URI
MONGO_URI = f"mongodb://{MONGO_USER_ENCODED}:{MONGO_PASSWORD_ENCODED}@{MONGO_HOST}:{MONGO_PORT}/{MONGO_AUTH_DB}?authSource={MONGO_AUTH_DB}"

DB_NAME = "honeyprint"
COLLECTION_NAME = "fingerprints"

# Tier 1 fields (40 fields - Device + Engine Identity)
# These are the field paths that SHOULD exist, but we handle missing ones gracefully
TIER1_FIELDS = [
    # Platform & OS
    "components.platform.value",
    "components.colorDepth.value",
    "components.browserInfo.value.os",
    "components.browserInfo.value.mobile",
    "components.touchSupport.value.maxTouchPoints",
    "components.touchSupport.value.touchEvent",
    "components.touchSupport.value.touchStart",
    "additionalData.vmDetection.isVM",
    "components.vendor.value",
    
    # Device Memory
    "components.deviceMemory.value",
    
    # WASM Support
    "components.wasmSupport.value.supported",
    "components.wasmSupport.value.simd",
    "components.wasmSupport.value.sharedArrayBuffer",
    
    # Audio & Fonts
    "components.audio.value",
    "components.audioContext.value.sampleRate",
    "components.audioContext.value.maxChannelCount",
    "components.audioContext.value.baseLatency",
    "components.fontPreferences.value.default",
    "components.fontPreferences.value.serif",
    "components.fontPreferences.value.sans",
    "components.fontPreferences.value.mono",
    
    # Sensor Support
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
    
    # Performance
    "components.performanceFeatures.value.entryTypes",
    
    # Heap Info
    "components.heapInfo.value.supported",
    "components.heapInfo.value.jsHeapSizeLimit",
    "components.heapInfo.value.limitMB",
    
    # Hardware
    "components.webGlBasics.value.rendererUnmasked",
    "components.webGl2Basics.value.rendererUnmasked",
    
    # Battery (check both locations)
    "additionalData.battery.supported",
    
    # Plugins
    "components.plugins.value",
]

# Tier 2 fields (20 fields - Exact Browser + Rendering Signature)
TIER2_FIELDS = [
    # Canvas Rendering
    "components.canvas.value",
    "components.canvasEmoji.value",
    
    # Math Precision
    "components.math.value.acos",
    "components.math.value.asin",
    "components.math.value.atan",
    "components.math.value.sin",
    "components.math.value.cos",
    "components.math.value.tan",
    "components.math.value.exp",
    "components.math.value.log1p",
    "components.math.value.powPI",
    
    # WebGL Extensions
    "components.webGlExtensions.value.extensions",
    "components.webGlExtensions.value.parameters",
    "components.webGlExtensions.value.contextAttributes",
    
    # WebGL2 Extensions
    "components.webGl2Extensions.value.supported",
    "components.webGl2Extensions.value.extensions",
    "components.webGl2Extensions.value.parameters",
    "components.webGl2Extensions.value.contextAttributes",
]


def get_nested_value(data, path):
    """
    Get value from nested dictionary using dot notation
    Returns None if path doesn't exist
    """
    keys = path.split('.')
    value = data
    
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return None
    
    return value


def serialize_value(value):
    """
    Convert value to string for hashing
    Handles lists, dicts, None, etc.
    """
    if value is None:
        return "null"
    elif isinstance(value, bool):
        return str(value).lower()
    elif isinstance(value, (int, float)):
        return str(value)
    elif isinstance(value, str):
        return value
    elif isinstance(value, list):
        return json.dumps(value, sort_keys=True)
    elif isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    else:
        return str(value)


def compute_tier_hash(data, field_list):
    """
    Compute SHA256 hash from specified fields
    Missing fields are treated as null
    """
    values = []
    
    for field in field_list:
        value = get_nested_value(data, field)
        serialized = serialize_value(value)
        values.append(f"{field}:{serialized}")
    
    # Concatenate all values and hash
    combined = "|".join(values)
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()


def validate_fingerprint_fields(data, verbose=False):
    """
    Check which Tier 1 and Tier 2 fields are present in the fingerprint
    Returns dict with statistics
    """
    tier1_present = 0
    tier1_missing = []
    
    for field in TIER1_FIELDS:
        value = get_nested_value(data, field)
        if value is not None:
            tier1_present += 1
        else:
            tier1_missing.append(field)
    
    tier2_present = 0
    tier2_missing = []
    
    for field in TIER2_FIELDS:
        value = get_nested_value(data, field)
        if value is not None:
            tier2_present += 1
        else:
            tier2_missing.append(field)
    
    result = {
        'tier1': {
            'total': len(TIER1_FIELDS),
            'present': tier1_present,
            'missing': tier1_missing,
            'coverage': (tier1_present / len(TIER1_FIELDS)) * 100
        },
        'tier2': {
            'total': len(TIER2_FIELDS),
            'present': tier2_present,
            'missing': tier2_missing,
            'coverage': (tier2_present / len(TIER2_FIELDS)) * 100
        }
    }
    
    if verbose:
        print("\n" + "="*70)
        print("FINGERPRINT FIELD VALIDATION")
        print("="*70)
        print(f"\n📊 Tier 1 Fields: {tier1_present}/{len(TIER1_FIELDS)} present ({result['tier1']['coverage']:.1f}%)")
        if tier1_missing:
            print(f"   Missing ({len(tier1_missing)}):")
            for field in tier1_missing[:5]:  # Show first 5
                print(f"     - {field}")
            if len(tier1_missing) > 5:
                print(f"     ... and {len(tier1_missing) - 5} more")
        
        print(f"\n📊 Tier 2 Fields: {tier2_present}/{len(TIER2_FIELDS)} present ({result['tier2']['coverage']:.1f}%)")
        if tier2_missing:
            print(f"   Missing ({len(tier2_missing)}):")
            for field in tier2_missing[:5]:
                print(f"     - {field}")
            if len(tier2_missing) > 5:
                print(f"     ... and {len(tier2_missing) - 5} more")
        
        print("="*70 + "\n")
    
    return result


def extract_observation_data(data):
    """
    Extract observation data from fingerprint
    """
    network = data.get('additionalData', {}).get('network', {})
    incognito = data.get('additionalData', {}).get('incognito', {})
    vm_detection = data.get('additionalData', {}).get('vmDetection', {})
    browser_info = data.get('components', {}).get('browserInfo', {}).get('value', {})
    timezone = data.get('additionalData', {}).get('timezone', {})
    user_agent = data.get('components', {}).get('userAgent', {}).get('value', '')
    
    observation = {
        'timestamp': data.get('timestamp', int(datetime.now().timestamp() * 1000)),
        'ip': network.get('query', ''),
        'country': network.get('country', ''),
        'attackType': None,  # Will be set by external logic
        'proxy': network.get('proxy', False),
        'isPrivate': incognito.get('isPrivate', False),
        'browserName': browser_info.get('browser', ''),
        'vm': vm_detection.get('isVM', False),
        'userAgent': user_agent,
        'os': browser_info.get('os', ''),
        'timezone': timezone.get('timezone', '')
    }
    
    return observation


def insert_fingerprint(client, fingerprint_data, observation_override=None):
    """
    Insert or update fingerprint in MongoDB
    
    Args:
        client: MongoDB client
        fingerprint_data: Raw fingerprint JSON
        observation_override: Optional dict to override observation fields
    
    Returns:
        dict with status and message
    """
    db = client[DB_NAME]
    collection = db[COLLECTION_NAME]
    
    # Compute hashes
    tier1_hash = compute_tier_hash(fingerprint_data, TIER1_FIELDS)
    tier2_hash = compute_tier_hash(fingerprint_data, TIER2_FIELDS)
    
    # Full hash = SHA256(Tier1 fields + Tier2 fields combined)
    all_fields = TIER1_FIELDS + TIER2_FIELDS
    full_hash = compute_tier_hash(fingerprint_data, all_fields)
    
    # Extract observation
    observation = extract_observation_data(fingerprint_data)
    
    # Apply overrides
    if observation_override:
        observation.update(observation_override)
    
    # Check if fingerprint exists
    existing = collection.find_one({'full_hash': full_hash})
    
    if existing:
        # Fingerprint exists - add observation
        result = collection.update_one(
            {'full_hash': full_hash},
            {
                '$push': {
                    'observations': observation
                }
            }
        )
        
        return {
            'status': 'updated',
            'full_hash': full_hash,
            'tier1_hash': tier1_hash,
            'matched_count': result.matched_count,
            'modified_count': result.modified_count,
            'message': f'Added observation to existing fingerprint'
        }
    else:
        # New fingerprint - insert with EXACT structure from your document
        document = {
            'full_hash': full_hash,
            'tier1_hash': tier1_hash,
            'raw_fingerprint': fingerprint_data,  # Store entire fingerprint as nested JSON
            'observations': [observation]
        }
        
        try:
            result = collection.insert_one(document)
            
            return {
                'status': 'inserted',
                'full_hash': full_hash,
                'tier1_hash': tier1_hash,
                'inserted_id': str(result.inserted_id),
                'message': f'Inserted new fingerprint'
            }
        except DuplicateKeyError:
            # Race condition - fingerprint was just inserted
            # Try to add observation instead
            result = collection.update_one(
                {'full_hash': full_hash},
                {
                    '$push': {
                        'observations': observation
                    }
                }
            )
            
            return {
                'status': 'updated_after_race',
                'full_hash': full_hash,
                'tier1_hash': tier1_hash,
                'message': f'Added observation (race condition handled)'
            }


def main():
    """
    Main function - fetches fingerprint from raw_logs by UID and processes it
    """
    import sys
    import argparse
    
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description='Process fingerprint from raw_logs by UID',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Process fingerprint by UID with attack type
  python3 fingerprint_inserter.py --uid xxxxxxxxxxxxxxxxxxxxxxxxxxxx --attack bruteforce
  
  # Short form
  python3 fingerprint_inserter.py -u xxxxxxxxxxxxxxxxxxxxxxxxxxxx -a scanning
  
  # Override IP and country
  python3 fingerprint_inserter.py -u xxxxxxxxxxxxxxxxxxxxxxxxxxxx -a injection --ip 1.2.3.4 --country US
        '''
    )
    
    parser.add_argument('-u', '--uid', required=True,
                       help='UID to look up in raw_logs collection')
    parser.add_argument('-a', '--attack', '--attackType', dest='attack_type', required=True,
                       help='Attack type (e.g., bruteforce, scanning, scraping)')
    parser.add_argument('-i', '--ip', help='Override IP address')
    parser.add_argument('-c', '--country', help='Override country code')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Connect to MongoDB
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        client.admin.command('ping')  # Test connection
        print("✅ Connected to MongoDB")
    except Exception as e:
        print(f"❌ Error: Could not connect to MongoDB - {e}")
        sys.exit(1)
    
    # Fetch latest raw_log by UID
    try:
        db = client[DB_NAME]
        raw_logs_collection = db['raw_logs']
        
        print(f"🔍 Looking up UID: {args.uid}")
        
        # Find the latest raw_log with this UID
        raw_log = raw_logs_collection.find_one(
            {'uid': args.uid},
            sort=[('timestamp', -1)]  # Get most recent
        )
        
        if not raw_log:
            print(f"❌ Error: No raw_log found with UID: {args.uid}")
            client.close()
            sys.exit(1)
        
        print(f"✅ Found raw_log (timestamp: {raw_log['timestamp']})")
        
        # Extract fingerprint_data
        if 'fingerprint_data' not in raw_log or not raw_log['fingerprint_data']:
            print(f"❌ Error: No fingerprint_data in raw_log")
            client.close()
            sys.exit(1)
        
        fingerprint_data = raw_log['fingerprint_data']
        
    except Exception as e:
        print(f"❌ Error: Failed to fetch raw_log - {e}")
        import traceback
        traceback.print_exc()
        client.close()
        sys.exit(1)
    
    # Validate fields (show what's present)
    if args.verbose:
        validation = validate_fingerprint_fields(fingerprint_data, verbose=True)
    
    # Build observation override
    observation_override = {
        'attackType': args.attack_type  # Always set attack type
    }
    if args.ip:
        observation_override['ip'] = args.ip
    if args.country:
        observation_override['country'] = args.country
    
    # Insert fingerprint
    try:
        result = insert_fingerprint(client, fingerprint_data, observation_override)
        
        print(f"\n{'='*60}")
        print(f"Status: {result['status'].upper()}")
        print(f"{'='*60}")
        print(f"UID:        {args.uid}")
        print(f"Full Hash:  {result['full_hash']}")
        print(f"Tier1 Hash: {result['tier1_hash']}")
        print(f"Attack:     {args.attack_type}")
        
        if result['status'] == 'inserted':
            print(f"Action:     New fingerprint created")
            print(f"MongoDB ID: {result['inserted_id']}")
        elif result['status'] == 'updated':
            print(f"Action:     Observation added to existing fingerprint")
            print(f"Matched:    {result['matched_count']} document(s)")
            print(f"Modified:   {result['modified_count']} document(s)")
        
        if args.ip or args.country:
            print(f"\nOverrides applied:")
            if args.ip:
                print(f"  • IP: {args.ip}")
            if args.country:
                print(f"  • Country: {args.country}")
        
        print(f"\nMessage:    {result['message']}")
        print(f"{'='*60}\n")
        
    except Exception as e:
        print(f"❌ Error: Failed to insert fingerprint - {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    finally:
        client.close()


if __name__ == "__main__":
    main()
