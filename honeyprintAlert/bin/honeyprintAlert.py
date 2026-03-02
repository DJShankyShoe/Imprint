#!/usr/bin/env python3
"""
Honeyprint Alert Action - Combined Version with JWE Support
Handles Splunk alert integration AND MongoDB fingerprint processing

FEATURES:
- Configurable field name (UID, userID, sess_jwe, etc.)
- Plain or Encrypted (JWE) format
- Automatic JWE token decryption to extract UID
- MongoDB fingerprint processing

WORKFLOW:
1. Receives alert from Splunk (via stdin)
2. Extracts configured field from results
3. If encrypted: Decrypts JWE token to get UID
4. Looks up UID in raw_logs collection
5. Parses raw_log string to extract fingerprint JSON
6. Processes and inserts into fingerprints collection
"""

import sys
import json
import gzip
import csv
import os
import hashlib
import logging
import re
import base64
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import quote_plus
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError

# Try to import JWE decryption (optional)
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    JWE_AVAILABLE = True
except ImportError:
    JWE_AVAILABLE = False

# ============================================================================
# CONFIGURATION
# ============================================================================

# Logging setup
LOG_FILE = os.path.join(os.environ.get('SPLUNK_HOME', '/opt/splunk'), 
                        'var', 'log', 'splunk', 'honeyprintAlert.log')

# Configure logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

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

# JWE decryption key path
JWE_PRIVATE_KEY_PATH = "/opt/keys/server_private.pem"

# ============================================================================
# TIER 1 & TIER 2 FIELDS
# ============================================================================

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
]

TIER2_FIELDS = [
    "components.canvas.value",
    "components.canvasData.value.data",
    "components.webGl.value.renderer",
    "components.webGl.value.vendor",
    "components.webGl.value.shadingLanguageVersion",
    "components.webGl.value.version",
    "components.webGl.value.unmaskedVendor",
    "components.webGl.value.unmaskedRenderer",
    "components.webGl2.value.renderer",
    "components.webGl2.value.vendor",
    "components.webGl2.value.shadingLanguageVersion",
    "components.webGl2.value.version",
    "components.webGl2.value.unmaskedVendor",
    "components.webGl2.value.unmaskedRenderer",
    "components.webGlExtensions.value.supportedExtensions",
    "components.webGlExtensions.value.contextAttributes",
    "components.webGlExtensions.value.shaderPrecisionFormats",
    "components.webGlExtensions.value.parameters",
    "components.webGl2Extensions.value.supportedExtensions",
    "components.webGl2Extensions.value.shaderPrecisionFormats",
    "components.webGl2Extensions.value.parameters",
    "components.webGl2Extensions.value.contextAttributes",
]

# ============================================================================
# JWE TOKEN DECRYPTION
# ============================================================================

def decrypt_jwe_token(token):
    """
    Decrypt JWE token to extract UID
    
    Args:
        token: JWE token string (e.g., "eyJ0eXAi...")
    
    Returns:
        UID string if successful, None otherwise
    """
    if not JWE_AVAILABLE:
        logger.error("JWE decryption not available - cryptography module not installed")
        return None
    
    try:
        # Load private key
        if not os.path.exists(JWE_PRIVATE_KEY_PATH):
            logger.error(f"JWE private key not found: {JWE_PRIVATE_KEY_PATH}")
            return None
        
        with open(JWE_PRIVATE_KEY_PATH, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        
        # Split JWE token (header.encrypted_key.iv.ciphertext.tag)
        parts = token.split('.')
        if len(parts) != 5:
            logger.error(f"Invalid JWE token format - expected 5 parts, got {len(parts)}")
            return None
        
        header_b64, ek_b64, iv_b64, ciphertext_b64, tag_b64 = parts
        
        # Decode base64
        ek = base64.urlsafe_b64decode(ek_b64 + '==')
        iv = base64.urlsafe_b64decode(iv_b64 + '==')
        ciphertext = base64.urlsafe_b64decode(ciphertext_b64 + '==')
        tag = base64.urlsafe_b64decode(tag_b64 + '==')
        
        # Decrypt AES key using RSA
        aes_key = private_key.decrypt(
            ek,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        
        # Decrypt payload using AES-GCM
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Parse JSON payload
        payload = json.loads(plaintext.decode('utf-8'))
        
        # Extract UID
        uid = payload.get('UID')
        
        if uid:
            logger.info(f"Successfully decrypted JWE token - UID: {uid}")
            return uid
        else:
            logger.error("No UID found in decrypted payload")
            return None
    
    except Exception as e:
        logger.error(f"Failed to decrypt JWE token: {e}")
        return None


# ============================================================================
# RAW LOG PARSING
# ============================================================================

def parse_raw_log(raw_log_string):
    """
    Parse raw log string to extract fingerprint JSON
    
    Format: [timestamp] UID {json}
    
    Args:
        raw_log_string: Raw log line from database
    
    Returns:
        dict with fingerprint data, or None if parsing fails
    """
    try:
        # Pattern: [timestamp] UID {json}
        pattern = r'^\[([\d:A-Za-z\s+-]+)\]\s+([a-f0-9-]+)\s+(\{.+\})$'
        match = re.match(pattern, raw_log_string.strip())
        
        if not match:
            logger.error(f"Could not parse raw log format")
            return None
        
        timestamp_str = match.group(1)
        uid = match.group(2)
        json_str = match.group(3)
        
        # Parse JSON
        fingerprint_data = json.loads(json_str)
        
        logger.info(f"Parsed fingerprint from raw log - UID: {uid}")
        
        return fingerprint_data
    
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON from raw log: {e}")
        return None
    except Exception as e:
        logger.error(f"Error parsing raw log: {e}", exc_info=True)
        return None


# ============================================================================
# FINGERPRINT PROCESSING FUNCTIONS
# ============================================================================

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


def extract_observation_data(data):
    """Extract observation data from fingerprint"""
    network = data.get('additionalData', {}).get('network', {})
    incognito = data.get('additionalData', {}).get('incognito', {})
    vm_detection = data.get('additionalData', {}).get('vmDetection', {})
    browser_info = data.get('components', {}).get('browserInfo', {}).get('value', {})
    timezone = data.get('additionalData', {}).get('timezone', {})
    user_agent = data.get('components', {}).get('userAgent', {}).get('value', '')

    return {
        'timestamp': data.get('timestamp', int(datetime.now().timestamp() * 1000)),
        'ip': network.get('query', ''),
        'country': network.get('country', ''),
        'attackType': None,  # Will be set by observation_override
        'proxy': network.get('proxy', False),
        'isPrivate': incognito.get('isPrivate', False),
        'browserName': browser_info.get('browser', ''),
        'vm': vm_detection.get('isVM', False),
        'userAgent': user_agent,
        'os': browser_info.get('os', ''),
        'timezone': timezone.get('timezone', '')
    }


def insert_fingerprint(client, fingerprint_data, observation_override=None):
    """
    Insert or update fingerprint in MongoDB
    
    Args:
        client: MongoDB client
        fingerprint_data: Parsed fingerprint JSON (from raw_log)
        observation_override: Dict with attackType and optional overrides
    
    Returns:
        dict with status and message
    """
    db = client[DB_NAME]
    collection = db[FINGERPRINTS_COLLECTION]

    # Compute hashes
    tier1_hash = compute_tier_hash(fingerprint_data, TIER1_FIELDS)
    full_hash = compute_tier_hash(fingerprint_data, TIER1_FIELDS + TIER2_FIELDS)

    # Extract observation
    observation = extract_observation_data(fingerprint_data)
    if observation_override:
        observation.update(observation_override)

    # Check if fingerprint exists
    existing = collection.find_one({'full_hash': full_hash})

    if existing:
        # Fingerprint exists - add observation
        result = collection.update_one(
            {'full_hash': full_hash},
            {'$push': {'observations': observation}}
        )
        
        logger.info(f"Updated existing fingerprint: {full_hash[:40]}...")
        
        return {
            'status': 'updated',
            'full_hash': full_hash,
            'tier1_hash': tier1_hash,
            'message': 'Added observation to existing fingerprint'
        }
    else:
        # New fingerprint - insert with actions field
        document = {
            'full_hash': full_hash,
            'tier1_hash': tier1_hash,
            'actions': [],  # Empty array for future actions
            'raw_fingerprint': fingerprint_data,
            'observations': [observation]
        }

        try:
            result = collection.insert_one(document)
            
            logger.info(f"Inserted new fingerprint: {full_hash[:40]}...")
            
            return {
                'status': 'inserted',
                'full_hash': full_hash,
                'tier1_hash': tier1_hash,
                'inserted_id': str(result.inserted_id),
                'message': 'Inserted new fingerprint with actions field'
            }
        except DuplicateKeyError:
            # Race condition - try to add observation
            collection.update_one(
                {'full_hash': full_hash},
                {'$push': {'observations': observation}}
            )
            
            logger.warning(f"Race condition handled for: {full_hash[:40]}...")
            
            return {
                'status': 'updated_after_race',
                'full_hash': full_hash,
                'tier1_hash': tier1_hash,
                'message': 'Added observation (race condition handled)'
            }


# ============================================================================
# SPLUNK INTEGRATION FUNCTIONS
# ============================================================================

def process_alert(config):
    """
    Process Splunk alert and extract field value with configurable field name
    
    Args:
        config: Alert configuration from Splunk
    
    Returns:
        dict with alert_name, field_value, field_name, and data_format
    """
    try:
        # Get alert name
        alert_name = config.get('search_name', 'Unknown Alert')
        
        # Get configuration parameters
        configuration = config.get('configuration', {})
        field_name = configuration.get('field_name', 'UID')
        data_format = configuration.get('data_format', 'plain')
        
        logger.info(f"Processing alert: {alert_name}, Field: {field_name}, Format: {data_format}")
        
        # Get results file
        results_file = config.get('results_file', '')
        
        if not results_file or not os.path.exists(results_file):
            logger.error(f"Results file not found: {results_file}")
            return None
        
        field_value = None
        
        # Read results (handle gzipped or plain CSV)
        if results_file.endswith('.gz'):
            with gzip.open(results_file, 'rt') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Case-insensitive field matching
                    for key in row.keys():
                        if key.lower() == field_name.lower():
                            field_value = row[key]
                            break
                    if field_value:
                        break
        else:
            with open(results_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    for key in row.keys():
                        if key.lower() == field_name.lower():
                            field_value = row[key]
                            break
                    if field_value:
                        break
        
        if not field_value:
            logger.warning(f"Field '{field_name}' not found in results")
            return None
        
        logger.info(f"Extracted field '{field_name}' from alert '{alert_name}'")
        
        return {
            'alert_name': alert_name,
            'field_name': field_name,
            'field_value': field_value,
            'data_format': data_format
        }
    
    except Exception as e:
        logger.error(f"Error processing alert: {e}")
        return None


def process_fingerprint_by_uid(client, uid, alert_name):
    """
    Lookup fingerprint by UID and process it
    
    Args:
        client: MongoDB client
        uid: UID to lookup in raw_logs
        alert_name: Splunk alert name
    
    Returns:
        dict with processing result
    """
    try:
        db = client[DB_NAME]
        raw_logs_collection = db[RAW_LOGS_COLLECTION]

        logger.info(f"Looking up UID in raw_logs: {uid}")

        # Find latest raw_log with this UID
        raw_log = raw_logs_collection.find_one(
            {'uid': uid},
            sort=[('timestamp', -1)]
        )

        if not raw_log:
            logger.error(f"No raw_log found with UID: {uid}")
            return {
                'status': 'error',
                'message': f'No raw_log found with UID: {uid}'
            }

        # Get raw_log string
        raw_log_string = raw_log.get('raw_log')
        
        if not raw_log_string:
            logger.error(f"No raw_log field in document for UID: {uid}")
            return {
                'status': 'error',
                'message': 'No raw_log field in document'
            }

        logger.info(f"Found raw_log for UID: {uid}")

        # PARSE raw log to extract fingerprint JSON
        fingerprint_data = parse_raw_log(raw_log_string)
        
        if not fingerprint_data:
            logger.error(f"Failed to parse fingerprint from raw_log")
            return {
                'status': 'error',
                'message': 'Failed to parse fingerprint from raw_log'
            }

        # Build observation override with alert name
        observation_override = {
            'attackType': alert_name
        }

        # Insert fingerprint
        result = insert_fingerprint(client, fingerprint_data, observation_override)
        
        logger.info(f"Fingerprint processing result: {result['status']}")
        
        return result

    except Exception as e:
        logger.error(f"Error processing fingerprint by UID: {e}", exc_info=True)
        return {
            'status': 'error',
            'message': str(e)
        }


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """
    Main entry point - called by Splunk when alert fires
    """
    try:
        # Read configuration from Splunk (via stdin) - Splunk sends XML
        raw_input = sys.stdin.read()
        
        # Parse XML input from Splunk
        root = ET.fromstring(raw_input)
        
        # Extract configuration from XML
        config = {
            'search_name': root.find('.//search_name').text if root.find('.//search_name') is not None else 'Unknown Alert',
            'results_file': root.find('.//results_file').text if root.find('.//results_file') is not None else '',
            'configuration': {}
        }
        
        # Extract custom parameters (field_name, data_format)
        for param in root.findall('.//param'):
            param_name = param.get('name', '').replace('action.honeyprintAlert.param.', '')
            if param_name in ['field_name', 'data_format']:
                config['configuration'][param_name] = param.text or ''
        
        logger.info("Honeyprint Alert Action Triggered")
        
        # Connect to MongoDB
        try:
            client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
            client.admin.command('ping')
            logger.info("Connected to MongoDB")
        except Exception as e:
            logger.error(f"Could not connect to MongoDB: {e}")
            sys.exit(1)
        
        try:
            # Process Splunk alert (extract configured field)
            alert_data = process_alert(config)
            
            if not alert_data:
                logger.warning("No valid alert data to process")
                sys.exit(1)
            
            alert_name = alert_data['alert_name']
            field_value = alert_data['field_value']
            data_format = alert_data['data_format']
            
            # Extract UID based on format
            if data_format == 'encrypted':
                logger.info("Processing encrypted JWE token")
                uid = decrypt_jwe_token(field_value)
                if not uid:
                    logger.error("Failed to decrypt JWE token")
                    sys.exit(1)
            else:
                logger.info("Processing plain UID")
                uid = field_value
            
            logger.info(f"Processing fingerprint: Alert='{alert_name}', UID='{uid}'")
            
            # Process fingerprint (lookup raw_log, parse it, insert into fingerprints)
            result = process_fingerprint_by_uid(client, uid, alert_name)
            
            if result['status'] == 'error':
                logger.error(f"Fingerprint processing failed: {result['message']}")
                sys.exit(1)
            
            logger.info(f"SUCCESS - {result['message']}")
            logger.info(f"Hash: {result.get('full_hash', 'N/A')[:16]}...")
            
            sys.exit(0)
        
        finally:
            client.close()
    
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
