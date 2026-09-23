#!/usr/bin/env python3
"""
Imprint Alert Action - Webhook Version
Sends Splunk alerts to the Imprint service

FEATURES:
- Configurable field name (UID, userID, sess_jwe, etc.)
- Plain or Encrypted (JWE) format
- JWE token decrypted by the service

WORKFLOW:
1. Receives alert from Splunk (via stdin)
2. Extracts configured field from results
3. Sends alert to the Imprint service (/api/v1/alert)
4. Service updates the fingerprint and its actions

SETTINGS:
- service_url / IMPRINT_SERVICE_URL
- token / IMPRINT_ALERT_TOKEN
"""

import csv
import gzip
import json
import logging
import os
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

# ============================================================================
# CONFIGURATION
# ============================================================================

# Logging setup
LOG_FILE = os.path.join(os.environ.get('SPLUNK_HOME', '/opt/splunk'),
                        'var', 'log', 'splunk', 'imprintAlert.log')

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

PARAM_PREFIX = 'action.imprintAlert.param.'
PARAMS = ('field_name', 'data_format', 'service_url', 'token')


# ============================================================================
# SPLUNK INTEGRATION FUNCTIONS
# ============================================================================

def read_config(raw_input):
    """
    Parse alert config from Splunk (XML)

    Returns:
        dict with search_name, results_file and configuration params
    """
    root = ET.fromstring(raw_input)
    search_name = root.find('.//search_name')
    results_file = root.find('.//results_file')
    config = {
        'search_name': search_name.text if search_name is not None else 'Unknown Alert',
        'results_file': results_file.text if results_file is not None else '',
        'configuration': {}
    }
    for param in root.findall('.//param'):
        name = param.get('name', '').replace(PARAM_PREFIX, '')
        if name in PARAMS:
            config['configuration'][name] = param.text or ''
    return config


def extract_field(results_file, field_name):
    """
    Get field value from the results file (case-insensitive)

    Returns:
        field value, or None
    """
    if not results_file or not os.path.exists(results_file):
        logger.error(f"Results file not found: {results_file}")
        return None

    opener = gzip.open if results_file.endswith('.gz') else open
    with opener(results_file, 'rt') as f:
        for row in csv.DictReader(f):
            for key, value in row.items():
                if key and key.lower() == field_name.lower() and value:
                    return value
    return None


def send_alert(service_url, token, payload):
    """
    Send alert to the Imprint service

    Returns:
        (HTTP status, response body)
    """
    req = urllib.request.Request(
        service_url.rstrip('/') + '/api/v1/alert',
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'},
        method='POST'
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read().decode('utf-8', errors='replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', errors='replace')


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """
    Main entry point - called by Splunk when alert fires
    """
    try:
        config = read_config(sys.stdin.read())
        params = config['configuration']
        alert_name = config['search_name']
        field_name = params.get('field_name') or 'UID'
        data_format = params.get('data_format') or 'plain'
        service_url = params.get('service_url') or os.environ.get('IMPRINT_SERVICE_URL', '')
        token = params.get('token') or os.environ.get('IMPRINT_ALERT_TOKEN', '')

        logger.info(f"Imprint Alert Action Triggered: {alert_name}, Field: {field_name}, Format: {data_format}")

        if not service_url or not token:
            logger.error("service_url / token not configured (alert_actions.conf params or environment)")
            sys.exit(1)

        field_value = extract_field(config['results_file'], field_name)
        if not field_value:
            logger.warning(f"Field '{field_name}' not found in results")
            sys.exit(1)

        status, body = send_alert(service_url, token, {
            'alert_name': alert_name,
            'field_value': field_value,
            'data_format': data_format,
        })
        if status != 200:
            logger.error(f"Imprint service returned HTTP {status}: {body[:300]}")
            sys.exit(1)

        logger.info(f"SUCCESS - {body[:300]}")
        sys.exit(0)

    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
