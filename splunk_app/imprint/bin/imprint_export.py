#!/usr/bin/env python3
"""
Imprint Observation Input - Pulls observations from the Imprint service

FEATURES:
- One event per observation, each sent once
- Checkpoint kept between runs
- No MongoDB credentials in Splunk (uses the alert action settings)

WORKFLOW:
1. Reads service_url / token from alert_actions.conf (local, then default)
2. Gets observations newer than the checkpoint (/api/v1/export/observations)
3. Prints one JSON event per observation (index=imprint_intel)
4. Saves the new checkpoint
"""

import configparser
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

# ============================================================================
# CONFIGURATION
# ============================================================================

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPLUNK_HOME = os.environ.get('SPLUNK_HOME', '/opt/splunk')

# Checkpoint (last exported observation)
CHECKPOINT_DIR = os.path.join(SPLUNK_HOME, 'var', 'lib', 'splunk', 'modinputs', 'imprint')
CHECKPOINT_FILE = os.path.join(CHECKPOINT_DIR, 'observations_checkpoint.json')

PAGE_SIZE = 1000
MAX_PAGES = 20

# Event fields (timestamp first for the event time)
FIELDS = ['timestamp', 'fingerprint_id', 'obs_index', 'full_hash', 'tier1_hash', 'ip', 'country', 'attackType',
          'proxy', 'isPrivate', 'vm', 'browserName', 'os', 'timezone', 'userAgent', 'actions_full', 'actions_tier1']


def log(message):
    """Log to splunkd.log (scripted input stderr)"""
    print(f"imprint_export: {message}", file=sys.stderr)


def read_settings():
    """
    Get service_url and token from the alert action settings

    Returns:
        (service_url, token)
    """
    conf = configparser.ConfigParser(interpolation=None)
    conf.read([os.path.join(APP_DIR, 'default', 'alert_actions.conf'),
               os.path.join(APP_DIR, 'local', 'alert_actions.conf')])
    section = conf['imprintAlert'] if conf.has_section('imprintAlert') else {}
    service_url = section.get('param.service_url', '').strip() or os.environ.get('IMPRINT_SERVICE_URL', '')
    token = section.get('param.token', '').strip() or os.environ.get('IMPRINT_ALERT_TOKEN', '')
    return service_url, token


# ============================================================================
# CHECKPOINT
# ============================================================================

def load_checkpoint():
    """Load the last exported observation (timestamp, fingerprint _id, index)"""
    try:
        with open(CHECKPOINT_FILE) as f:
            data = json.load(f)
        return int(data.get('since', 0)), str(data.get('after_id', '')), int(data.get('after_index', -1))
    except (OSError, ValueError):
        return 0, '', -1


def save_checkpoint(since, after_id, after_index):
    """Save checkpoint (write then rename)"""
    os.makedirs(CHECKPOINT_DIR, exist_ok=True)
    tmp = CHECKPOINT_FILE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump({'since': since, 'after_id': after_id, 'after_index': after_index}, f)
    os.replace(tmp, CHECKPOINT_FILE)


# ============================================================================
# EXPORT
# ============================================================================

def fetch_page(service_url, token, since, after_id, after_index):
    """
    Get one page of observations from the service

    Returns:
        list of observation dicts
    """
    query = urllib.parse.urlencode({'since': since, 'after_id': after_id, 'after_index': after_index, 'limit': PAGE_SIZE})
    req = urllib.request.Request(f"{service_url.rstrip('/')}/api/v1/export/observations?{query}",
                                 headers={'Authorization': f'Bearer {token}'})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode('utf-8')).get('observations', [])


def format_event(obs):
    """Build the JSON event for one observation"""
    event = {key: obs.get(key) for key in FIELDS}
    event['obs_index'] = obs.get('index')
    event['actions_full'] = ','.join(obs.get('actions_full') or [])
    event['actions_tier1'] = ','.join(obs.get('actions_tier1') or [])
    return json.dumps(event, separators=(',', ':'))


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    service_url, token = read_settings()
    if not service_url or not token:
        log("service_url / token not configured (alert_actions.conf) - skipping")
        return

    since, after_id, after_index = load_checkpoint()
    exported = 0
    try:
        for _ in range(MAX_PAGES):
            page = fetch_page(service_url, token, since, after_id, after_index)
            for obs in page:
                print(format_event(obs))
                since, after_id, after_index = int(obs.get('timestamp') or since), obs.get('fingerprint_id', ''), int(obs.get('index', -1))
            sys.stdout.flush()
            exported += len(page)
            if len(page) < PAGE_SIZE:
                break
    except (urllib.error.URLError, ValueError) as e:
        log(f"export failed: {e}")
    finally:
        if exported:
            save_checkpoint(since, after_id, after_index)
            log(f"exported {exported} observation(s), checkpoint {since}")


if __name__ == '__main__':
    main()
