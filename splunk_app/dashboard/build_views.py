#!/usr/bin/env python3
"""
Imprint Dashboard Views - Builds the Splunk dashboard views from the JSON files

FEATURES:
- Imprint Threat Intel.json -> splunk_app/imprint (shipped with the app)
- Imprint Honeypot.json     -> docker/splunk/views (POC only)

USAGE:
    python3 splunk_app/dashboard/build_views.py   (run after editing a dashboard JSON)
"""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

VIEWS = [
    ("Imprint Threat Intel.json", "splunk_app/imprint/default/data/ui/views/imprint_threat_intel.xml"),
    ("Imprint Honeypot.json", "docker/splunk/views/imprint_honeypot.xml"),
]


def build_view(dashboard):
    """Wrap Dashboard Studio JSON in a Splunk view (version 2)"""
    return ('<dashboard version="2" theme="dark">\n'
            f'    <label>{dashboard["title"]}</label>\n'
            f'    <description>{dashboard.get("description", "")}</description>\n'
            '    <definition><![CDATA[\n' + json.dumps(dashboard, indent=4, ensure_ascii=False) + '\n    ]]></definition>\n'
            '    <meta type="hiddenElements"><![CDATA[\n{\n    "hideEdit": false,\n    "hideOpenInSearch": false,\n    "hideExport": false\n}\n    ]]></meta>\n'
            '</dashboard>\n')


for source, target in VIEWS:
    with open(os.path.join(HERE, source), encoding="utf-8") as f:
        dashboard = json.load(f)
    path = os.path.join(ROOT, target)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(build_view(dashboard))
    print(f"{source} -> {target}")
