#!/usr/bin/python3
"""
Imprint Fingerprint Hashing - Tier 1 & Tier 2 hashes

FEATURES:
- tier1_hash: hardware class (TIER1_FIELDS)
- full_hash: full fingerprint (TIER1_FIELDS + TIER2_FIELDS)

NOTE: Field paths must match the payload from fingerprint.js.
Changing the fields changes every hash.
"""

import hashlib
import json

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
    "components.webGlBasics.value.version",
    "components.webGlBasics.value.vendor",
    "components.webGlBasics.value.vendorUnmasked",
    "components.webGlBasics.value.renderer",
    "components.webGlBasics.value.rendererUnmasked",
    "components.webGlBasics.value.shadingLanguageVersion",
    "components.webGl2Basics.value.version",
    "components.webGl2Basics.value.vendor",
    "components.webGl2Basics.value.vendorUnmasked",
    "components.webGl2Basics.value.renderer",
    "components.webGl2Basics.value.rendererUnmasked",
    "components.webGl2Basics.value.shadingLanguageVersion",
    "components.webGlExtensions.value.extensions",
    "components.webGlExtensions.value.contextAttributes",
    "components.webGlExtensions.value.shaderPrecisionFormats",
    "components.webGlExtensions.value.parameters",
    "components.webGl2Extensions.value.extensions",
    "components.webGl2Extensions.value.shaderPrecisionFormats",
    "components.webGl2Extensions.value.parameters",
    "components.webGl2Extensions.value.contextAttributes",
]

# ============================================================================
# HASHING FUNCTIONS
# ============================================================================

def get_nested_value(data, path, default=None):
    """Get value from nested dictionary using dot notation"""
    keys = path.split('.')
    value = data
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return default
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


def compute_hashes(data):
    """
    Compute both fingerprint hashes

    Args:
        data: Parsed fingerprint JSON

    Returns:
        (tier1_hash, full_hash)
    """
    tier1_hash = compute_tier_hash(data, TIER1_FIELDS)
    full_hash = compute_tier_hash(data, TIER1_FIELDS + TIER2_FIELDS)
    return (tier1_hash, full_hash)
