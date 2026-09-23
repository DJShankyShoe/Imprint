#!/usr/bin/python3
"""
Imprint Environment - Loads settings from .env

FEATURES:
- Reads /opt/imprint/.env (or IMPRINT_ENV_FILE)
- Environment variables override the file
- MongoDB connection settings

.env FORMAT:
- KEY=value per line, # for comments
- Values can be quoted, no inline comments
"""

import os
from urllib.parse import quote_plus

ENV_FILE = os.environ.get("IMPRINT_ENV_FILE", "/opt/imprint/.env")


# ============================================================================
# .ENV LOADING
# ============================================================================

def parse_env_file(path):
    """
    Parse a .env file

    Args:
        path: path to the .env file

    Returns:
        dict of settings
    """
    values = {}
    if not os.path.isfile(path):
        return values
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[len("export "):]
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip()
            # Strip matching surrounding quotes
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            values[key] = value
    return values


def load_env(path=ENV_FILE):
    """Load .env values into os.environ"""
    for key, value in parse_env_file(path).items():
        os.environ.setdefault(key, value)


def require_env(key):
    """Get a required setting"""
    value = os.environ.get(key)
    if not value:
        raise RuntimeError(f"{key} is not set (add it to {ENV_FILE})")
    return value


# Load .env on import
load_env()


# ============================================================================
# MONGODB SETTINGS
# ============================================================================

MONGO_HOST = os.environ.get("MONGO_HOST", "localhost")
MONGO_PORT = int(os.environ.get("MONGO_PORT", "27017"))
MONGO_AUTH_DB = os.environ.get("MONGO_AUTH_DB", "imprint")
DB_NAME = os.environ.get("MONGO_DB", "imprint")


def mongo_uri():
    """
    Build MongoDB connection URI

    Returns:
        MongoDB connection URI
    """
    user = quote_plus(require_env("MONGO_USER"))
    password = quote_plus(require_env("MONGO_PASSWORD"))
    return f"mongodb://{user}:{password}@{MONGO_HOST}:{MONGO_PORT}/{MONGO_AUTH_DB}?authSource={MONGO_AUTH_DB}"
