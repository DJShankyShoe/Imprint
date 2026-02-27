#!/usr/bin/env python3
"""
MongoDB Setup Script - Modified
Creates indexes for the fingerprints collection including 'actions' field
"""

from urllib.parse import quote_plus
from pymongo import MongoClient, ASCENDING, DESCENDING

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
COLLECTION_NAME = "fingerprints"


def setup_indexes(client):
    """Create all necessary indexes including actions field"""
    db = client[DB_NAME]
    collection = db[COLLECTION_NAME]

    print("Creating indexes...")

    # Drop existing indexes (except _id)
    try:
        collection.drop_indexes()
        print("✅ Dropped existing indexes")
    except:
        pass

    # Primary indexes
    collection.create_index([('full_hash', ASCENDING)], unique=True, name='idx_full_hash')
    print("✅ Created index: full_hash (unique)")

    collection.create_index([('tier1_hash', ASCENDING)], name='idx_tier1_hash')
    print("✅ Created index: tier1_hash")

    # NEW: Actions field index
    collection.create_index([('actions', ASCENDING)], name='idx_actions')
    print("✅ Created index: actions (NEW)")

    # Observation indexes
    collection.create_index([('observations.ip', ASCENDING)], name='idx_obs_ip')
    print("✅ Created index: observations.ip")

    collection.create_index([('observations.timestamp', DESCENDING)], name='idx_obs_timestamp')
    print("✅ Created index: observations.timestamp")

    collection.create_index([('observations.country', ASCENDING)], name='idx_obs_country')
    print("✅ Created index: observations.country")

    collection.create_index([('observations.attackType', ASCENDING)], name='idx_obs_attack_type')
    print("✅ Created index: observations.attackType")

    # Network indexes
    collection.create_index([('raw_fingerprint.additionalData.network.query', ASCENDING)], name='idx_network_ip')
    print("✅ Created index: raw_fingerprint.additionalData.network.query")

    collection.create_index([('raw_fingerprint.additionalData.network.country', ASCENDING)], name='idx_network_country')
    print("✅ Created index: raw_fingerprint.additionalData.network.country")

    collection.create_index([('raw_fingerprint.additionalData.network.proxy', ASCENDING)], name='idx_network_proxy')
    print("✅ Created index: raw_fingerprint.additionalData.network.proxy")

    # Detection indexes
    collection.create_index([('raw_fingerprint.additionalData.incognito.isPrivate', ASCENDING)], name='idx_incognito')
    print("✅ Created index: raw_fingerprint.additionalData.incognito.isPrivate")

    collection.create_index([('raw_fingerprint.additionalData.vmDetection.isVM', ASCENDING)], name='idx_vm_detection')
    print("✅ Created index: raw_fingerprint.additionalData.vmDetection.isVM")

    # Browser indexes
    collection.create_index([('raw_fingerprint.components.browserInfo.value.browser', ASCENDING)], name='idx_browser')
    print("✅ Created index: raw_fingerprint.components.browserInfo.value.browser")

    collection.create_index([('raw_fingerprint.components.browserInfo.value.os', ASCENDING)], name='idx_os')
    print("✅ Created index: raw_fingerprint.components.browserInfo.value.os")

    # Timestamp index
    collection.create_index([('raw_fingerprint.timestamp', DESCENDING)], name='idx_fp_timestamp')
    print("✅ Created index: raw_fingerprint.timestamp")

    # Compound indexes
    collection.create_index([
        ('full_hash', ASCENDING),
        ('raw_fingerprint.timestamp', DESCENDING)
    ], name='idx_compound_fullhash_timestamp')
    print("✅ Created compound index: full_hash + raw_fingerprint.timestamp")

    collection.create_index([
        ('tier1_hash', ASCENDING),
        ('observations.timestamp', DESCENDING)
    ], name='idx_compound_tier1_timestamp')
    print("✅ Created compound index: tier1_hash + observations.timestamp")

    collection.create_index([
        ('observations.attackType', ASCENDING),
        ('observations.timestamp', DESCENDING)
    ], name='idx_compound_attack_timestamp')
    print("✅ Created compound index: observations.attackType + observations.timestamp")

    collection.create_index([
        ('observations.country', ASCENDING),
        ('observations.attackType', ASCENDING)
    ], name='idx_compound_country_attack')
    print("✅ Created compound index: observations.country + observations.attackType")

    print("\n✅ All indexes created successfully!")

    # List all indexes
    print("\n" + "="*60)
    print("Current Indexes:")
    print("="*60)
    for index in collection.list_indexes():
        print(f"  • {index['name']}: {index.get('key', {})}")
    print("="*60)


def main():
    """Main function"""
    print("MongoDB Index Setup (with actions field)")
    print("="*60)

    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        print("✅ Connected to MongoDB")
    except Exception as e:
        print(f"❌ Error: Could not connect to MongoDB - {e}")
        return 1

    try:
        setup_indexes(client)
        return 0
    except Exception as e:
        print(f"❌ Error: Failed to create indexes - {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    import sys
    sys.exit(main())
