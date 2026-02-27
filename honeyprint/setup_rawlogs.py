#!/usr/bin/env python3
"""
Setup indexes for raw_logs collection
UPDATED: Removed fingerprint_data indexes (field no longer exists)
"""
from urllib.parse import quote_plus
from pymongo import MongoClient, ASCENDING, DESCENDING

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
COLLECTION_NAME = "raw_logs"


def setup_raw_logs_indexes(client):
    """
    Create indexes for raw_logs collection
    
    NOTE: fingerprint_data field no longer exists, so we only index:
    - timestamp
    - uid
    - inserted_at
    """
    db = client[DB_NAME]
    collection = db[COLLECTION_NAME]
    
    print("Creating indexes for raw_logs collection...")
    
    # Drop existing indexes (except _id)
    try:
        collection.drop_indexes()
        print("✅ Dropped existing indexes")
    except:
        pass
    
    # Index 1: timestamp (descending for recent-first queries)
    collection.create_index([('timestamp', DESCENDING)], name='idx_timestamp')
    print("✅ Created index: timestamp (descending)")
    
    # Index 2: uid (for lookup by UID)
    collection.create_index([('uid', ASCENDING)], name='idx_uid')
    print("✅ Created index: uid")
    
    # Index 3: inserted_at (for cleanup/maintenance)
    collection.create_index([('inserted_at', DESCENDING)], name='idx_inserted_at')
    print("✅ Created index: inserted_at")
    
    # Index 4: compound (uid + timestamp for user timelines)
    collection.create_index([
        ('uid', ASCENDING),
        ('timestamp', DESCENDING)
    ], name='idx_compound_uid_timestamp')
    print("✅ Created compound index: uid + timestamp")
    
    # REMOVED: fingerprint_data indexes (field no longer exists)
    # - fingerprint_data.additionalData.network.query
    # - fingerprint_data.additionalData.network.country
    # - fingerprint_data.additionalData.network.proxy
    
    # Optional: TTL index for auto-deletion after 30 days
    # Uncomment if you want raw logs to auto-delete after 30 days
    # collection.create_index([('inserted_at', ASCENDING)], expireAfterSeconds=2592000, name='idx_ttl')
    # print("✅ Created TTL index: auto-delete after 30 days")
    
    print("\n✅ All indexes created successfully!")
    
    # List all indexes
    print("\n" + "="*60)
    print("Current Indexes:")
    print("="*60)
    for index in collection.list_indexes():
        print(f"  • {index['name']}: {index.get('key', {})}")
    print("="*60)


def main():
    """
    Main function
    """
    print("MongoDB Raw Logs Index Setup (Updated)")
    print("="*60)
    
    # Connect to MongoDB
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        print("✅ Connected to MongoDB")
    except Exception as e:
        print(f"❌ Error: Could not connect to MongoDB - {e}")
        return 1
    
    try:
        setup_raw_logs_indexes(client)
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
