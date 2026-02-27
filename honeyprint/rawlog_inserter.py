#!/usr/bin/env python3
"""
Raw Fingerprint Log Inserter
Parses log lines and stores them in MongoDB

Log format:
[03:Feb:2026:20:50:25 +0000] xxxxxxxxxx {"components":{...},"timestamp":1770151827661}
"""

import json
import re
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
COLLECTION_NAME = "raw_logs"  # Separate collection for raw logs


def parse_log_line(line):
    """
    Parse a log line and extract timestamp, UID, and raw JSON
    
    Format: [03:Feb:2026:20:50:25 +0000] 019c256a-1ed4-7f58-be40-e30a00c7ab55 {"components":{...}}
    
    Returns:
        dict with parsed data or None if invalid
    """
    # Regex pattern to match log format
    # [timestamp] UID (UUID with dashes) JSON
    pattern = r'^\[([\d:A-Za-z\s+-]+)\]\s+([a-f0-9-]+)\s+(\{.+\})$'
    
    match = re.match(pattern, line.strip())
    
    if not match:
        return None
    
    timestamp_str = match.group(1)
    uid = match.group(2)
    json_str = match.group(3)
    
    # Parse timestamp: "03:Feb:2026:20:50:25 +0000"
    try:
        timestamp_dt = datetime.strptime(timestamp_str, "%d:%b:%Y:%H:%M:%S %z")
        timestamp_unix = int(timestamp_dt.timestamp() * 1000)  # Convert to milliseconds
    except ValueError:
        # Fallback: use current time if parsing fails
        timestamp_unix = int(datetime.now().timestamp() * 1000)
    
    # Validate JSON
    try:
        json_data = json.loads(json_str)
    except json.JSONDecodeError:
        return None
    
    return {
        'timestamp': timestamp_unix,
        'uid': uid,
        'raw_log': line.strip(),
        'fingerprint_data': json_data
    }


def insert_raw_log(client, log_data):
    """
    Insert raw log into MongoDB
    
    Args:
        client: MongoDB client
        log_data: Parsed log data dict
    
    Returns:
        dict with status and message
    """
    db = client[DB_NAME]
    collection = db[COLLECTION_NAME]
    
    # Create document
    document = {
        'timestamp': log_data['timestamp'],
        'uid': log_data['uid'],
        'raw_log': log_data['raw_log'],
        'fingerprint_data': log_data.get('fingerprint_data'),  # Optional
        'inserted_at': int(datetime.now().timestamp() * 1000)
    }
    
    try:
        result = collection.insert_one(document)
        
        return {
            'status': 'inserted',
            'inserted_id': str(result.inserted_id),
            'uid': log_data['uid'],
            'timestamp': log_data['timestamp']
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
        }


def main():
    """
    Main function - processes log lines from stdin or file
    """
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Insert raw fingerprint logs into MongoDB',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # From file
  python3 log_inserter.py fingerprint.txt
  
  # From stdin (pipe)
  cat /var/log/scythe/fingerprint.txt | python3 log_inserter.py
  
  # Real-time log monitoring
  tail -f /var/log/scythe/fingerprint.txt | python3 log_inserter.py
  
  # Process entire log file
  python3 log_inserter.py /var/log/scythe/fingerprint.txt
        '''
    )
    
    parser.add_argument(
        'file',
        nargs='?',
        help='Log file path (or read from stdin if not provided)'
    )
    parser.add_argument(
        '--batch',
        action='store_true',
        help='Batch mode (process all lines, show summary at end)'
    )
    
    args = parser.parse_args()
    
    # Connect to MongoDB
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        if not args.batch:
            print("✅ Connected to MongoDB")
    except Exception as e:
        print(f"❌ Error: Could not connect to MongoDB - {e}")
        sys.exit(1)
    
    # Read log lines
    if args.file:
        try:
            log_file = open(args.file, 'r')
        except FileNotFoundError:
            print(f"❌ Error: File not found - {args.file}")
            sys.exit(1)
    else:
        log_file = sys.stdin
    
    # Process lines
    inserted_count = 0
    error_count = 0
    skipped_count = 0
    
    try:
        for line_num, line in enumerate(log_file, 1):
            line = line.strip()
            
            if not line:
                continue
            
            # Parse log line
            log_data = parse_log_line(line)
            
            if not log_data:
                if not args.batch:
                    print(f"⚠️  Line {line_num}: Invalid format - skipped")
                skipped_count += 1
                continue
            
            # Insert into MongoDB
            result = insert_raw_log(client, log_data)
            
            if result['status'] == 'inserted':
                inserted_count += 1
                if not args.batch:
                    print(f"✅ Inserted: UID={result['uid']}, Timestamp={result['timestamp']}")
            else:
                error_count += 1
                if not args.batch:
                    print(f"❌ Error: {result.get('message', 'Unknown error')}")
    
    except KeyboardInterrupt:
        print("\n⚠️  Interrupted by user")
    
    finally:
        if args.file:
            log_file.close()
        client.close()
    
    # Print summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"✅ Inserted: {inserted_count}")
    print(f"❌ Errors:   {error_count}")
    print(f"⚠️  Skipped:  {skipped_count}")
    print(f"📊 Total:    {inserted_count + error_count + skipped_count}")
    print("="*60)


if __name__ == "__main__":
    main()
