#!/bin/bash
#
# Clear MongoDB Collections - Honeyprint Database
#
# This script will delete all data from:
# - honeyprint.raw_logs (fingerprint data)
# - honeyprint.actor_intel (actor intelligence data)
# - Log files
# - Splunk indexes
#

echo "========================================"
echo "MongoDB Data Cleanup Script"
echo "========================================"
echo ""

# MongoDB connection details
MONGO_USER="honeyprint_user"
MONGO_PASS="adminSh@nkk_P@55w0rd"
MONGO_HOST="localhost"
MONGO_PORT="27017"
MONGO_DB="honeyprint"

echo "Database: $MONGO_DB"
echo "Collections to clear:"
echo "  - fingerprints"
echo "  - actor_intel"
echo "  - threat_intel"
echo ""

read -p "⚠️  WARNING: This will DELETE ALL DATA from these collections. Continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Cancelled."
    exit 0
fi

echo ""
echo "Connecting to MongoDB..."
echo ""

# Using mongosh (MongoDB Shell 5.0+)
if command -v mongosh &> /dev/null; then
    echo "Using mongosh..."
    
    mongosh "mongodb://${MONGO_USER}:${MONGO_PASS}@${MONGO_HOST}:${MONGO_PORT}/${MONGO_DB}?authSource=honeyprint" <<EOF
    
    // Show current counts
    print("Current document counts:");
    print("  fingerprints: " + db.fingerprints.countDocuments());
    print("  raw logs: " + db.raw_logs.countDocuments());
    print("");
    
    // Delete all documents
    print("Deleting all documents from fingerprints...");
    var result1 = db.fingerprints.deleteMany({});
    print("✓ Deleted " + result1.deletedCount + " documents from fingerprints");
    
    print("Deleting all documents from raw_logs...");
    var result2 = db.raw_logs.deleteMany({});
    print("✓ Deleted " + result2.deletedCount + " documents from raw_logs");
    
    print("");
    print("Verification - New counts:");
    print("  fingerprints: " + db.fingerprints.countDocuments());
    print("  raw_logs: " + db.raw_logs.countDocuments());

EOF

elif command -v mongo &> /dev/null; then
    echo "Using mongo..."
    
    mongo "mongodb://${MONGO_USER}:${MONGO_PASS}@${MONGO_HOST}:${MONGO_PORT}/${MONGO_DB}?authSource=honeyprint" <<EOF
    
    print("Current document counts:");
    print("  fingerprints: " + db.fingerprints.count());
    print("  actor_intel: " + db.actor_intel.count());
    print("  threat_intel: " + db.threat_intel.count());
    print("");
    
    print("Deleting all documents from fingerprints...");
    var result1 = db.fingerprints.remove({});
    print("✓ Deleted " + result1.nRemoved + " documents from fingerprints");
    
    print("Deleting all documents from actor_intel...");
    var result2 = db.actor_intel.remove({});
    print("✓ Deleted " + result2.nRemoved + " documents from actor_intel");
    
    print("Deleting all documents from threat_intel...");
    var result3 = db.threat_intel.remove({});
    print("✓ Deleted " + result3.nRemoved + " documents from threat_intel");
    
    print("");
    print("Verification - New counts:");
    print("  fingerprints: " + db.fingerprints.count());
    print("  actor_intel: " + db.actor_intel.count());
    print("  threat_intel: " + db.threat_intel.count());
    
EOF

else
    echo "❌ Error: Neither mongosh nor mongo command found!"
    exit 1
fi

echo ""
echo "========================================"
echo "✅ MongoDB Cleanup Complete"
echo "========================================"
echo ""

# ============================================
# Clear Log Files
# ============================================
echo "========================================"
echo "Clearing Log Files"
echo "========================================"
echo ""

if [ -f /var/log/honeyprint/modsec_audit.log ]; then
    echo "Truncating ModSecurity audit log..."
    sudo truncate -s 0 /var/log/honeyprint/modsec_audit.log
    echo "✓ /var/log/honeyprint/modsec_audit.log cleared"
else
    echo "⚠️  /var/log/honeyprint/modsec_audit.log not found (skipping)"
fi

if [ -f /var/log/honeyprint/endpoint_debug.log ]; then
    echo "Truncating endpoint debug log..."
    sudo truncate -s 0 /var/log/honeyprint/endpoint_debug.log
    echo "✓ /var/log/honeyprint/endpoint_debug.log cleared"
else
    echo "⚠️  /var/log/honeyprint/endpoint_debug.log not found (skipping)"
fi

if [ -f /var/log/honeyprint/status.txt ]; then
    echo "Truncating status log..."
    sudo truncate -s 0 /var/log/honeyprint/status.txt
    echo "✓ /var/log/honeyprint/status.txt cleared"
else
    echo "⚠️  /var/log/honeyprint/status.txt not found (skipping)"
fi

echo ""

# ============================================
# Clear Splunk Event Data
# ============================================
echo "========================================"
echo "Clearing Splunk Event Data"
echo "========================================"
echo ""

if [ -f /opt/splunk/bin/splunk ]; then
    echo "Cleaning Splunk indexes..."
    echo "This will delete all events from all indexes."
    echo ""
    
    # Stop Splunk first (required for clean eventdata)
    echo "Stopping Splunk (this may take 30-60 seconds)..."
    sudo /opt/splunk/bin/splunk stop --run-as-root
    
    # Wait for Splunk to fully stop
    echo "Waiting for Splunk to stop completely..."
    sleep 10
    
    # Verify Splunk is stopped
    if pgrep -f "splunkd" > /dev/null; then
        echo "⚠️  Splunk processes still running, waiting longer..."
        sleep 20
    fi
    
    echo "✓ Splunk stopped"
    echo ""
    
    # Clean all indexes
    echo "Cleaning event data from indexes..."
    
    # Clean each index individually with -f flag to skip prompts
    echo "  Cleaning index: waf..."
    sudo /opt/splunk/bin/splunk clean eventdata -index "waf" --run-as-root -f
    
    echo "  Cleaning index: mongo_honeyprint..."
    sudo /opt/splunk/bin/splunk clean eventdata -index "mongo_honeyprint" --run-as-root -f
    
    echo "  Cleaning index: main..."
    sudo /opt/splunk/bin/splunk clean eventdata -index "main" --run-as-root -f
    
    echo "  Cleaning index: summary..."
    sudo /opt/splunk/bin/splunk clean eventdata -index "summary" --run-as-root -f
    
    echo "✓ Splunk event data cleared from all indexes"
    echo ""
    
    # Restart Splunk
    echo "Starting Splunk (this may take 30-60 seconds)..."
    sudo /opt/splunk/bin/splunk start --run-as-root
    
    # Wait for Splunk to fully start
    echo "Waiting for Splunk to start completely..."
    sleep 15
    
    # Wait for Splunk web interface to be ready
    echo "Waiting for Splunk web interface..."
    for i in {1..30}; do
        if curl -s -o /dev/null -w "%{http_code}" http://localhost:8000 2>/dev/null | grep -q "200\|303"; then
            echo "✓ Splunk is ready"
            break
        fi
        echo -n "."
        sleep 2
        if [ $i -eq 30 ]; then
            echo ""
            echo "⚠️  Splunk may still be starting (this is normal)"
        fi
    done
    
    echo "✓ Splunk restarted"
else
    echo "⚠️  Splunk not found at /opt/splunk/bin/splunk (skipping)"
fi

echo ""
echo "========================================"
echo "✅✅✅ ALL CLEANUP COMPLETE ✅✅✅"
echo "========================================"
echo ""
echo "Summary:"
echo "  ✓ MongoDB collections cleared (fingerprints, actor_intel, threat_intel)"
echo "  ✓ Log files truncated"
echo "  ✓ Splunk indexes cleared (waf, mongo_honeyprint, main, summary)"
echo ""
echo "System is ready for fresh data collection!"
echo ""
