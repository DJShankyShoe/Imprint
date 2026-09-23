#!/bin/bash
#
# Clear Imprint Data (Docker)
#
# This script will delete all data from:
# - imprint.fingerprints, raw_logs, slots
# - Log files
# - Splunk indexes (POC)
#
# USAGE: sudo ./scripts/imprint/clear_log.sh
#

PROJECT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/../.." && pwd )"
cd "$PROJECT_DIR"

echo "========================================"
echo "Imprint Data Cleanup Script"
echo "========================================"
echo ""

# MongoDB connection details (.env)
if [ ! -r "$PROJECT_DIR/.env" ]; then
    echo "Cannot read $PROJECT_DIR/.env (run as root)"
    exit 1
fi
set -a
. "$PROJECT_DIR/.env"
set +a
MONGO_DB="${MONGO_DB:-imprint}"

COMPOSE=(docker compose --profile poc)
running() { [ -n "$("${COMPOSE[@]}" ps -q --status running "$1" 2>/dev/null)" ]; }

echo "Database: $MONGO_DB"
echo "Collections to clear:"
echo "  - fingerprints"
echo "  - raw_logs"
echo "  - slots"
echo ""

read -p "⚠️  WARNING: This will DELETE ALL DATA from these collections, logs and Splunk indexes. Continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Cancelled."
    exit 0
fi

echo ""

# ============================================
# Clear MongoDB
# ============================================
if running mongo; then
    CLEANUP_JS='
print("Current document counts:");
print("  fingerprints: " + db.fingerprints.countDocuments());
print("  raw_logs: " + db.raw_logs.countDocuments());
print("");
["fingerprints", "raw_logs", "slots"].forEach(function (c) {
    var r = db.getCollection(c).deleteMany({});
    print("✓ Deleted " + r.deletedCount + " documents from " + c);
});'
    "${COMPOSE[@]}" exec -T mongo mongosh --quiet -u "$MONGO_USER" -p "$MONGO_PASSWORD" \
        --authenticationDatabase "$MONGO_DB" "$MONGO_DB" --eval "$CLEANUP_JS"
    echo "✅ MongoDB Cleanup Complete"
else
    echo "⚠️  mongo container not running (skipping)"
fi
echo ""

# ============================================
# Clear Log Files
# ============================================
if running web; then
    "${COMPOSE[@]}" exec -T web sh -c '
        for f in /var/log/imprint/modsec_audit.log /var/log/imprint/endpoint_debug.log \
                 /var/log/imprint/auth_debug.log /var/log/imprint/status.txt \
                 /var/log/imprint/commands/commands.txt; do
            [ -f "$f" ] && truncate -s 0 "$f" && echo "✓ $f cleared"
        done'
else
    echo "⚠️  web container not running (skipping log files)"
fi
if running imprint; then
    "${COMPOSE[@]}" exec -T imprint sh -c ': > /data/audit/classifier_audit.jsonl' && echo "✓ classifier audit log cleared"
fi
echo ""

# ============================================
# Clear Splunk Event Data
# ============================================
if running splunk; then
    echo "Cleaning Splunk indexes (Splunk restarts inside the container, 1-2 minutes)..."
    SPLUNK=(/opt/splunk/bin/splunk)
    "${COMPOSE[@]}" exec -T -u splunk splunk "${SPLUNK[@]}" stop > /dev/null
    for index in imprint imprint_intel main; do
        "${COMPOSE[@]}" exec -T -u splunk splunk "${SPLUNK[@]}" clean eventdata -index "$index" -f > /dev/null 2>&1 \
            && echo "  ✓ index $index cleared"
    done
    "${COMPOSE[@]}" exec -T -u splunk splunk "${SPLUNK[@]}" start --answer-yes > /dev/null
    echo "✓ Splunk restarted"
else
    echo "⚠️  splunk container not running (skipping)"
fi

echo ""
echo "========================================"
echo "✅✅✅ ALL CLEANUP COMPLETE ✅✅✅"
echo "========================================"
echo ""
echo "System is ready for fresh data collection!"
echo ""
