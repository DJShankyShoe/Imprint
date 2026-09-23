#!/bin/bash
# Imprint POC Splunk entrypoint
set -e

# Copy apps from the image (keep local/)
for src in /opt/imprint-splunk-apps/*/; do
    app=$(basename "$src")
    dst="/opt/splunk/etc/apps/$app"
    sudo mkdir -p "$dst"
    sudo find "$dst" -mindepth 1 -maxdepth 1 ! -name local -exec rm -rf {} +
    sudo cp -a "$src." "$dst/"
    sudo chown -R splunk:splunk "$dst"
done

# Alert action settings (Splunk doesn't pass env vars to alert scripts)
if [ -n "$IMPRINT_SERVICE_URL" ] && [ -n "$IMPRINT_ALERT_TOKEN" ]; then
    tmp=$(mktemp)
    printf '[imprintAlert]\nparam.service_url = %s\nparam.token = %s\n' \
        "$IMPRINT_SERVICE_URL" "$IMPRINT_ALERT_TOKEN" > "$tmp"
    sudo install -D -o splunk -g splunk -m 600 "$tmp" /opt/splunk/etc/apps/imprint/local/alert_actions.conf
    rm -f "$tmp"
fi

exec /sbin/entrypoint.sh "$@"
