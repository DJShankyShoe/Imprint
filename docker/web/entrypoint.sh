#!/bin/sh
# Imprint POC web entrypoint
set -e

# Write env file from container variables
write_env() {
    file="$1"; shift
    : > "$file"
    for key in "$@"; do
        eval "value=\${$key:-}"
        printf "%s='%s'\n" "$key" "$value" >> "$file"
    done
    chown root:www-data "$file"
    chmod 640 "$file"
}

# Site settings
write_env /opt/imprint/.env \
    IMPRINT_SERVICE_URL IMPRINT_SITE_TOKEN \
    SPACEY_USERS SPACEY_DB_HOST SPACEY_DB_NAME SPACEY_DB_USER SPACEY_DB_PASS

# Mitigation PoC settings
write_env /opt/imprint/mitigation.env \
    HONEYPOT_URL RECAPTCHA_V2_SITEKEY RECAPTCHA_V2_SECRET GMAIL_USER GMAIL_APP_PASS OUTLOOK_USER OUTLOOK_APP_PASS

# Session keys from the Imprint service
mkdir -p /opt/keys
for i in $(seq 1 30); do
    [ -f /run/imprint/session/server_private.pem ] && break
    echo "Waiting for session keys from the Imprint service..."; sleep 2
done
install -o root -g www-data -m 640 /run/imprint/session/server_private.pem /opt/keys/server_private.pem
install -o root -g www-data -m 644 /run/imprint/session/server_public.pem /opt/keys/server_public.pem

# Self-signed certificate
if [ ! -f /etc/ssl/private/honeypot.key ]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/honeypot.key -out /etc/ssl/certs/honeypot.crt \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=honeypot" 2>/dev/null
    chmod 600 /etc/ssl/private/honeypot.key
fi

# Log files (read by Splunk)
mkdir -p /var/log/imprint/commands
touch /var/log/imprint/modsec_audit.log /var/log/imprint/endpoint_debug.log       /var/log/imprint/auth_debug.log /var/log/imprint/status.txt /var/log/imprint/commands/commands.txt
chown www-data:www-data /var/log/imprint/endpoint_debug.log /var/log/imprint/auth_debug.log       /var/log/imprint/status.txt /var/log/imprint/commands /var/log/imprint/commands/commands.txt
chmod 755 /var/log/imprint /var/log/imprint/commands
chmod 644 /var/log/imprint/*.log /var/log/imprint/*.txt /var/log/imprint/commands/commands.txt

exec "$@"
