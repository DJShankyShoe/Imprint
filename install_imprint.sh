#!/bin/bash
#
# ============================================================================
# IMPRINT INSTALLATION SCRIPT (Docker)
# ============================================================================
#
# This script installs and configures Imprint with Docker Compose:
# - Credentials files (.env, mitigation.env) next to compose.yaml
# - poc:  MongoDB + Imprint service + web (SpaceY, ZebraPal, ModSecurity) + Splunk
# - core: MongoDB + Imprint service only
#
# USAGE:
#   sudo ./install_imprint.sh [poc|core]      (default: poc)
#
# REQUIREMENTS:
#   - Docker Engine + Compose plugin already installed and running
#   - Root/sudo access, internet connection
#   - poc: ~8 GB RAM (Splunk), ~15 GB disk; ports 80, 443, 8443, 8000 free
#
# NOTE: Re-running keeps existing values in .env / mitigation.env
#
# ============================================================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "\n${BLUE}==>${NC} ${BLUE}$1${NC}\n"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "Please run as root or with sudo"
    exit 1
fi

MODE="${1:-poc}"
if [ "$MODE" != "poc" ] && [ "$MODE" != "core" ]; then
    log_error "Unknown mode '$MODE' - use: sudo ./install_imprint.sh [poc|core]"
    exit 1
fi

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

if [ ! -f "$SCRIPT_DIR/compose.yaml" ]; then
    log_error "compose.yaml not found in $SCRIPT_DIR - run this script from the imprint directory"
    exit 1
fi

COMPOSE=(docker compose)
if [ "$MODE" = "poc" ]; then
    COMPOSE+=(--profile poc)
fi

log_info "Starting Imprint installation (mode: $MODE)..."
log_info "Source directory: $SCRIPT_DIR"

# ============================================================================
# STEP 1: CHECK DOCKER
# ============================================================================

log_step "Step 1: Checking Docker"

if ! command -v docker &> /dev/null; then
    log_error "Docker not found - install Docker Engine + Compose plugin first: https://docs.docker.com/engine/install/"
    exit 1
fi
if ! docker compose version &> /dev/null; then
    log_error "Docker Compose plugin not found - install it first: https://docs.docker.com/compose/install/linux/"
    exit 1
fi
if ! docker info &> /dev/null; then
    log_error "Docker daemon not running - start it (e.g. systemctl start docker), then re-run"
    exit 1
fi
log_info "✓ Docker found ($(docker --version), compose $(docker compose version --short))"

# ============================================================================
# STEP 2: CREATE CREDENTIALS FILES (.env, mitigation.env)
# ============================================================================

log_step "Step 2: Creating Credentials Files"

ENV_FILE="$SCRIPT_DIR/.env"
MITIGATION_ENV_FILE="$SCRIPT_DIR/mitigation.env"

# Read value from env file
env_get() {
    grep -E "^$2=" "$1" 2>/dev/null | tail -n 1 | cut -d= -f2- | sed -e "s/^'//" -e "s/'$//" -e 's/^"//' -e 's/"$//'
}

# Prompt for value (Enter keeps current)
ask() {
    local var="$1" prompt="$2" secret="$3" current input
    current="${!var}"
    if [ -n "$current" ]; then prompt="$prompt [Enter to keep current]"; else prompt="$prompt [Enter to skip]"; fi
    if [ "$secret" = "secret" ]; then
        read -s -p "$prompt: " input || true; echo
    else
        read -p "$prompt: " input || true
    fi
    printf -v "$var" '%s' "${input:-$current}"
}

for f in "$ENV_FILE" "$MITIGATION_ENV_FILE"; do
    if [ -f "$f" ]; then
        log_info "Existing $f found - current values will be kept"
    fi
done

# Generated values (kept if already set)
MONGO_ROOT_USER=$(env_get "$ENV_FILE" MONGO_ROOT_USER);                 MONGO_ROOT_USER=${MONGO_ROOT_USER:-root}
MONGO_ROOT_PASSWORD=$(env_get "$ENV_FILE" MONGO_ROOT_PASSWORD);         MONGO_ROOT_PASSWORD=${MONGO_ROOT_PASSWORD:-$(openssl rand -hex 24)}
MONGO_USER=$(env_get "$ENV_FILE" MONGO_USER);                           MONGO_USER=${MONGO_USER:-imprint_user}
MONGO_PASSWORD=$(env_get "$ENV_FILE" MONGO_PASSWORD);                   MONGO_PASSWORD=${MONGO_PASSWORD:-$(openssl rand -hex 24)}
MONGO_DB=$(env_get "$ENV_FILE" MONGO_DB);                               MONGO_DB=${MONGO_DB:-imprint}
IMPRINT_SITE_TOKEN=$(env_get "$ENV_FILE" IMPRINT_SITE_TOKEN);     IMPRINT_SITE_TOKEN=${IMPRINT_SITE_TOKEN:-$(openssl rand -hex 32)}
IMPRINT_ALERT_TOKEN=$(env_get "$ENV_FILE" IMPRINT_ALERT_TOKEN);   IMPRINT_ALERT_TOKEN=${IMPRINT_ALERT_TOKEN:-$(openssl rand -hex 32)}
IMPRINT_BIND=$(env_get "$ENV_FILE" IMPRINT_BIND);                 IMPRINT_BIND=${IMPRINT_BIND:-127.0.0.1:8080}
SPACEY_USERS=$(env_get "$ENV_FILE" SPACEY_USERS);                       SPACEY_USERS=${SPACEY_USERS:-admin:$(openssl rand -hex 8)}
SPLUNK_PASSWORD=$(env_get "$ENV_FILE" SPLUNK_PASSWORD);                 SPLUNK_PASSWORD=${SPLUNK_PASSWORD:-$(openssl rand -hex 12)}

# API keys
ANTHROPIC_API_KEY=$(env_get "$ENV_FILE" ANTHROPIC_API_KEY)
ask ANTHROPIC_API_KEY    "Anthropic API key (mitigation advisor)" secret

# Mitigation PoC settings (poc only)
HONEYPOT_URL=$(env_get "$MITIGATION_ENV_FILE" HONEYPOT_URL)
RECAPTCHA_V2_SITEKEY=$(env_get "$MITIGATION_ENV_FILE" RECAPTCHA_V2_SITEKEY)
RECAPTCHA_V2_SECRET=$(env_get "$MITIGATION_ENV_FILE" RECAPTCHA_V2_SECRET)
GMAIL_USER=$(env_get "$MITIGATION_ENV_FILE" GMAIL_USER)
GMAIL_APP_PASS=$(env_get "$MITIGATION_ENV_FILE" GMAIL_APP_PASS)
OUTLOOK_USER=$(env_get "$MITIGATION_ENV_FILE" OUTLOOK_USER)
OUTLOOK_APP_PASS=$(env_get "$MITIGATION_ENV_FILE" OUTLOOK_APP_PASS)

if [ "$MODE" = "poc" ]; then
    ask RECAPTCHA_V2_SITEKEY "reCAPTCHA v2 site key"
    ask RECAPTCHA_V2_SECRET  "reCAPTCHA v2 secret key" secret
    ask GMAIL_USER           "Gmail address for OTP emails"
    ask GMAIL_APP_PASS       "Gmail app password" secret
    ask OUTLOOK_USER         "Outlook address for OTP emails (fallback)"
    ask OUTLOOK_APP_PASS     "Outlook app password" secret
fi

# Write .env
log_info "Writing $ENV_FILE..."
umask_old=$(umask)
umask 077
{
    echo "# Imprint credentials - generated by install_imprint.sh"
    echo "# Format: KEY='value' (see .env.example)"
    echo ""
    echo "# MongoDB"
    echo "MONGO_ROOT_USER='$MONGO_ROOT_USER'"
    echo "MONGO_ROOT_PASSWORD='$MONGO_ROOT_PASSWORD'"
    echo "MONGO_USER='$MONGO_USER'"
    echo "MONGO_PASSWORD='$MONGO_PASSWORD'"
    echo "MONGO_DB='$MONGO_DB'"
    echo ""
    echo "# Imprint service"
    echo "IMPRINT_SITE_TOKEN='$IMPRINT_SITE_TOKEN'"
    echo "IMPRINT_ALERT_TOKEN='$IMPRINT_ALERT_TOKEN'"
    echo "IMPRINT_BIND='$IMPRINT_BIND'"
    echo ""
    echo "# Mitigation advisor (Claude API)"
    echo "ANTHROPIC_API_KEY='$ANTHROPIC_API_KEY'"
    echo ""
    echo "# POC (SpaceY users, Splunk password)"
    echo "SPACEY_USERS='$SPACEY_USERS'"
    echo "SPLUNK_PASSWORD='$SPLUNK_PASSWORD'"
} > "$ENV_FILE"

# Write mitigation.env
log_info "Writing $MITIGATION_ENV_FILE..."
{
    echo "# Imprint mitigation actions (PoC) - generated by install_imprint.sh"
    echo "# Format: KEY='value' (see mitigation.env.example)"
    echo ""
    echo "# Google reCAPTCHA v2 (CAPTCHA action)"
    echo "RECAPTCHA_V2_SITEKEY='$RECAPTCHA_V2_SITEKEY'"
    echo "RECAPTCHA_V2_SECRET='$RECAPTCHA_V2_SECRET'"
    echo ""
    echo "# HONEYPOT action - empty means the POC honeypot (same host, port 8443)"
    echo "HONEYPOT_URL='$HONEYPOT_URL'"
    echo ""
    echo "# OTP action (SMTP accounts)"
    echo "GMAIL_USER='$GMAIL_USER'"
    echo "GMAIL_APP_PASS='$GMAIL_APP_PASS'"
    echo "OUTLOOK_USER='$OUTLOOK_USER'"
    echo "OUTLOOK_APP_PASS='$OUTLOOK_APP_PASS'"
} > "$MITIGATION_ENV_FILE"
umask "$umask_old"
chmod 600 "$ENV_FILE" "$MITIGATION_ENV_FILE"

if [ -z "$ANTHROPIC_API_KEY" ]; then
    log_warn "No Anthropic API key set - the mitigation advisor will use confirmed signals / CAPTCHA fail-safe"
fi
if [ "$MODE" = "poc" ] && { [ -z "$RECAPTCHA_V2_SITEKEY" ] || [ -z "$RECAPTCHA_V2_SECRET" ]; }; then
    log_warn "reCAPTCHA keys not set - the CAPTCHA action will not work until added to $MITIGATION_ENV_FILE"
fi

log_info "✓ Credentials stored in $ENV_FILE and $MITIGATION_ENV_FILE (root-only)"

# ============================================================================
# STEP 3: CHECK PORTS
# ============================================================================

log_step "Step 3: Checking Ports"

PORTS="${IMPRINT_BIND##*:}"
if [ "$MODE" = "poc" ]; then
    PORTS="$PORTS 80 443 8443 8000"
fi

RUNNING=$("${COMPOSE[@]}" ps -q 2>/dev/null || true)
for port in $PORTS; do
    if [ -z "$RUNNING" ] && ss -ltn "( sport = :$port )" 2>/dev/null | grep -q LISTEN; then
        log_error "Port $port is already in use (e.g. a native Apache/MongoDB/Splunk) - stop it and re-run"
        exit 1
    fi
done
log_info "✓ Ports available: $PORTS"

# ============================================================================
# STEP 4: BUILD AND START CONTAINERS
# ============================================================================

log_step "Step 4: Building and Starting Containers"

if [ "$MODE" = "poc" ]; then
    log_info "Splunk image is ~6.5 GB - the first build can take several minutes"
fi
"${COMPOSE[@]}" up -d --build

# ============================================================================
# STEP 5: WAIT FOR SERVICES
# ============================================================================

log_step "Step 5: Waiting for Services"

# Wait for container health check
wait_healthy() {
    local id status i
    id=$("${COMPOSE[@]}" ps -q "$1")
    for ((i = 0; i < $2; i += 10)); do
        status=$(docker inspect -f '{{.State.Health.Status}}' "$id" 2>/dev/null || echo unknown)
        if [ "$status" = "healthy" ]; then
            log_info "✓ $1 is healthy"
            return 0
        fi
        sleep 10
    done
    log_warn "$1 not healthy after $2s (status: $status) - check: docker compose logs $1"
    return 1
}

wait_healthy mongo 120 || true
wait_healthy imprint 120 || true
if [ "$MODE" = "poc" ]; then
    wait_healthy splunk 900 || true
fi

# ============================================================================
# INSTALLATION COMPLETE
# ============================================================================

echo ""
echo "========================================"
echo -e "${GREEN}✅ IMPRINT INSTALLATION COMPLETE ($MODE)${NC}"
echo "========================================"
echo ""
"${COMPOSE[@]}" ps --format 'table {{.Service}}\t{{.Status}}\t{{.Ports}}'
echo ""
echo "🔐 Credentials (root-only) - passwords and tokens were generated into:"
echo "   - Main system: $ENV_FILE"
echo "   - Mitigation PoC (reCAPTCHA / OTP SMTP): $MITIGATION_ENV_FILE"
echo "   View them:  sudo cat $ENV_FILE"
echo "   One value:  sudo grep SPLUNK_PASSWORD $ENV_FILE"
echo ""
echo "🌐 Imprint service API: http://$IMPRINT_BIND (site token: IMPRINT_SITE_TOKEN, alert token: IMPRINT_ALERT_TOKEN)"
if [ "$MODE" = "poc" ]; then
echo "   SpaceY (protected site):  https://localhost        login: SPACEY_USERS in .env (user:password)"
echo "   ZebraPal (honeypot):      https://localhost:8443    login: any decoy credentials"
echo "   Splunk:                   http://localhost:8000    login: admin / SPLUNK_PASSWORD in .env"
echo ""
echo "📝 Splunk runs on the Enterprise Trial licence (60 days, alerts work)."
echo "   After it expires Splunk switches to Free, which has no alerting - see README."
else
echo ""
echo "📝 Next steps (integrate your website and SIEM - see README):"
echo "   1. Set IMPRINT_BIND in .env to an internal interface your web servers can reach, then re-run"
echo "   2. Deploy scripts/imprint/env.php + imprint_client.php to /opt/imprint on each web server"
echo "   3. Copy the session keys to the web servers: docker compose cp imprint:/keys/session/. ./session_keys/"
echo "   4. Point your SIEM alert webhook at http://<service>/api/v1/alert (Splunk: splunk_app/imprint)"
fi
echo ""
echo "🔧 Useful Commands:"
echo "   - Status:     ${COMPOSE[*]} ps"
echo "   - Logs:       ${COMPOSE[*]} logs -f imprint"
echo "   - Stop:       ${COMPOSE[*]} down"
echo "   - Clear data: ./scripts/imprint/clear_log.sh"
echo ""
