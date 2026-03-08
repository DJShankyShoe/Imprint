#!/bin/bash
#
# ============================================================================
# HONEYPRINT INSTALLATION SCRIPT
# ============================================================================
#
# This script installs and configures the complete Honeyprint system including:
# - MongoDB database setup
# - PHP dependencies
# - Honeyprint scripts and modules
# - Web application files
# - Splunk app integration (if Splunk is installed)
# - System configurations
#
# USAGE:
#   sudo ./install_honeyprint.sh /path/to/honeyprint/
#
# REQUIREMENTS:
#   - Ubuntu/Debian system
#   - Root/sudo access
#   - Extracted honeyprint directory
#   - (Optional) Splunk Enterprise installed at /opt/splunk
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

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
HONEYPRINT_DIR="$SCRIPT_DIR"

log_info "Starting Honeyprint installation..."
log_info "Source directory: $HONEYPRINT_DIR"

# Verify this is the honeyprint directory by checking for expected subdirectories
if [ ! -d "$HONEYPRINT_DIR/scripts" ] || [ ! -d "$HONEYPRINT_DIR/webpage_raw" ]; then
    log_error "This doesn't appear to be a valid honeyprint directory"
    log_error "Expected to find 'scripts' and 'webpage_raw' subdirectories"
    exit 1
fi

# ============================================================================
# STEP 1: INSTALL SYSTEM DEPENDENCIES
# ============================================================================

log_step "Step 1: Installing System Dependencies"

log_info "Updating package lists..."
apt-get update -qq

log_info "Installing MongoDB..."
# Import MongoDB GPG key and add repository
if ! command -v mongod &> /dev/null; then
    wget -qO - https://www.mongodb.org/static/pgp/server-8.0.asc | apt-key add -
    echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu $(lsb_release -cs)/mongodb-org/8.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-8.0.list
    apt-get update -qq
    apt-get install -y mongodb-org
    systemctl enable mongod
    systemctl start mongod
    log_info "✓ MongoDB installed and started"
else
    log_info "✓ MongoDB already installed"
fi

log_info "Installing PHP MongoDB extension..."
apt-get install -y php-mongodb php-dev pkg-config libssl-dev

log_info "Installing PHPMailer..."
apt-get install -y libphp-phpmailer

log_info "Installing other dependencies..."
apt-get install -y python3 python3-pip

log_info "Installing Apache2 web server..."
if ! command -v apache2 &> /dev/null; then
    apt-get install -y apache2 libapache2-mod-php
    systemctl enable apache2
    systemctl start apache2
    
    # Enable required Apache modules
    a2enmod rewrite
    a2enmod ssl
    a2enmod headers
    
    log_info "✓ Apache2 installed and started"
else
    log_info "✓ Apache2 already installed"
fi

log_info "Installing ModSecurity WAF..."
if ! dpkg -l | grep -q libapache2-mod-security2; then
    apt-get install -y libapache2-mod-security2
    
    # Enable ModSecurity module
    a2enmod security2
    
    log_info "✓ ModSecurity installed"
else
    log_info "✓ ModSecurity already installed"
fi

log_info "✓ All system dependencies installed"

# ============================================================================
# STEP 2: CREATE DIRECTORY STRUCTURE
# ============================================================================

log_step "Step 2: Creating Directory Structure"

# Create /opt/honeyprint
log_info "Creating /opt/honeyprint..."
mkdir -p /opt/honeyprint
mkdir -p /opt/honeyprint/scripts
mkdir -p /opt/honeyprint/rules

# Create /var/log/honeyprint
log_info "Creating /var/log/honeyprint..."
mkdir -p /var/log/honeyprint
touch /var/log/honeyprint/status.txt
touch /var/log/honeyprint/modsec_audit.log
touch /var/log/honeyprint/endpoint_debug.log
chmod 755 /var/log/honeyprint
chmod 644 /var/log/honeyprint/*.txt
chmod 644 /var/log/honeyprint/*.log

# Create /opt/keys for JWE encryption
log_info "Creating /opt/keys..."
mkdir -p /opt/keys
chmod 700 /opt/keys

log_info "✓ Directory structure created"

# ============================================================================
# STEP 3: SET EXTRACTION PATH
# ============================================================================

log_step "Step 3: Setting Up Source Paths"

# Use the current directory (where script is located)
EXTRACT_PATH="$HONEYPRINT_DIR"

log_info "✓ Using honeyprint directory: $EXTRACT_PATH"

# ============================================================================
# STEP 4: DEPLOY HONEYPRINT SCRIPTS
# ============================================================================

log_step "Step 4: Deploying Honeyprint Scripts to /opt/honeyprint"

if [ -d "$EXTRACT_PATH/scripts/honeyprint" ]; then
    log_info "Copying check.py..."
    cp "$EXTRACT_PATH/scripts/honeyprint/check.py" /opt/honeyprint/
    chmod +x /opt/honeyprint/check.py
    
    log_info "Copying clear_log.sh..."
    cp "$EXTRACT_PATH/scripts/honeyprint/clear_log.sh" /opt/honeyprint/
    chmod +x /opt/honeyprint/clear_log.sh
    
    if [ -d "$EXTRACT_PATH/scripts/honeyprint/rules" ]; then
        log_info "Copying rule files..."
        cp -r "$EXTRACT_PATH/scripts/honeyprint/rules/"* /opt/honeyprint/rules/
    fi
    
    log_info "✓ Honeyprint scripts deployed"
else
    log_warn "Scripts directory not found, skipping..."
fi

# ============================================================================
# STEP 5: INSTALL PYTHON DEPENDENCIES
# ============================================================================

log_step "Step 5: Installing Python Dependencies"

log_info "Installing pymongo and cryptography..."
pip3 install pymongo cryptography --quiet

log_info "✓ Python dependencies installed"

# ============================================================================
# STEP 6: SETUP MONGODB
# ============================================================================

log_step "Step 6: Setting Up MongoDB"

# MongoDB credentials
MONGO_USER="honeyprint_user"
MONGO_PASS="adminSh@nkk_P@55w0rd"
MONGO_DB="honeyprint"

log_info "Creating MongoDB user and database..."

# Remove existing user if it exists (ignore errors)
mongosh --quiet honeyprint <<EOF 2>/dev/null || true
use ${MONGO_DB}
db.dropUser("${MONGO_USER}")
EOF

# Create user in honeyprint database (NOT admin)
mongosh --quiet <<EOF
use ${MONGO_DB}
db.createUser({
  user: "${MONGO_USER}",
  pwd: "${MONGO_PASS}",
  roles: [
    { role: "readWrite", db: "${MONGO_DB}" },
    { role: "dbAdmin", db: "${MONGO_DB}" }
  ]
})
EOF

# Create collections and indexes
mongosh -u "${MONGO_USER}" -p "${MONGO_PASS}" --authenticationDatabase ${MONGO_DB} --quiet <<EOF
use ${MONGO_DB}

// Create collections with indexes
db.createCollection("fingerprints")
db.fingerprints.createIndex({ "full_hash": 1 }, { unique: true })
db.fingerprints.createIndex({ "tier1_hash": 1 })
db.fingerprints.createIndex({ "updated_at": 1 })
db.fingerprints.createIndex({ "created_at": 1 })

db.createCollection("raw_logs")
db.raw_logs.createIndex({ "uid": 1 })
db.raw_logs.createIndex({ "timestamp": 1 })

print("✓ MongoDB setup complete")
EOF

log_info "✓ MongoDB user created and collections initialized"

# ============================================================================
# STEP 7: DEPLOY WEB APPLICATION FILES
# ============================================================================

log_step "Step 7: Deploying Web Application Files"

# Ask for web root parent directory
read -p "Enter web root parent directory (default: /var/www): " WEB_PARENT
WEB_PARENT=${WEB_PARENT:-/var/www}

log_info "Web parent directory: $WEB_PARENT"

# Create parent directory if it doesn't exist
if [ ! -d "$WEB_PARENT" ]; then
    log_info "Creating parent directory: $WEB_PARENT"
    mkdir -p "$WEB_PARENT"
fi

# ============================================================================
# Deploy Zebrapal Site
# ============================================================================

WEB_ROOT_ZEBRAPAL="$WEB_PARENT/zebrapal"

log_info "Deploying Zebrapal site to: $WEB_ROOT_ZEBRAPAL"

# Remove existing if present
if [ -d "$WEB_ROOT_ZEBRAPAL" ]; then
    log_warn "Directory $WEB_ROOT_ZEBRAPAL already exists"
    read -p "Overwrite Zebrapal? (y/n): " OVERWRITE
    if [ "$OVERWRITE" = "y" ]; then
        rm -rf "$WEB_ROOT_ZEBRAPAL"
    else
        log_warn "Skipping Zebrapal deployment"
        WEB_ROOT_ZEBRAPAL=""
    fi
fi

# Copy zebrapal directory
if [ -n "$WEB_ROOT_ZEBRAPAL" ] && [ -d "$EXTRACT_PATH/webpage_raw/zebrapal" ]; then
    log_info "Copying zebrapal web application..."
    cp -r "$EXTRACT_PATH/webpage_raw/zebrapal" "$WEB_PARENT/"
    log_info "✓ Zebrapal copied"
    
    # Overlay updated modules for zebrapal
    if [ -d "$EXTRACT_PATH/webpage_modules/fingerprint_scripts" ]; then
        cp -r "$EXTRACT_PATH/webpage_modules/fingerprint_scripts" "$WEB_ROOT_ZEBRAPAL/"
        log_info "✓ Zebrapal fingerprint scripts updated"
    fi
    
    if [ -d "$EXTRACT_PATH/webpage_modules/includes" ]; then
        cp -r "$EXTRACT_PATH/webpage_modules/includes" "$WEB_ROOT_ZEBRAPAL/"
        log_info "✓ Zebrapal includes updated"
    fi
    
    # Create endpoints directory
    mkdir -p "$WEB_ROOT_ZEBRAPAL/endpoints"
    chmod 755 "$WEB_ROOT_ZEBRAPAL/endpoints"
    
    # Set permissions
    chown -R www-data:www-data "$WEB_ROOT_ZEBRAPAL"
    chmod -R 755 "$WEB_ROOT_ZEBRAPAL"
    
    log_info "✓ Zebrapal deployed"
elif [ -n "$WEB_ROOT_ZEBRAPAL" ]; then
    log_error "Zebrapal directory not found at $EXTRACT_PATH/webpage_raw/zebrapal"
fi

# ============================================================================
# Deploy SpaceY Site
# ============================================================================

WEB_ROOT_SPACEY="$WEB_PARENT/spacey"

log_info "Deploying SpaceY site to: $WEB_ROOT_SPACEY"

# Remove existing if present
if [ -d "$WEB_ROOT_SPACEY" ]; then
    log_warn "Directory $WEB_ROOT_SPACEY already exists"
    read -p "Overwrite SpaceY? (y/n): " OVERWRITE
    if [ "$OVERWRITE" = "y" ]; then
        rm -rf "$WEB_ROOT_SPACEY"
    else
        log_warn "Skipping SpaceY deployment"
        WEB_ROOT_SPACEY=""
    fi
fi

# Copy spacey directory
if [ -n "$WEB_ROOT_SPACEY" ] && [ -d "$EXTRACT_PATH/webpage_raw/spacey" ]; then
    log_info "Copying spacey web application..."
    cp -r "$EXTRACT_PATH/webpage_raw/spacey" "$WEB_PARENT/"
    log_info "✓ SpaceY copied"
    
    # Create endpoints directory
    mkdir -p "$WEB_ROOT_SPACEY/endpoints"
    chmod 755 "$WEB_ROOT_SPACEY/endpoints"
    
    # Set permissions
    chown -R www-data:www-data "$WEB_ROOT_SPACEY"
    chmod -R 755 "$WEB_ROOT_SPACEY"
    
    log_info "✓ SpaceY deployed"
elif [ -n "$WEB_ROOT_SPACEY" ]; then
    log_warn "SpaceY directory not found at $EXTRACT_PATH/webpage_raw/spacey (optional)"
fi

log_info "✓ Web applications deployed"

# ============================================================================
# STEP 8: GENERATE RSA KEYS FOR JWE ENCRYPTION
# ============================================================================

log_step "Step 8: Generating RSA Keys for JWE Encryption"

# Ensure /opt/keys directory exists
if [ ! -d /opt/keys ]; then
    log_info "Creating /opt/keys directory..."
    mkdir -p /opt/keys
    chmod 700 /opt/keys
fi

# Generate keys if they don't exist
if [ ! -f /opt/keys/server_private.pem ]; then
    log_info "Generating RSA private key..."
    openssl genrsa -out /opt/keys/server_private.pem 2048
    chmod 600 /opt/keys/server_private.pem
    
    log_info "Generating RSA public key..."
    openssl rsa -in /opt/keys/server_private.pem -pubout -out /opt/keys/server_public.pem
    chmod 644 /opt/keys/server_public.pem
    
    log_info "✓ RSA keys generated"
else
    log_info "✓ RSA private key already exists"
fi

# Ensure public key exists (regenerate from private if missing)
if [ ! -f /opt/keys/server_public.pem ] && [ -f /opt/keys/server_private.pem ]; then
    log_warn "Public key missing, regenerating from private key..."
    openssl rsa -in /opt/keys/server_private.pem -pubout -out /opt/keys/server_public.pem
    chmod 644 /opt/keys/server_public.pem
    log_info "✓ RSA public key regenerated"
fi

# Verify both keys exist
if [ ! -f /opt/keys/server_private.pem ] || [ ! -f /opt/keys/server_public.pem ]; then
    log_error "Failed to generate RSA keys!"
    exit 1
fi

log_info "✓ RSA keys verified at /opt/keys/"

# Set proper ownership and permissions for Apache (www-data)
log_info "Setting key permissions for www-data..."
chown root:www-data /opt/keys
chown root:www-data /opt/keys/server_private.pem
chown root:www-data /opt/keys/server_public.pem
chmod 750 /opt/keys
chmod 640 /opt/keys/server_private.pem
chmod 644 /opt/keys/server_public.pem

log_info "✓ Key permissions configured for Apache"

# ============================================================================
# STEP 8.5: CONFIGURE APACHE VIRTUAL HOSTS
# ============================================================================

log_step "Step 8.5: Configuring Apache Virtual Hosts"

# Enable required Apache modules
log_info "Enabling Apache modules..."
a2enmod rewrite ssl headers 2>/dev/null

# Add listening ports to ports.conf if not already there
log_info "Configuring Apache ports..."
if ! grep -q "Listen 8443" /etc/apache2/ports.conf; then
    echo "Listen 8443" >> /etc/apache2/ports.conf
    log_info "✓ Added Listen 8443 to ports.conf"
fi

# Try to find Apache config files in multiple locations
APACHE_CONF_DIR=""

# Check multiple possible locations
if [ -d "$EXTRACT_PATH/webpage_raw/apache2_conf" ]; then
    APACHE_CONF_DIR="$EXTRACT_PATH/webpage_raw/apache2_conf"
elif [ -d "$EXTRACT_PATH/apache2_conf" ]; then
    APACHE_CONF_DIR="$EXTRACT_PATH/apache2_conf"
elif [ -d "$HONEYPRINT_DIR/webpage_raw/apache2_conf" ]; then
    APACHE_CONF_DIR="$HONEYPRINT_DIR/webpage_raw/apache2_conf"
fi

if [ -n "$APACHE_CONF_DIR" ] && [ -d "$APACHE_CONF_DIR" ]; then
    log_info "Found Apache configs at: $APACHE_CONF_DIR"
    
    # Copy Zebrapal config
    if [ -f "$APACHE_CONF_DIR/zebrapal.conf" ]; then
        cp "$APACHE_CONF_DIR/zebrapal.conf" /etc/apache2/sites-available/
        log_info "✓ Zebrapal virtual host config copied"
    else
        log_warn "zebrapal.conf not found"
    fi
    
    # Copy SpaceY config
    if [ -f "$APACHE_CONF_DIR/spacey.conf" ]; then
        cp "$APACHE_CONF_DIR/spacey.conf" /etc/apache2/sites-available/
        log_info "✓ SpaceY virtual host config copied"
    else
        log_warn "spacey.conf not found"
    fi
else
    log_warn "Apache config directory not found, creating default configurations..."
    
    # Create default Zebrapal config
    cat > /etc/apache2/sites-available/zebrapal.conf <<'EOF'
<VirtualHost *:80>
    ServerName zebrapal.ddns.net
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/zebrapal
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
    ErrorLog ${APACHE_LOG_DIR}/zebrapal_error.log
    CustomLog ${APACHE_LOG_DIR}/zebrapal_access.log combined
</VirtualHost>

<VirtualHost *:8443 *:443>
    ServerName zebrapal.ddns.net
    ServerAlias localhost
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/zebrapal
    
    <Directory /var/www/zebrapal>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Strict-Transport-Security "max-age=31536000"
    Header edit Set-Cookie ^(.*)$ "$1; Domain=zebrapal.ddns.net"
    
    ErrorLog ${APACHE_LOG_DIR}/zebrapal_error.log
    CustomLog ${APACHE_LOG_DIR}/zebrapal_access.log combined
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/honeypot.crt
    SSLCertificateKeyFile /etc/ssl/private/honeypot.key
    
    <FilesMatch "\.(?:cgi|shtml|phtml|php)$">
        SSLOptions +StdEnvVars
    </FilesMatch>
</VirtualHost>
EOF
    log_info "✓ Created default zebrapal.conf"
    
    # Create default SpaceY config
    cat > /etc/apache2/sites-available/spacey.conf <<'EOF'
<VirtualHost *:80>
    ServerName spacey.ddns.net
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/spacey
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
    ErrorLog ${APACHE_LOG_DIR}/spacey_error.log
    CustomLog ${APACHE_LOG_DIR}/spacey_access.log combined
</VirtualHost>

<VirtualHost *:443>
    ServerName spacey.ddns.net
    ServerAlias localhost
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/spacey
    
    <Directory /var/www/spacey>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
        DirectorySlash Off
        DirectoryIndex index.php
    </Directory>
    
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Strict-Transport-Security "max-age=31536000"
    Header edit Set-Cookie ^(.*)$ "$1; Domain=spacey.ddns.net"
    
    ErrorLog ${APACHE_LOG_DIR}/spacey_error.log
    CustomLog ${APACHE_LOG_DIR}/spacey_access.log combined
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/honeypot.crt
    SSLCertificateKeyFile /etc/ssl/private/honeypot.key
    
    <FilesMatch "\.(?:cgi|shtml|phtml|php)$">
        SSLOptions +StdEnvVars
    </FilesMatch>
</VirtualHost>
EOF
    log_info "✓ Created default spacey.conf"
fi

# Generate self-signed SSL certificate if none exists
if [ ! -f /etc/ssl/certs/honeypot.crt ]; then
    log_info "Generating self-signed SSL certificate..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/honeypot.key \
        -out /etc/ssl/certs/honeypot.crt \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=honeypot" 2>/dev/null
    chmod 600 /etc/ssl/private/honeypot.key
    chmod 644 /etc/ssl/certs/honeypot.crt
    log_info "✓ Self-signed SSL certificate created"
else
    log_info "✓ SSL certificate already exists"
fi

# Disable default site
a2dissite 000-default 2>/dev/null || true
a2dissite default-ssl 2>/dev/null || true

# Enable honeypot sites (only if config files exist)
if [ -n "$WEB_ROOT_ZEBRAPAL" ] && [ -d "$WEB_ROOT_ZEBRAPAL" ]; then
    if [ -f /etc/apache2/sites-available/zebrapal.conf ]; then
        a2ensite zebrapal 2>/dev/null && log_info "✓ Zebrapal site enabled" || log_warn "Failed to enable zebrapal site"
    else
        log_error "zebrapal.conf not found in /etc/apache2/sites-available/"
    fi
fi

if [ -n "$WEB_ROOT_SPACEY" ] && [ -d "$WEB_ROOT_SPACEY" ]; then
    if [ -f /etc/apache2/sites-available/spacey.conf ]; then
        a2ensite spacey 2>/dev/null && log_info "✓ SpaceY site enabled" || log_warn "Failed to enable spacey site"
    else
        log_error "spacey.conf not found in /etc/apache2/sites-available/"
    fi
fi

# Test Apache configuration
log_info "Testing Apache configuration..."
if apache2ctl configtest 2>&1 | grep -q "Syntax OK"; then
    log_info "✓ Apache configuration valid"
else
    log_warn "Apache configuration test failed - checking errors..."
    apache2ctl configtest
fi

# ============================================================================
# Configure ModSecurity
# ============================================================================

log_info "Configuring ModSecurity WAF..."

# Copy ModSecurity configuration if available
if [ -f "$EXTRACT_PATH/waf/modsecurity.conf" ]; then
    log_info "Copying ModSecurity configuration..."
    cp "$EXTRACT_PATH/waf/modsecurity.conf" /etc/modsecurity/modsecurity.conf
    log_info "✓ ModSecurity configuration deployed"
else
    log_warn "ModSecurity config not found at $EXTRACT_PATH/waf/modsecurity.conf"
    
    # Use default recommended config
    if [ -f /etc/modsecurity/modsecurity.conf-recommended ]; then
        log_info "Using default ModSecurity configuration..."
        cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
        
        # Enable ModSecurity (change SecRuleEngine DetectionOnly to On)
        sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
        
        log_info "✓ ModSecurity enabled with default configuration"
    fi
fi

log_info "✓ ModSecurity configured"

# ============================================================================
# Restart Apache
# ============================================================================

# Restart Apache to apply all changes
log_info "Restarting Apache..."
systemctl restart apache2
log_info "✓ Apache restarted"

log_info "✓ Apache virtual hosts configured"

# ============================================================================
# STEP 9: DEPLOY SPLUNK APP (IF SPLUNK IS INSTALLED)
# ============================================================================

log_step "Step 9: Deploying Splunk App"

SPLUNK_HOME="/opt/splunk"

if [ -d "$SPLUNK_HOME" ]; then
    log_info "Splunk installation detected at $SPLUNK_HOME"
    
    # Prompt for Splunk app name
    echo ""
    read -p "Enter Splunk app name (press Enter to skip Splunk deployment): " SPLUNK_APP_NAME
    
    if [ -z "$SPLUNK_APP_NAME" ]; then
        log_warn "Skipping Splunk app deployment (no app name provided)"
    else
        # Deploy honeyprint app
        if [ -d "$EXTRACT_PATH/splunk_app/honeyprint" ]; then
            log_info "Deploying Splunk app as: $SPLUNK_APP_NAME"
            
            SPLUNK_APP_DIR="$SPLUNK_HOME/etc/apps/$SPLUNK_APP_NAME"
            
            # Check if app already exists
            if [ -d "$SPLUNK_APP_DIR" ]; then
                log_warn "Splunk app '$SPLUNK_APP_NAME' already exists at $SPLUNK_APP_DIR"
                read -p "Overwrite existing app? (y/n): " OVERWRITE_SPLUNK
                if [ "$OVERWRITE_SPLUNK" != "y" ]; then
                    log_warn "Skipping Splunk app deployment"
                    SPLUNK_APP_NAME=""
                else
                    rm -rf "$SPLUNK_APP_DIR"
                fi
            fi
            
            if [ -n "$SPLUNK_APP_NAME" ]; then
                mkdir -p "$SPLUNK_APP_DIR"
                cp -r "$EXTRACT_PATH/splunk_app/honeyprint/"* "$SPLUNK_APP_DIR/"
                
                chown -R splunk:splunk "$SPLUNK_APP_DIR" 2>/dev/null || chown -R root:root "$SPLUNK_APP_DIR"
                
                log_info "✓ Splunk app '$SPLUNK_APP_NAME' deployed to $SPLUNK_APP_DIR"
            fi
        else
            log_warn "Splunk app source directory not found at $EXTRACT_PATH/splunk_app/honeyprint"
        fi
        
        # Note about dashboard
        if [ -n "$SPLUNK_APP_NAME" ] && [ -d "$EXTRACT_PATH/splunk_app/dahsboard" ]; then
            log_info "Dashboard JSON found at: $EXTRACT_PATH/splunk_app/dahsboard/"
            log_warn "Please import 'Honeyprint Dashboard.json' manually via Splunk Web UI"
        fi
        
        # Restart Splunk if app was deployed
        if [ -n "$SPLUNK_APP_NAME" ] && [ -d "$SPLUNK_APP_DIR" ]; then
            read -p "Restart Splunk now? (y/n): " RESTART_SPLUNK
            if [ "$RESTART_SPLUNK" = "y" ]; then
                log_info "Restarting Splunk..."
                $SPLUNK_HOME/bin/splunk restart --run-as-root
                log_info "✓ Splunk restarted"
            fi
        fi
    fi
else
    log_warn "Splunk not found at $SPLUNK_HOME, skipping Splunk app deployment"
    SPLUNK_APP_NAME=""
fi

# ============================================================================
# INSTALLATION COMPLETE
# ============================================================================

echo ""
echo "========================================"
echo -e "${GREEN}✅ HONEYPRINT INSTALLATION COMPLETE${NC}"
echo "========================================"
echo ""
echo "📁 Installation Summary:"
echo "   - Honeyprint scripts: /opt/honeyprint"
echo "   - Log directory: /var/log/honeyprint"
echo "   - RSA keys: /opt/keys"
if [ -n "$WEB_ROOT_ZEBRAPAL" ] && [ -d "$WEB_ROOT_ZEBRAPAL" ]; then
echo "   - Zebrapal site: $WEB_ROOT_ZEBRAPAL"
fi
if [ -n "$WEB_ROOT_SPACEY" ] && [ -d "$WEB_ROOT_SPACEY" ]; then
echo "   - SpaceY site: $WEB_ROOT_SPACEY"
fi
if [ -n "$SPLUNK_APP_NAME" ] && [ -d "$SPLUNK_HOME/etc/apps/$SPLUNK_APP_NAME" ]; then
echo "   - Splunk app: $SPLUNK_HOME/etc/apps/$SPLUNK_APP_NAME"
fi
echo ""
echo "🌐 Access URLs:"
if [ -n "$WEB_ROOT_ZEBRAPAL" ] && [ -d "$WEB_ROOT_ZEBRAPAL" ]; then
echo "   Zebrapal:"
echo "      - Localhost: https://localhost:8443"
echo "      - Domain:    https://zebrapal.ddns.net"
fi
if [ -n "$WEB_ROOT_SPACEY" ] && [ -d "$WEB_ROOT_SPACEY" ]; then
echo "   SpaceY:"
echo "      - Localhost: https://localhost:443"
echo "      - Domain:    https://spacey.ddns.net"
fi
echo ""
echo "🔐 MongoDB Credentials:"
echo "   - User: $MONGO_USER"
echo "   - Password: $MONGO_PASS"
echo "   - Database: $MONGO_DB"
echo "   - Connection: mongodb://$MONGO_USER:<password>@localhost:27017/$MONGO_DB"
echo ""
echo "📝 Next Steps:"
echo "   1. Test your honeypot sites:"
if [ -n "$WEB_ROOT_ZEBRAPAL" ] && [ -d "$WEB_ROOT_ZEBRAPAL" ]; then
echo "      curl -k https://localhost:8443  # Zebrapal"
fi
if [ -n "$WEB_ROOT_SPACEY" ] && [ -d "$WEB_ROOT_SPACEY" ]; then
echo "      curl -k https://localhost:443   # SpaceY"
fi
echo "   2. Verify MongoDB is running: systemctl status mongod"
echo "   3. Check Apache status: systemctl status apache2"
if [ -n "$SPLUNK_APP_NAME" ] && [ -d "$SPLUNK_HOME/etc/apps/$SPLUNK_APP_NAME" ]; then
echo "   4. Import Honeyprint Dashboard to Splunk via Web UI"
echo "   5. Configure MongoDB input in Splunk to pull fingerprint data"
fi
echo ""
echo "🔧 Useful Commands:"
echo "   - View logs: tail -f /var/log/honeyprint/status.txt"
echo "   - MongoDB shell: mongosh mongodb://$MONGO_USER:$MONGO_PASS@localhost:27017/$MONGO_DB"
echo "   - Clear data: /opt/honeyprint/clear_log.sh"
echo ""
echo "📚 Documentation: See README for configuration details"
echo ""
