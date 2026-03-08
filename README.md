# HONEYPRINT: Honeypot-Observed Web Fingerprint Signature 

```                                                                               
██╗  ██╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗██████╗ ██████╗ ██╗███╗   ██╗████████╗
██║  ██║██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██╔══██╗██╔══██╗██║████╗  ██║╚══██╔══╝
███████║██║   ██║██╔██╗ ██║█████╗   ╚████╔╝ ██████╔╝██████╔╝██║██╔██╗ ██║   ██║   
██╔══██║██║   ██║██║╚██╗██║██╔══╝    ╚██╔╝  ██╔═══╝ ██╔══██╗██║██║╚██╗██║   ██║   
██║  ██║╚██████╔╝██║ ╚████║███████╗   ██║   ██║     ██║  ██║██║██║ ╚████║   ██║   
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝   ╚═╝

         %           %
            %           %
               %          %
                 %          %
                   %          %                   :::
                    %          %                ::::::
                 %%%%%%  %%%%%%%%%            ::::::::
              %%%%%ZZZZ%%%%%%   %%%ZZZZ     ::::::::::         ::::::
             %%%ZZZZZ%%%%%%%%%%%%%%ZZZZZZ  :::::::::::    :::::::::::::::::
             ZZZ%ZZZ%%%%%%%%%%%%%%%ZZZZZZZ::::::::::***:::::::::::::::::::::
          ZZZ%ZZZZZZ%%%%%%%%%%%%%%ZZZZZZZZZ::::::***:::::::::::::::::::::::
        ZZZ%ZZZZZZZZZZ%%%%%%%%%%ZZZZZZ%ZZZZ:::***:::::::::::::::::::::::
       ZZ%ZZZZZZZZZZZZZZZZZZZZZZZ%%%%% %ZZZ:**::::::::::::::::::::::
      ZZ%ZZZZZZZZZZZZZZZZZZZ%%%%% | | %ZZZ *:::::::::::::::::::
      Z%ZZZZZZZZZZZZZZZ%%%%%%%%%%%%%%%ZZZ::::::::::::::::::::::::::
       ZZZZZZZZZZZ%%%%%ZZZZZZZZZZZZZZZZZ%%%%:::ZZZZ:::::::::::::::::
         ZZZZ%%%%%ZZZZZZZZZZZZZZZZZZ%%%%%ZZZ%%ZZZ%ZZ%%*:::::::::::
            ZZZZZZZZZZZZZZZZZZ%%%%%%%%%ZZZZZZZZZZ%ZZ%:::*:::::::
            *:::%%%%%%%%%%%%%%%%%%%%%%%ZZZZZZZZZZ%%%*::::*::::
          *:::::::%%%%%%%%%%%%%%%%%%%%%%%ZZZZZ%%      *:::Z
         **:ZZZZ:::%%%%%%%%%%%%%%%%%%%%%%%%%%%ZZ      ZZZZZ
        *:ZZZZZZZ       %%%%%%%%%%%%%%%%%%%%%ZZZZ    ZZZZZZZ
       *::::ZZZZZZ         %%%%%%%%%%%%%%%ZZZZZZZ      ZZZ
        *::ZZZZZZ           Z%%%%%%%%%%%ZZZZZZZ%%
          ZZZZ              ZZZZZZZZZZZZZZZZ%%%%%
                           %%%ZZZZZZZZZZZ%%%%%%%%
                          Z%%%%%%%%%%%%%%%%%%%%%
                          ZZ%%%%%%%%%%%%%%%%%%%
                          %ZZZZZZZZZZZZZZZZZZZ
                          %%ZZZZZZZZZZZZZZZZZ
                           %%%%%%%%%%%%%%%%
                            %%%%%%%%%%%%%
                             %%%%%%%%%
                              ZZZZ
                              ZZZ
                             ZZ
                            Z
                                                                                  
```
# 🍯 HoneyPrint

**Honeypot-Observed Web Fingerprint Signature System**

An adaptive website protection framework that integrates device fingerprinting, threat monitoring, and dynamic mitigation. HoneyPrint tracks malicious actors across sessions using browser fingerprints (~93% re-identification rate), correlates activity with WAF threat intelligence, and applies graduated mitigation responses in real-time.

---

## 🎯 Overview

HoneyPrint addresses automated attacks, credential stuffing, web scraping, and bot-driven abuse by using **browser fingerprinting** to persistently track threat actors—even when they rotate IPs, clear cookies, or use incognito mode.

**Key Statistics:**
- **~93%** device re-identification rate
- **30+** browser signals collected per visitor (Canvas, WebGL, Audio, Fonts, Hardware, Platform, Network)
- **6** graduated mitigation actions
- **Tier 1** signatures: ~60% confidence (Platform, Browser, Device, Hardware)
- **Tier 2** signatures: ~93% confidence (Tier 1 + Rendering Details)

---

## 🏗️ System Architecture

![architecture](https://github.com/user-attachments/assets/8a674a9b-b495-4588-b825-a58b14d4f855)


### Core Components

**Websites:**
- **ZebraPal** (Honeypot): Fake admin panel at `https://zebrapal.ddns.net:8443` with hardcoded credentials
- **SpaceY** (Production): Real website at `https://spacey.ddns.net:443` with fingerprint protection

**Backend:**
- **Fingerprinting Engine**: JavaScript collector (30+ signals) + RSA-AES hybrid encryption + one-time self-destructing endpoints
- **MongoDB**: `fingerprints` collection (Tier1/Tier2 hashes), `raw_logs` collection (full payloads)
- **ModSecurity WAF**: Detection-only mode (logs attacks: SQL injection, XSS, RCE, PHP injection)
- **Splunk SIEM**: Centralized monitoring with alerts and dashboard
- **Actor DB Intel**: Malicious fingerprint database built by `check.py` script
- **Mitigation Advisor**: `enforce_action.php` executes graduated responses (session-based, bypass-resistant)

### Workflow

1. **Page Load** → JavaScript collects 30+ signals → RSA-AES encrypted payload
2. **One-Time Endpoint** → Validates CSRF + secret → Assigns persistent UID via JWE token → Stores in MongoDB
3. **Endpoint Self-Destructs** → 10-second TTL prevents replay attacks
4. **WAF Monitoring** → ModSecurity logs all attacks → Correlated with UID from fingerprint
5. **Splunk Alert** → Triggers `honeyprintAlert.py` → Updates Actor DB Intel
6. **Mitigation** → `check.py` matches visitor against Actor DB → `enforce_action.php` applies response

---

## ✨ Key Features

### Browser Fingerprinting Technology
- **30+ signals collected**: Canvas rendering, WebGL, Audio context, Hardware specs, Platform details, Network info
- **Tier 1 signatures** (~60% confidence): Platform + Browser + Device + Hardware
- **Tier 2 signatures** (~93% confidence): Tier 1 + Canvas hash + WebGL renderer + Audio fingerprint
- **Passive collection**: Runs silently in background—users never know it's happening
- **Cookieless persistence**: Survives clearing history, incognito mode, and browser restarts

### Adaptive Mitigation System
- **Intelligence-driven**: Correlates live fingerprints with Actor DB Intel from past attacks
- **Graduated responses**: 6 escalating actions based on threat confidence level
- **Feedback loop**: Newly detected threats continuously refine the intelligence base
- **Multi-layer**: Combines RATE_LIMIT + CAPTCHA + OTP for persistent attackers
- **Real-time**: Mitigation applied on every page load before content is served

### Dynamic One-Time Endpoints
- Each submission uses unique, randomly-generated endpoint with embedded secret
- CSRF validation via Origin and Sec-Fetch-Site headers
- Endpoint self-destructs after 10 seconds

### Graduated Mitigation Responses

| Action | Trigger | Behavior |
|--------|---------|----------|
| **ALLOW** | No threat detected | Normal access |
| **RATE_LIMIT** | Low-confidence match | 60-second penalty window |
| **CAPTCHA** | Medium-confidence match | Google reCAPTCHA v2 challenge |
| **OTP** | High-confidence match | Email one-time password required |
| **HONEYPOT** | Confirmed attacker | Silent session trap with fake content |
| **BLOCK** | Critical threat | Hard block with 403 Forbidden |

### Bypass-Resistant Enforcement
- Session-based flags stored server-side (not in cookies)
- Changing URL, clearing cookies, or back button **cannot bypass** enforcement
- `enforce_action.php` runs on every request via `require_once`
- Cache-Control: no-store headers force fresh server requests

---

## 📦 Installation

### Prerequisites
- Ubuntu 20.04+ (tested on Ubuntu 24)
- Root or sudo access
- Internet connection

### Quick Start

```bash
# Extract package
unzip honeyprint.zip
cd honeyprint/

# Run installation script
chmod +x install_honeyprint.sh
sudo ./install_honeyprint.sh
```

The script will install and configure:
- ✅ MongoDB 8.0 with authenticated user
- ✅ Apache2 with ModSecurity WAF
- ✅ PHP with required extensions
- ✅ Python packages (pymongo, cryptography)
- ✅ Web files (`/var/www/zebrapal`, `/var/www/spacey`)
- ✅ RSA key pair (`/opt/keys/`)
- ✅ Splunk app (optional, prompts for app name)

### Access URLs

| Site | Domain |
|------|-----------|
| ZebraPal (Honeypot) | `https://localhost:8443` |
| SpaceY (Production) | `https://localhost:443` |

---

## 🔧 Configuration

### MongoDB Authentication

**IMPORTANT**: User must be created in the `honeyprint` database (NOT `admin` database):

```javascript
use honeyprint
db.createUser({
  user: "honeyprint_user",
  pwd: "adminSh@nkk_P@55w0rd",
  roles: [{ role: "readWrite", db: "honeyprint" }]
})
```

**Connection string:**
```
mongodb://honeyprint_user:adminSh@nkk_P@55w0rd@localhost:27017/honeyprint?authSource=honeyprint
```

### Apache Virtual Hosts

The installation includes conditional Domain cookie settings that work on **both localhost AND domain**:

```apache
# Only set Domain attribute if accessed via actual domain
SetEnvIf Host "zebrapal.ddns.net" SET_DOMAIN=true
Header edit Set-Cookie ^(.*)$ "$1; Domain=zebrapal.ddns.net" env=SET_DOMAIN
```

### ModSecurity WAF

ModSecurity runs in **detection-only mode** (logs attacks without blocking):

```bash
# Config file
/etc/modsecurity/modsecurity.conf

# Audit log
/var/log/honeyprint/modsec_audit.log
```

### Splunk Configuration For Dashboard

#### Step 1: Configure MongoDB Input

1. Settings → Data Inputs → MongoDB → Add New
2. **Connection Settings**:
   - Connection URI: `mongodb://honeyprint_user:adminSh@nkk_P@55w0rd@localhost:27017/honeyprint?authSource=honeyprint`
   - Database: `honeyprint`
   - Collection: `fingerprints`
3. **Query Settings**:
   - Query Editor:
     ```javascript
     honeyprint.fingerprints.aggregate([
       { $match: { updated_at: { $gt: ? } } },
       { $sort: { updated_at: 1 } }
     ])
     ```
   - Rising Column Field: `updated_at`
   - Initial Rising Column Value: `0`
4. **Output Settings**:
   - Index: `mongo_honeyprint`
   - Sourcetype: `mongodb`
5. Click **Save**

#### Step 2: Import Dashboard

1. Navigate to **Dashboards** → **Create New Dashboard**
2. Click **Source** (top right corner)
3. **Option A - Manual JSON Import**:
   - Delete default XML content
   - Open `splunk_app/dashboard/Honeyprint Dashboard.json`
   - Copy entire JSON content
   - Paste into source editor
   - Click **Save**

4. **Option B - Dashboard Studio** (Splunk 9.0+):
   - Dashboards → Create New Dashboard → Dashboard Studio
   - Import from JSON file
   - Select `Honeyprint Dashboard.json`

5. Verify dashboard loads correctly with two tabs: **MongoDB** and **Honeypot**

### Splunk Configuration For Alerts

#### Step 1: Create Alert Actions

The HoneyPrint Splunk app includes a custom alert action that updates the Actor DB Intel when attacks are detected.

**How It Works:**
- **Alert Name** = **Attack Type** stored in Actor DB Intel (e.g., alert named `sqli` stores attack type as "sqli")
- Alert must extract either:
  - **UID** (from fingerprint session), OR
  - **JWE Token** (`sess_jwe` cookie) which the script will decode to extract UID
- When triggered, `/opt/splunk/etc/apps/honeyprint/bin/honeyprintAlert.py` executes:
  1. Extracts UID from alert results
  2. Queries MongoDB `raw_logs` for matching fingerprint
  3. Creates/updates Actor DB Intel entry with attack type from alert name
  4. Uses current timestamp for observation (not old fingerprint timestamp)

**To Create Alerts:**

1. Navigate to **Settings** → **Searches, reports, and alerts**
2. Click **New Alert**
3. Configure search to extract UID or JWE token from your WAF logs
4. Set **Trigger Actions** → **Honeyprint Alert**
5. Name the alert with the attack type you want stored (e.g., `sqli`, `xss`, `rce`, `phpi`)

**Example Alert Configuration:**

- **Alert Name**: `sqli` (this becomes the attack_type in Actor DB)
- **Search**: Extract UID from ModSecurity logs
- **Schedule**: Every 5 minutes
- **Trigger**: When results > 0
- **Action**: Honeyprint Alert

The alert action will automatically correlate the UID with the fingerprint and update Actor DB Intel.

---

## 📊 Dashboard

<img width="1918" height="1078" alt="dashboard" src="https://github.com/user-attachments/assets/b452ac42-0d10-468f-a3ed-28dafcbfe5a5" />

The Splunk dashboard provides two views:

**MongoDB View:**
- Total observations, proxy usage, private browsing detection
- Attack type distribution (pie chart)
- Unique IPs with observation counts
- Full fingerprint details (IP, Country, Attack Type, Browser, OS, Hashes)

**Honeypot View:**
- Total commands executed, unique attackers
- Command activity timeline
- Top commands and top attack IPs
- Complete terminal interaction logs

**Search by**: IP Address, Full Hash, Tier1 Hash, Attack Type

### Alert → Actor DB Workflow

```
1. ModSecurity detects attack → Logs to /var/log/honeyprint/modsec_audit.log
2. Splunk ingests log → index=waf
3. Alert search matches pattern (sqli/xss/rce/phpi) → Extracts UID
4. honeyprintAlert.py triggers:
   - Queries MongoDB raw_logs for fingerprint matching UID
   - Updates Actor DB Intel with attack type + current timestamp
   - Creates observation entry
5. Dashboard displays updated threat intelligence
6. check.py reads Actor DB → Mitigation Advisor applies action on next visit
```

---

## 🧩 Components

### File Structure
```
/opt/honeyprint/              # Core scripts
├── check.py                  # Actor DB Intel builder
├── clear_log.sh              # Cleanup script (MongoDB + Splunk)
└── rules/*.json              # Detection rules

/var/www/zebrapal/            # Honeypot site
├── index.php                 # Fake admin login
├── home/                     # Fake admin dashboard
├── modules/                  # Auth check, JWE, fingerprint verification
├── fingerprint_scripts/      # JavaScript collectors
└── endpoints/                # Self-destructing endpoints (created dynamically)

/var/www/spacey/              # Production site
├── index.php                 # Real website
├── modules/                  # Shared auth/fingerprint modules
├── fingerprint_scripts/      # JavaScript collectors
└── endpoints/                # Self-destructing endpoints

/opt/keys/                    # RSA key pair
├── server_private.pem        # 640, root:www-data
└── server_public.pem         # 644, root:www-data

/etc/modsecurity/             # ModSecurity WAF configuration
└── modsecurity.conf          # WAF rules and settings

/etc/apache2/sites-available/ # Apache virtual host configurations
├── zebrapal.conf             # Honeypot site (port 8443)
└── spacey.conf               # Production site (port 443)

/opt/splunk/etc/apps/honeyprint/  # Splunk app (optional)
├── bin/honeyprintAlert.py    # Alert action script
├── default/                  # App config
└── metadata/                 # Permissions

/var/log/honeyprint/          # Logs
├── modsec_audit.log          # ModSecurity WAF logs
└── endpoint_debug.log        # Endpoint debugging
```

---

## 🚀 Deployment Architectures

HoneyPrint supports multiple deployment models:

**Design 1: Production Only**
- Simplest setup
- Fingerprinting on production site only
- Fast enforcement, low complexity

**Design 2: Separate Honeypot**
- Production + dedicated honeypot
- Better threat discovery
- Safer intelligence gathering

**Design 3: Hybrid (Implemented POC)**
- Production + honeypot share Actor DB Intel
- Richer intelligence fusion
- Stronger attribution with feedback loop

**Design 4: Shared Intel**
- Multiple sites share centralized Actor DB
- Highly scalable for enterprises
- Better long-term analytics

---

## 📝 License

This project is licensed under the MIT License.

---

**⚠️ Disclaimer**: This is a proof-of-concept research project. Use responsibly and comply with all applicable laws and regulations regarding data privacy and user tracking.
