# IMPRINT: Observed Web Fingerprint Signature System

```
██╗███╗   ███╗██████╗ ██████╗ ██╗███╗   ██╗████████╗
██║████╗ ████║██╔══██╗██╔══██╗██║████╗  ██║╚══██╔══╝
██║██╔████╔██║██████╔╝██████╔╝██║██╔██╗ ██║   ██║
██║██║╚██╔╝██║██╔═══╝ ██╔══██╗██║██║╚██╗██║   ██║
██║██║ ╚═╝ ██║██║     ██║  ██║██║██║ ╚████║   ██║
╚═╝╚═╝     ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝   ╚═╝
```

# 🔍 Imprint

**Device-level threat intelligence and adaptive mitigation for any web application**

Imprint remembers the *device* behind an attack, not just the IP or the session. Every visitor is fingerprinted, every attack your security monitoring detects (WAF, IDS, SIEM, application logs...) is recorded against that fingerprint, and the next time the same device shows up - new IP, cleared cookies, incognito - it gets a graduated response (CAPTCHA, OTP, rate limit, honeypot redirect or block) before your page is served.

---

## 🎯 Overview

IP blocklists and session bans stop working the moment an attacker changes proxy or clears cookies. Imprint ties attacks to **browser fingerprints** instead, so repeat offenders are recognised across sessions, IPs and identities.

1. **Observe** - a JavaScript collector fingerprints each visitor (30+ signals) and sends it, encrypted, through a one-time endpoint
2. **Correlate** - an alert from your monitoring tools (in the POC: ModSecurity SQL injection in Splunk) is linked to the visitor's fingerprint through the `imprint_uid` cookie
3. **Classify** - the mitigation advisor classifies the actor (AI) and a static, human-reviewed decision matrix maps it to actions
4. **Mitigate** - each [required page](#key-terms) looks up the visitor's fingerprint and enforces the stored actions

**Key Statistics:**
- **30+** browser signals collected per visitor (Canvas, WebGL, Audio, Fonts, Hardware, Platform, Network)
- **6** graduated mitigation actions
- **Tier 1** signatures: Lower confidence (Platform, Browser, Device, Hardware)
- **Full (Tier 2)** signatures: Higher confidence (Tier 1 + Rendering Details)
- **0** AI calls in the request path - page loads only read stored decisions

### Where It Fits

| Setup | Observation source | Mitigation |
|-------|--------------------|------------|
| **Production only** | Monitoring on your production site (WAF, IDS, app logs...) | Challenge / block the attacker on the same site |
| **Production + honeypot** | Monitoring on production + everything the attacker does in the honeypot | Send confirmed attackers to the honeypot instead of blocking them |
| **Multiple sites** | Every site reports into one Imprint service | An attacker seen on one site is recognised on all of them |

### Detection Sources

The POC uses ModSecurity (WAF) and Splunk (SIEM), but neither is required. Imprint only needs **something that detects an attack** and **something that tells the service about it**:

| Role | Examples | Requirement |
|------|----------|-------------|
| **Detection** | WAF (ModSecurity, Cloudflare, AWS WAF), IDS / IPS (Suricata, Snort, Zeek), application logs, login-failure monitoring, bot detection, honeypot activity | Must see the request's `imprint_uid` cookie (or the visitor's UID). Network IDS needs decrypted traffic (behind TLS termination) |
| **Alerting** | SIEM (Splunk, Elastic, QRadar, Sentinel, Wazuh), SOAR, a script or cron job | Can send an HTTP POST to `/api/v1/alert` with the alert token |

The alert name becomes the attack type stored for the fingerprint (e.g. `sqli`, `brute_force`, `port_scan`), so any detection your tools can name can drive mitigation.

### Key Terms

| Term | Meaning |
|------|---------|
| **Fingerprint** | The set of browser / device signals collected from a visitor, stored as two hashes: **tier1** (hardware class - shared by similar devices) and **full** (tier1 + rendering details - close to unique per device) |
| **Observation** | One recorded attack on a fingerprint (attack type, time, IP, country, browser...). A fingerprint collects observations over time |
| **UID** | Random visitor ID assigned after the first fingerprint, kept in the `imprint_uid` cookie |
| **`imprint_uid` cookie** | Imprint's own encrypted cookie, holding the visitor's UID and nothing else. It is **separate from your application's session cookie**, which Imprint never reads or writes. Your detection tools record it, so an alert can be traced back to the visitor |
| **`site_session` cookie** (POC) | The example sites' own login cookie, with its own key pair (`/opt/keys/site_*.pem`). It stands in for whatever session mechanism your application already uses - Imprint neither reads nor replaces it |
| **Slot** | A **one-time upload link** for one visitor's fingerprint. When a page that fingerprints visitors is rendered, the service creates a random link (`/endpoints/fp_<random id>.php?s=<secret>`) that accepts exactly one upload within 30 seconds, then stops existing. There is no fixed upload address to find, flood or replay |
| **Slot secret** | Second random value in the link (`?s=`), proving the upload comes from the page your server rendered. The service only stores its hash |
| **Decision** | The actions stored for a visitor's fingerprint (e.g. `["CAPTCHA"]`), which a required page looks up and enforces |
| **Required pages** | The pages you choose to protect (e.g. login, account, checkout). Only these look up a decision - other pages are untouched |
| **Site token** | `IMPRINT_SITE_TOKEN` - password your websites use to call the service (slots, fingerprint upload, decisions) |
| **Alert token** | `IMPRINT_ALERT_TOKEN` - password your SIEM / monitoring uses to call the service (report attacks, read observations). Kept separate so a leaked SIEM token cannot upload fake fingerprints, and a leaked site token cannot report fake attacks |

Both tokens are random values generated by `install_imprint.sh` into the Imprint server's `.env` - you never create them yourself. To read one: `sudo grep IMPRINT_ALERT_TOKEN .env`. In the POC the containers receive them automatically.

---

## 🏗️ System Architecture

![architecture](https://github.com/user-attachments/assets/8a674a9b-b495-4588-b825-a58b14d4f855)

### Core Components

**Imprint (the product):**
- **Imprint Service** (`scripts/imprint/service.py`): HTTP API - one-time upload links ([slots](#key-terms)), payload decryption, decisions, alert webhook (any SIEM / monitoring tool), observation export. The only component that talks to MongoDB
- **Fingerprinting Engine**: JavaScript collector (30+ signals) + RSA-AES hybrid encryption + one-time random endpoints
- **Mitigation Advisor** (`advisor.py` + `classify.py`): classifies each attacker (Claude) and maps it through a static decision matrix to actions
- **MongoDB**: `fingerprints` (Tier1/full hashes + observations + actions), `raw_logs` (full payloads), `slots` (one-time upload links)
- **PHP Integration Library** (`env.php`, `imprint_client.php`) + **Enforcement** (`enforce_action.php`): drop into any PHP site (PHP only for now; other languages are future work)
- **Splunk App** (`splunk_app/imprint`): alert action, observation input, Threat Intel dashboard

**POC environment (examples, not required - swap in your own site, monitoring and SIEM):**
- **SpaceY** (Production): example protected website on port 443
- **ZebraPal** (Honeypot): example decoy admin panel on port 8443, hardcoded credentials, logs every command
- **ModSecurity WAF**: example detection source, detection-only mode (logs attacks: SQL injection, XSS, RCE, PHP injection)
- **Splunk SIEM**: example alerting source, preconfigured with the ModSecurity and failed-login inputs, the `sqli` / `brute_force` alerts and both dashboards

### Workflow

1. **Page Load** → site asks the service for a [slot](#key-terms) (one-time upload link) → JavaScript collects 30+ signals → RSA-AES encrypted payload
2. **One-Time Endpoint** → `/endpoints/fp_<slot>.php` validates CSRF → relays to the service, which uses up the slot (single use, 30 s), decrypts, adds geolocation and stores it → site assigns a persistent UID via JWE cookie
3. **Monitoring** → a detection source (POC: ModSecurity WAF) logs the attack → SIEM extracts the attack type and the visitor's `imprint_uid` cookie
4. **Alert** → SIEM / monitoring tool posts to the service's `/api/v1/alert` → observation recorded, advisor stores actions for the fingerprint
5. **Mitigation** → each required page asks the service for a decision (full or tier1 match) → `enforce_action.php` applies it

### Deployment Modes (Docker)

| Mode | Containers | For |
|------|------------|-----|
| **Core** | MongoDB, Imprint service | Production - your own websites and monitoring / SIEM talk to the service over HTTP |
| **POC** | Core + web (SpaceY + ZebraPal + ModSecurity) + Splunk | Self-contained demo of the whole attack → alert → mitigation loop |

Both modes run the same service image; the POC only adds the example containers.

---

## ✨ Key Features

### Browser Fingerprinting Technology
- **30+ signals collected**: Canvas rendering, WebGL, Audio context, Hardware specs, Platform details, Network info
- **Tier 1 signatures** (Lower confidence): Platform + Browser + Device + Hardware
- **Full signatures** (Higher confidence): Tier 1 + Canvas hash + WebGL renderer + Audio fingerprint
- **Passive collection**: Runs silently in background—users never know it's happening
- **Cookieless persistence**: Survives clearing history, incognito mode, and browser restarts
- **Server-side geolocation**: the service looks up the visitor's IP (ip-api.com) - the browser never self-reports it

### AI Mitigation Advisor
- **Classification, not decisions**: the model only returns a category, confidence and severity - it never picks the action
- **Static decision matrix**: `rules/decision_matrix.json` maps category × severity to actions - human-editable and reviewed, the model never sees it
- **Guardrails in code**: enforced after the model returns, so prompt injection cannot talk its way past them (see [Mitigation Advisor](#-mitigation-advisor))
- **Untrusted input**: every attacker-controlled string (user agent, WebGL renderer, alert name) is sanitised and delimited as data in the prompt
- **Audit log**: every classification (input + output) is written to `classifier_audit.jsonl`
- **Off the request path**: runs only when an alert arrives - page loads never wait on an API call

### Adaptive Mitigation System
- **Intelligence-driven**: Correlates live fingerprints with past attacks from every observation source
- **Graduated responses**: 6 escalating actions based on threat category and severity
- **Escalates over time**: re-evaluated on every new observation, so an actor rotating fingerprints on the same hardware escalates
- **Multi-layer**: Combines RATE_LIMIT + CAPTCHA + OTP for persistent attackers
- **Real-time**: Mitigation applied on each required page before content is served

### Dynamic One-Time Endpoints
- Each page that fingerprints visitors gets its own [slot](#key-terms) - a random one-time upload link (`/endpoints/fp_<128-bit id>.php?s=<secret>`)
- Single use and short-lived (30 s): the service deletes the slot on first use; replays and guessed URLs get 404, like a missing file
- CSRF validation via Origin and Sec-Fetch-Site headers
- No code is written to the web root; the website never holds database credentials

### Graduated Mitigation Responses

| Action | Behavior |
|--------|----------|
| **ALLOW** | Normal access |
| **RATE_LIMIT** | 60-second penalty window |
| **CAPTCHA** | Google reCAPTCHA v2 challenge |
| **OTP** | Email one-time password required |
| **HONEYPOT** | Silent redirect to your honeypot (`HONEYPOT_URL` in `mitigation.env`; the POC defaults to the same host on port 8443) |
| **BLOCK** | Hard block with 403 Forbidden |

No honeypot? Replace `HONEYPOT` in `rules/decision_matrix.json` with `BLOCK` or `RATE_LIMIT`.

### Bypass-Resistant Enforcement
- Session-based flags stored server-side (not in cookies)
- Changing URL, clearing cookies, or back button **cannot bypass** enforcement
- `enforce_action.php` runs on every request to a required page via `require_once`
- Cache-Control: no-store headers force fresh server requests

---

## 🧠 Mitigation Advisor

Runs in the service whenever an alert adds an observation to a fingerprint.

```
alert → observation stored → feature record → classify (Claude) → guardrails → decision matrix → actions {tier1, full}
```

**Feature record:** the current event (alert name, IP, country, proxy, browser, OS), device signals (VM, WebGL, platform), identity match (how many full hashes share this tier1 hash) and history (attack types, distinct IPs and countries). The raw fingerprint is not sent.

**Categories:** `credential_stuffing`, `bot_scraping`, `injection_attack`, `reconnaissance`, `automated_exploitation`, `unknown`

**Severity buckets:** low < 30, medium 30-59, high 60-84, critical ≥ 85

**Guardrails** (`advisor.py`):

| Guardrail | Rule |
|-----------|------|
| Confidence floor | confidence < 50 → `unknown` category |
| Confirmed signals | alert names in `rules/confirmed_signals.json` force the category and a severity floor (`sqli` 80, `rce` 85, `phpi` 80, `xss` 50) |
| Tier1 ceiling | a tier1 (hardware class) match never reaches HONEYPOT / BLOCK, unless corroborated: a confirmed signal **and** 2-3 attacking fingerprints on that hardware class |
| Fail-safe | API error / timeout / no key → `CAPTCHA` (never allow, never block everyone) |

**Model:** `claude-haiku-4-5` by default (`IMPRINT_CLASSIFIER_MODEL` to change). `classify()` is one function, so the provider can be swapped without touching the rest.

---

## 📦 Installation

### Prerequisites
- **Docker Engine + Compose plugin** installed and running ([install guide](https://docs.docker.com/engine/install/))
- Git, root or sudo access, internet connection
- **Website integration:** PHP only for now (see [Supported Languages](#supported-languages))
- **POC:** ~8 GB RAM (Splunk), ~15 GB disk, ports 80, 443, 8443 and 8000 free

### Quick Start

```bash
# Clone the repository
git clone https://github.com/DJShankyShoe/HoneyPrint.git imprint
cd imprint/

# Core: MongoDB + Imprint service only (integrate your own websites and monitoring / SIEM)
sudo ./install_imprint.sh core

# POC: everything in Docker (MongoDB, service, example websites + ModSecurity, Splunk)
sudo ./install_imprint.sh poc
```

The script will:
- ✅ Check that Docker + Compose are installed and running (error if not)
- ✅ Generate `.env` and `mitigation.env` next to `compose.yaml` (root-only) - random passwords and tokens, prompts for API keys; values already in `.env` are kept ([choose your own](#choosing-your-own-passwords))
- ✅ Build and start the containers, then wait until they are healthy

**Where the passwords are:** the installer writes them to `.env` next to `compose.yaml`, in the folder you installed from. The file is root-only (`600`), so read it with sudo:

```bash
sudo cat .env                       # everything
sudo grep SPLUNK_PASSWORD .env      # one value (e.g. the Splunk login)
```

Manual equivalent: fill in `.env` / `mitigation.env` from the `.example` files, then `docker compose up -d` (core) or `docker compose --profile poc up -d` (POC).

### Access URLs (POC)

| Service | URL | Login |
|---------|-----|-------|
| SpaceY (protected site) | `https://localhost` | `SPACEY_USERS` in `.env` |
| ZebraPal (honeypot) | `https://localhost:8443` | decoy credentials |
| Splunk | `http://localhost:8000` | `admin` / `SPLUNK_PASSWORD` in `.env` |
| Imprint service API | `http://127.0.0.1:8080` | Bearer tokens in `.env` |

**Splunk licence:** the POC container starts on the Splunk **Enterprise Trial** (60 days). Starting it accepts the Splunk General Terms. Alerts need the trial (or a paid licence) - after 60 days Splunk converts to **Free**, which has no alerting, so the `sqli` alert stops firing.

### Integrating Your Website and Monitoring (Core)

In core mode the Imprint server only runs MongoDB and the Imprint service. Your website and your monitoring tools run elsewhere and talk to the service over HTTP:

```
  Your web server (PHP)                                         Your SIEM / monitoring
  - fingerprints visitors    ── site token ──▶  Imprint   ◀── alert token ──  - reports attacks
  - asks "what do I do with                     service                       - pulls observations
    this visitor?" on                          (:8080)                          for its dashboard
    required pages                                │
                                               MongoDB
```

Two tokens from the Imprint server's `.env`: `IMPRINT_SITE_TOKEN` for your websites, `IMPRINT_ALERT_TOKEN` for your SIEM. Neither side ever gets MongoDB credentials.

#### Supported Languages

| Language | Status |
|----------|--------|
| **PHP** | Supported - integration library (`env.php`, `imprint_client.php`) + modules in `webpage_modules/` |
| Other languages (Python, Node.js, Java, ...) | Future work |

The service itself is plain HTTP + JSON, so other languages only need a client for the [Service API](#service-api) endpoints.

#### Part 1: Connect Your PHP Website

**Step 1 - Make the service reachable from your web servers** (on the Imprint server)

By default the service only listens on `127.0.0.1:8080`, so only the Imprint server itself can reach it. Set `IMPRINT_BIND` in `.env` to an **internal** address your web servers can reach, then re-run the installer:

```bash
IMPRINT_BIND='10.0.0.5:8080'      # internal IP of the Imprint server - never a public address
sudo ./install_imprint.sh core
```

**Step 2 - Install the PHP client library** (on each web server)

The library is how your pages call the service. It lives in `/opt/imprint/`, outside the web root, so the token can never be downloaded as a page.

```bash
sudo mkdir -p /opt/imprint
sudo cp scripts/imprint/env.php scripts/imprint/imprint_client.php /opt/imprint/
```

Create `/opt/imprint/.env` - where the service is, and the site token (copied from the Imprint server's `.env`):

```bash
IMPRINT_SERVICE_URL='http://10.0.0.5:8080'
IMPRINT_SITE_TOKEN='<IMPRINT_SITE_TOKEN from the Imprint server>'
```

For the CAPTCHA / OTP actions, also create `/opt/imprint/mitigation.env` (see `mitigation.env.example`). Make both files readable by the web server only:

```bash
sudo chown root:www-data /opt/imprint/*.env && sudo chmod 640 /opt/imprint/*.env
```

**Step 3 - Copy the session keys** (Imprint server → each web server)

After fingerprinting, the website gives the visitor an encrypted `imprint_uid` cookie holding their UID. The website creates and reads it; the service decrypts it when an alert comes in, to know *which* visitor attacked. Both need the same key pair, which the service generates on first start.

This cookie is Imprint's own and carries the UID only. Your application keeps its own session cookie (`PHPSESSID`, `JSESSIONID`, whatever you use) and Imprint never reads, writes or replaces it.

The two are protected by different keys. The POC shows this: `imprint_uid` uses the session key pair shared with the service, while the site's own login cookie (`site_session`) uses `/opt/keys/site_*.pem`, generated on the web server and never given to Imprint - so the service cannot read the site's login state.

```bash
# On the Imprint server: copy the keys out of the container
sudo docker compose cp imprint:/keys/session/. ./session_keys/

# On each web server: install them (server_private.pem + server_public.pem)
sudo mkdir -p /opt/keys
sudo install -o root -g www-data -m 640 session_keys/server_private.pem /opt/keys/
sudo install -o root -g www-data -m 644 session_keys/server_public.pem  /opt/keys/
```

Delete the `session_keys/` copies afterwards.

**Step 4 - Add the modules to your site**

Copy these folders from `webpage_modules/` into your site's document root:

| Folder | What it does |
|--------|--------------|
| `fingerprint_scripts/` | JavaScript collector, page loader, `collect.php` (receives the fingerprint and forwards it to the service) |
| `modules/` | `imprint_uid` cookie handling, login / fingerprint check, `insert_actions.php` (asks the service for a decision) |
| `includes/actions/` | Enforcement: CAPTCHA, OTP, rate limit, honeypot redirect, block |

Add the rewrite rule to your Apache vhost (needs `mod_rewrite`):

```apache
RewriteEngine On
RewriteRule ^/endpoints/fp_([a-f0-9]{32})\.php$ /fingerprint_scripts/collect.php?slot=$1 [QSA,L]
```

Each page that fingerprints visitors gives the browser a [slot](#key-terms) - a one-time upload link such as `/endpoints/fp_3f9a...e1.php?s=...`. That file does not exist - the rule sends it to `collect.php`. Used, expired or made-up URLs return 404.

**Step 5 - Call Imprint from your pages**

Copying the modules does nothing until your pages use them. See `webpage_modules/example/index.php` for a full page.

Pages where visitors get fingerprinted (e.g. landing / login page):

```php
<?php
require_once $_SERVER['DOCUMENT_ROOT'] . '/modules/auth_check.php';
$auth = new AuthCheck();
$needsFingerprinting = $auth->needsFingerprinting($_SERVER['DOCUMENT_ROOT'] . '/fingerprint_scripts/fingerprint_module.php');

require_once $_SERVER['DOCUMENT_ROOT'] . '/fingerprint_scripts/fingerprint_loader.php';
$fpLoader = new FingerprintLoader($needsFingerprinting);
?>
<head> ... <?php $fpLoader->renderBlockingUI(); ?> </head>
<body>
  <?php $fpLoader->renderBlockingElements(); ?>
  ...
  <?php $fpLoader->renderScripts(); ?>
</body>
```

[Required pages](#key-terms) - the pages you want to protect, e.g. login, account, checkout (at the top, before any output):

```php
<?php
require_once $_SERVER['DOCUMENT_ROOT'] . '/modules/insert_actions.php';
updateTokenActions();                    // ask the service for this visitor's actions
executeActions([                         // apply them (CAPTCHA / OTP / RATE_LIMIT / HONEYPOT / BLOCK)
    'identifier' => session_id(),
    'ip'         => $_SERVER['REMOTE_ADDR'],
    'return_url' => $_SERVER['REQUEST_URI'] ?? '/',
]);
```

**Step 6 - Honeypot redirect (optional)**

`HONEYPOT` actions redirect the visitor to `HONEYPOT_URL` in `mitigation.env`. Leave it empty and the POC sends them to the same host on port 8443 (ZebraPal), so nothing depends on a domain you don't own. If you have no honeypot, replace `HONEYPOT` in `scripts/imprint/rules/decision_matrix.json` with `BLOCK` or a milder action.

#### Part 2: Connect Your Monitoring

**Detection** - any detection source works (WAF, IDS, application logs... see [Detection Sources](#detection-sources)). It must record the request's `imprint_uid` cookie: that is the only way the service can tell which visitor attacked. ModSecurity in detection-only mode (`waf/modsecurity.conf`) is the tested setup.

**Alerting with Splunk:**
1. Install `splunk_app/imprint` on your Splunk
2. Create `local/alert_actions.conf` in the app with the service address and the **alert token**:
   ```ini
   [imprintAlert]
   param.service_url = http://10.0.0.5:8080
   param.token = <IMPRINT_ALERT_TOKEN from the Imprint server>
   ```
3. Add the **Imprint Alert** action to your alerts (see [Adding Alerts](#adding-alerts-other-attack-types-or-your-own-splunk))

The same app brings the observation input and the Threat Intel dashboard - no extra setup.

**Alerting with any other tool** (SIEM, SOAR, script) - send a webhook:

```bash
curl -X POST http://10.0.0.5:8080/api/v1/alert \
  -H "Authorization: Bearer <IMPRINT_ALERT_TOKEN>" -H "Content-Type: application/json" \
  -d '{"alert_name": "sqli", "field_value": "<imprint_uid cookie>", "data_format": "encrypted"}'
```

`alert_name` is stored as the attack type. Use `"data_format": "plain"` if you send the visitor's UID instead of the cookie. For dashboards, pull `GET /api/v1/export/observations`.

#### Service API

All calls server-to-server, `Authorization: Bearer <token>`:

| Endpoint | Token | Called by |
|----------|-------|-----------|
| `POST /api/v1/slots` | site | your web server, when rendering a page that fingerprints visitors (creates a [slot](#key-terms)) |
| `POST /api/v1/collect/<slot>?s=<secret>` | site | your web server (`collect.php`), forwarding the fingerprint uploaded through a slot |
| `GET /api/v1/decision?uid=<uid>` | site | your web server, on each required page |
| `GET /api/v1/fingerprints/<uid>` | site | your web server (has this visitor been fingerprinted?) |
| `POST /api/v1/alert` | alert | your SIEM / monitoring tool (`{"alert_name": "sqli", "field_value": "<imprint_uid or UID>", "data_format": "encrypted"}`) |
| `GET /api/v1/export/observations?since=<timestamp>` | alert | your SIEM's observation input (dashboard) |

---

## 🔧 Configuration

### Credentials (`.env`)

Passwords and API keys live in two files next to `compose.yaml`. The installer creates both (root-only, mode `600`), generating passwords and tokens and prompting for the rest.

- `.env` - main system (see `.env.example`); also read by `docker compose`
- `mitigation.env` - credentials for the mitigation action PoC (CAPTCHA / OTP), kept separate from the main system (see `mitigation.env.example`); only the web container receives it

| `.env` key | Used for |
|-----|----------|
| `MONGO_ROOT_USER`, `MONGO_ROOT_PASSWORD` | MongoDB initialisation only |
| `MONGO_USER`, `MONGO_PASSWORD`, `MONGO_DB` | Imprint service's database user |
| `IMPRINT_SITE_TOKEN` | websites → service (slots, fingerprint upload, decision) |
| `IMPRINT_ALERT_TOKEN` | SIEM / monitoring → service (alerts, observation export) |
| `IMPRINT_BIND` | host interface:port where the service API listens (default `127.0.0.1:8080`) |
| `ANTHROPIC_API_KEY` | AI mitigation advisor |
| `SPACEY_USERS` | POC: SpaceY login users (`user:password,user:password`) |
| `SPLUNK_PASSWORD` | POC: Splunk `admin` password |

| `mitigation.env` key | Used for |
|-----|----------|
| `RECAPTCHA_V2_SITEKEY`, `RECAPTCHA_V2_SECRET` | CAPTCHA action |
| `GMAIL_USER`, `GMAIL_APP_PASS`, `OUTLOOK_USER`, `OUTLOOK_APP_PASS` | OTP action (SMTP accounts) |
| `HONEYPOT_URL` | HONEYPOT action target (empty = same host, port 8443) |

After editing either file, re-run `sudo ./install_imprint.sh <mode>` (or `docker compose up -d`) to recreate the containers with the new values.

#### Choosing Your Own Passwords

Two options - both work for core and POC:

| Option | How |
|--------|-----|
| **Auto-create** (default) | Just run the installer. Passwords and tokens are generated randomly into `.env` (MongoDB users default to `root` / `imprint_user`, database `imprint`) |
| **Your own values** | Create `.env` **before** the first install and fill in the values you want - the installer uses them as they are, and only generates the ones left empty |

```bash
cp .env.example .env
nano .env                          # e.g. MONGO_PASSWORD='my-own-password'
sudo ./install_imprint.sh core
```

Format: `KEY='value'`, no single quotes inside the value.

To read a generated value later: `sudo grep IMPRINT_ALERT_TOKEN .env`

**Changing values later:**
- **Tokens** (`IMPRINT_SITE_TOKEN`, `IMPRINT_ALERT_TOKEN`) - edit `.env` and re-run the installer, then update them on your web servers (`/opt/imprint/.env`) and in Splunk (`param.token`)
- **MongoDB passwords** - only applied on the very first start (empty database). Changing them in `.env` afterwards locks the service out. Choose them before the first install, or change the password inside MongoDB first and then update `.env` to match

### Mitigation Policy

| File | Controls |
|------|----------|
| `scripts/imprint/rules/decision_matrix.json` | category × severity bucket → actions |
| `scripts/imprint/rules/confirmed_signals.json` | alert names with a guaranteed category and severity floor |

Both are read by the service; restart it after editing (`docker compose restart imprint`). New actions apply from the next observation of each fingerprint.

### MongoDB Authentication

MongoDB runs in the `mongo` container on the internal Docker network only (not published on the host). On first start, `docker/mongo/init-imprint.js` creates the application user from `.env`:

```javascript
db.getSiblingDB("imprint").createUser({
  user: "<MONGO_USER>",
  pwd: "<MONGO_PASSWORD>",
  roles: [{ role: "readWrite", db: "imprint" }]
})
```

Shell access: `sudo docker compose exec mongo mongosh -u <MONGO_USER> -p --authenticationDatabase imprint imprint`

### Apache Virtual Hosts (POC)

Cookies are host-only by default, so the POC works on `localhost`, a raw IP or any domain with no edits. To share cookies across subdomains, uncomment and set your own domain:

```apache
# Only set Domain attribute if accessed via actual domain
#SetEnvIf Host "example.com" SET_DOMAIN=true
#Header edit Set-Cookie ^(.*)$ "$1; Domain=example.com" env=SET_DOMAIN
```

### ModSecurity WAF (POC)

The POC's example detection source. ModSecurity runs in **detection-only mode** (logs attacks without blocking):

```bash
# Config file
/etc/modsecurity/modsecurity.conf

# Audit log
/var/log/imprint/modsec_audit.log
```

### Splunk Configuration For Dashboard

There are two dashboards, both in the menu of **Apps → Imprint**. In the POC everything below is already set up.

| Dashboard | Ships with | Data | How it gets into Splunk |
|-----------|-----------|------|-------------------------|
| **Threat Intel** | the Imprint app (default view) | `index=imprint_intel sourcetype=imprint:observations` | Observation input (below) |
| **Honeypot (POC)** | POC only - optional example for honeypot users | `index=imprint sourcetype=imprint:commands` | Monitor of ZebraPal's `/var/log/imprint/commands/commands.txt` |

#### Observation Input

A scripted input in the Imprint app (`bin/imprint_export.py`, every 60 s) pulls fingerprint observations from the Imprint service. Splunk needs no MongoDB access or credentials, and MongoDB stays unexposed.

```
MongoDB ◀── Imprint service ◀── HTTP + alert token ── Splunk observation input ──▶ index=imprint_intel ──▶ dashboard
```

- One event per **observation**, each sent once (~540 bytes)
- Checkpoint on the observation `timestamp` (starts at `0`), kept in `$SPLUNK_HOME/var/lib/splunk/modinputs/imprint/`
- Uses the same `service_url` / `token` settings as the alert action (`local/alert_actions.conf`)

Each event is one JSON line:

```json
{"timestamp":1790049355100,"fingerprint_id":"6ab1fb60e482d147da244d45","obs_index":51,"full_hash":"b640...","tier1_hash":"2120...","ip":"203.0.113.9","country":"Romania","attackType":"sqli","proxy":false,"isPrivate":false,"vm":false,"browserName":"Chrome","os":"Windows 10","timezone":"Asia/Singapore","userAgent":"Mozilla/5.0 ...","actions_full":"HONEYPOT","actions_tier1":"HONEYPOT"}
```

The event time is the observation's `timestamp` (when the attack was recorded), so the dashboard time range filters attacks by when they happened. The dashboard's base search ends with an explicit `| fields ...` list (Dashboard Studio chained searches only receive the fields the base search names).

#### Company Splunk

1. Install `splunk_app/imprint` (alert action + observation input + Threat Intel dashboard + `imprint_intel` index)
2. Set `param.service_url` and `param.token` (alert token) in `local/alert_actions.conf`
3. Open **Apps → Imprint** - the Threat Intel dashboard opens by default
4. *(Optional, honeypot only)* Honeypot dashboard: monitor your honeypot's `commands.txt` into `index=imprint sourcetype=imprint:commands`, then import it (below)

#### Importing the Dashboards

The dashboards are separate import files in `splunk_app/dashboard/`:

| File | Dashboard |
|------|-----------|
| `Imprint Threat Intel.json` | Threat Intel (already in the Imprint app) |
| `Imprint Honeypot.json` | Honeypot (POC example) |

To import one manually:
1. Open **Apps → Imprint** (so the dashboard is created in the Imprint app)
2. **Dashboards** → **Create New Dashboard** → **Dashboard Studio** → **Absolute**
3. Click **Source** (top right), replace the content with the JSON file, click **Back** → **Save**

To add an imported Honeypot dashboard to the app menu, add `<view name="<its view name>" />` to the app's `local/data/ui/nav/default.xml` (copy of `default/data/ui/nav/default.xml`).

After editing a JSON file, run `python3 splunk_app/dashboard/build_views.py` to rebuild the Splunk views (`splunk_app/imprint/default/data/ui/views/imprint_threat_intel.xml`, `docker/splunk/views/imprint_honeypot.xml`).

### Splunk Configuration For Alerts

**POC (preconfigured):** the Splunk container ships with everything below already set up (`docker/splunk/imprint_poc`):
- Monitor inputs for `/var/log/imprint/modsec_audit.log` → `index=imprint sourcetype=modsec:audit` and `/var/log/imprint/auth/failed_logins.log` → `sourcetype=imprint:auth`
- Field extractions: `attack_type` via `\[tag "attack-(?<attack_type>sqli)"\]`, `imprint_uid` from the request `Cookie` header, `src_ip`, `uri`
- Alert **`sqli`**: `index=imprint sourcetype=modsec:audit attack_type=sqli imprint_uid=*`, every minute, per result, suppressed per `imprint_uid` for 5 minutes, action **Imprint Alert** (`field_name=imprint_uid`, `data_format=encrypted`)
- Alert **`brute_force`**: 5+ failed logins from one visitor in 5 minutes
- Alert **`brute_force_burst`**: 15+ failed logins from one visitor in 1 minute

The two failed-login alerts show how **the SIEM classifies the velocity, not the AI**. The feature record carries no attempt counts or rates, so "5 attempts over 5 minutes" and "50 in 10 seconds" look identical to the classifier - the difference reaches it only as the alert name (`brute_force` vs `brute_force_burst`). Add thresholds you care about as separate alerts; each name becomes its own attack type.

SpaceY writes one JSON line per failed login (`uid`, `username`, `ip`, `user_agent`, `site`) to `/var/log/imprint/auth/failed_logins.log`. The alerts send the plain `uid`, so they use `data_format=plain`. To wire your own application up the same way, log the visitor's UID on each failed login and point a threshold alert at it.

#### Adding Alerts (other attack types, or your own Splunk)

The Imprint Splunk app includes a custom alert action that forwards alerts to the Imprint service.

**How It Works:**
- **Alert Name** = **Attack Type** stored for the fingerprint (e.g., alert named `sqli` stores attack type "sqli")
- Alert must extract either:
  - **UID** (from fingerprint session), OR
  - **JWE Token** (`imprint_uid` cookie) - the service decrypts it to the UID
- When triggered, `imprintAlert.py` posts `{alert_name, field_value, data_format}` to `<service_url>/api/v1/alert`. The service:
  1. Finds the visitor's latest fingerprint in `raw_logs`
  2. Records an observation with the attack type and current timestamp
  3. Runs the mitigation advisor and stores the actions for tier1 / full matches
- Splunk needs no MongoDB credentials, keys or Python packages - only `param.service_url` and `param.token` (alert token) in `alert_actions.conf`

**To Create Alerts:**

1. Add a field extraction for the attack tag, e.g. `\[tag "attack-(?<attack_type>xss)"\]` on `modsec:audit`
2. Navigate to **Settings** → **Searches, reports, and alerts** → **New Alert**
3. Search: `index=imprint sourcetype=modsec:audit attack_type=xss imprint_uid=* | dedup imprint_uid | table imprint_uid`
4. Set **Trigger Actions** → **Imprint Alert**, Field Name `imprint_uid`, Data Format **Encrypted**
5. Name the alert with the attack type you want stored (e.g., `sqli`, `xss`, `rce`, `phpi`)

Alert names listed in `scripts/imprint/rules/confirmed_signals.json` get a guaranteed category and severity floor, whatever the AI returns.

---

## 📊 Dashboard

<img width="1918" height="1078" alt="dashboard" src="https://github.com/user-attachments/assets/b452ac42-0d10-468f-a3ed-28dafcbfe5a5" />

**Threat Intel** (shipped with the Imprint app):
- Total observations, proxy usage, private browsing detection
- Attack type distribution (pie chart)
- Unique IPs with observation counts
- Full fingerprint details (IP, Country, Attack Type, Browser, OS, Hashes)
- **Search by**: IP Address, Full Hash, Tier1 Hash, Attack Type

**Honeypot (POC)** (example, optional):
- Total commands executed, unique attackers
- Command activity timeline
- Top commands and top attack IPs
- Complete terminal interaction logs
- **Search by**: UID (the visitor's fingerprint UID - follow one attacker)

### Alert → Threat Intel Workflow (POC example)

```
1. Detection source (POC: ModSecurity WAF, DetectionOnly) detects attack → /var/log/imprint/modsec_audit.log
2. Splunk ingests log → index=imprint sourcetype=modsec:audit
3. Alert search matches (attack_type=sqli) → Extracts imprint_uid cookie
4. Imprint alert action → POST /api/v1/alert on the Imprint service:
   - Decrypts imprint_uid → UID → latest fingerprint in raw_logs
   - Records observation (attack type + current timestamp)
   - Mitigation advisor stores actions {tier1, full}
5. Observation input pulls the new observation → dashboard shows it (within ~1 minute)
6. Next visit to a required page: GET /api/v1/decision → enforce_action.php applies the action
```

---

## 🧩 Components

### File Structure
```
compose.yaml                  # Core + POC (profile "poc") containers
install_imprint.sh            # Installer (core | poc)
.env / mitigation.env         # Credentials (generated by install_imprint.sh, root-only)

scripts/imprint/              # Imprint service (container: imprint)
├── service.py                # HTTP API: slots, collect, decision, alert, export
├── advisor.py                # Guardrails + decision matrix -> actions
├── classify.py               # LLM threat classifier
├── fingerprint_hash.py       # Tier1 / full fingerprint hashing
├── imprint_env.py            # .env loader (Python)
├── env.php                   # .env loader (PHP integration library)
├── imprint_client.php        # Service client (PHP integration library)
├── clear_log.sh              # Cleanup script (MongoDB + logs + Splunk)
└── rules/                    # decision_matrix.json, confirmed_signals.json

webpage_modules/              # Integration modules for your site (fingerprint scripts, collect.php, actions)
splunk_app/imprint/           # Splunk app: alert action, observation input, Threat Intel dashboard
splunk_app/dashboard/         # Dashboard import files (Threat Intel, Honeypot) + build_views.py
waf/modsecurity.conf          # ModSecurity config (detection only)

docker/
├── service/Dockerfile        # Imprint service image
├── mongo/init-imprint.js     # Creates the application database user
├── web/                      # POC web image: SpaceY + ZebraPal + ModSecurity
└── splunk/                   # POC Splunk image: inputs, extractions, sqli alert, Honeypot dashboard

webpage_raw/spacey/           # POC: example protected site
webpage_raw/zebrapal/         # POC: example honeypot

Docker volumes:
├── mongo_data                # MongoDB data
├── payload_keys              # Fingerprint payload RSA key (service only)
├── session_keys              # imprint_uid RSA key (service + website)
├── audit_logs                # classifier_audit.jsonl
├── web_logs                  # POC: /var/log/imprint (web writes, Splunk reads)
└── splunk_var                # POC: Splunk indexes
```

---

## 🚀 Deployment Architectures

Imprint supports multiple deployment models:

**Design 1: Production Only**
- Simplest setup
- Fingerprinting and monitoring (WAF, IDS...) on the production site
- Fast enforcement, low complexity

**Design 2: Separate Honeypot**
- Production + dedicated honeypot, each with its own Imprint service
- Better threat discovery
- Safer intelligence gathering

**Design 3: Hybrid (Implemented POC)**
- Production + honeypot share one Imprint service
- Attackers seen in either are recognised in both, confirmed attackers are sent to the honeypot
- Stronger attribution with feedback loop

**Design 4: Shared Intel**
- Multiple sites share one centralized Imprint service
- Highly scalable for enterprises
- Better long-term analytics

---

## 📝 License

This project is licensed under the MIT License.

---

**⚠️ Disclaimer**: This is a proof-of-concept research project. Use responsibly and comply with all applicable laws and regulations regarding data privacy and user tracking.
