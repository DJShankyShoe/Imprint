<?php
/**
 * Fingerprint Collection Module
 */

class FingerprintModule {

    private $endpointDir;
    private $endpointWebPath;
    private $rsaPrivateKeyPath;
    private $rsaPublicKeyPath;
    private $rsaPublicKeyPem;
    private $mongoUri;
    private $mongoDb;
    private $mongoCollection;
    private $endpointFile;
    private $endpointSecret;

    public function __construct($config = []) {
        $defaults = [
            'endpointWebPath'   => "/endpoints/",
            'rsaPrivateKeyPath' => "/opt/keys/server_private.pem",
            'rsaPublicKeyPath'  => "/opt/keys/server_public.pem",
            'mongoUser'         => "honeyprint_user",
            'mongoPassword'     => "adminSh@nkk_P@55w0rd",
            'mongoHost'         => "localhost",
            'mongoPort'         => 27017,
            'mongoAuthDb'       => "honeyprint",
            'mongoDb'           => "honeyprint",
            'mongoCollection'   => "raw_logs",
        ];

        $config = array_merge($defaults, $config);

        $this->endpointWebPath = rtrim($config['endpointWebPath'], '/') . '/';

        $docRoot = $_SERVER['DOCUMENT_ROOT'] ?? '';
        if (empty($docRoot) || !is_dir($docRoot)) {
            $docRoot = dirname(dirname(__FILE__));
        }
        $this->endpointDir = rtrim($docRoot . $this->endpointWebPath, '/') . '/';

        $this->rsaPrivateKeyPath = $config['rsaPrivateKeyPath'];
        $this->rsaPublicKeyPath  = $config['rsaPublicKeyPath'];

        $user     = urlencode($config['mongoUser']);
        $password = urlencode($config['mongoPassword']);
        $host     = $config['mongoHost'];
        $port     = $config['mongoPort'];
        $authDb   = $config['mongoAuthDb'];

        $this->mongoUri        = "mongodb://{$user}:{$password}@{$host}:{$port}/{$authDb}?authSource={$authDb}";
        $this->mongoDb         = $config['mongoDb'];
        $this->mongoCollection = $config['mongoCollection'];

        $this->rsaPublicKeyPem = "";
        if (is_readable($this->rsaPublicKeyPath)) {
            $this->rsaPublicKeyPem = trim(file_get_contents($this->rsaPublicKeyPath));
        }

        if (!is_dir($this->endpointDir)) {
            mkdir($this->endpointDir, 0755, true);
        }

        $this->autoCleanupStaleEndpoints(10);
        $this->initializeEndpoint();
    }
    
    public function hasFingerprintForUID($uid) {
        if (empty($uid)) {
            return false;
        }
        
        try {
            $autoloaders = [
                ($_SERVER['DOCUMENT_ROOT'] ?? '') . '/vendor/autoload.php',
                dirname(__DIR__) . '/vendor/autoload.php',
                '/var/www/html/vendor/autoload.php',
                '/opt/honeyprint/vendor/autoload.php',
            ];

            foreach ($autoloaders as $autoloader) {
                if (file_exists($autoloader)) {
                    require_once $autoloader;
                    break;
                }
            }
            
            if (class_exists('MongoDB\Client')) {
                $client     = new MongoDB\Client($this->mongoUri);
                $collection = $client->{$this->mongoDb}->{$this->mongoCollection};
                
                $count = $collection->countDocuments(['uid' => $uid], ['limit' => 1]);
                return $count > 0;
            }
            
            if (class_exists('MongoDB\Driver\Manager')) {
                $manager = new MongoDB\Driver\Manager($this->mongoUri);
                $query   = new MongoDB\Driver\Query(['uid' => $uid], ['limit' => 1]);
                $cursor  = $manager->executeQuery("{$this->mongoDb}.{$this->mongoCollection}", $query);
                
                $documents = $cursor->toArray();
                return count($documents) > 0;
            }
            
            return false;
            
        } catch (Exception $e) {
            error_log("hasFingerprintForUID error: " . $e->getMessage());
            return false;
        }
    }

    private function initializeEndpoint() {
        $slug     = bin2hex(random_bytes(16));
        $secret   = bin2hex(random_bytes(16));
        $filename = "fp_" . $slug . ".php";
        $filepath = $this->endpointDir . $filename;

        $code = $this->getEndpointTemplate();
        $code = str_replace(
            [
                "REPLACE_SECRET",
                "REPLACE_PRIVATE_KEY_PATH",
                "REPLACE_MONGO_URI",
                "REPLACE_MONGO_DB",
                "REPLACE_MONGO_COLLECTION",
            ],
            [
                $secret,
                $this->rsaPrivateKeyPath,
                $this->mongoUri,
                $this->mongoDb,
                $this->mongoCollection,
            ],
            $code
        );

        file_put_contents($filepath, $code);
        chmod($filepath, 0644);

        $this->endpointFile   = $filename;
        $this->endpointSecret = $secret;
        
        $this->triggerBackgroundCleanup($filepath, 10);
    }

    private function triggerBackgroundCleanup($filepath, $delaySeconds) {
        $workerScript = __DIR__ . '/cleanup_worker.php';
        if (!file_exists($workerScript)) return;

        $phpBin = $this->findPhpBinary();
        if (empty($phpBin)) {
            error_log("triggerBackgroundCleanup: Could not find PHP binary");
            return;
        }

        if (stripos(PHP_OS, 'WIN') === 0) {
            $command = "start /B \"{$phpBin}\" " . escapeshellarg($workerScript) . " " . escapeshellarg($filepath) . " " . intval($delaySeconds);
            pclose(popen($command, "r"));
        } else {
            $command = sprintf(
                '%s %s %s %d > /dev/null 2>&1 &',
                escapeshellarg($phpBin),
                escapeshellarg($workerScript),
                escapeshellarg($filepath),
                intval($delaySeconds)
            );
            exec($command);
        }
    }

    private function getEndpointTemplate() {
        return <<<'PHP'
<?php
declare(strict_types=1);

$logFile = '/var/log/honeyprint/endpoint_debug.log';
function logDebug($msg) {
    global $logFile;
    $timestamp = date('Y-m-d H:i:s');
    @file_put_contents($logFile, "[{$timestamp}] {$msg}\n", FILE_APPEND | LOCK_EX);
}

// Base64 URL decode function (handles URL-safe Base64)
function base64UrlDecode($data) {
    $data = str_replace(['-', '_'], ['+', '/'], $data);
    $padding = strlen($data) % 4;
    if ($padding) {
        $data .= str_repeat('=', 4 - $padding);
    }
    return base64_decode($data, true);
}

logDebug("============ ENDPOINT CALLED ============");
logDebug("Request Method: " . ($_SERVER["REQUEST_METHOD"] ?? 'UNKNOWN'));
logDebug("Request URI: " . ($_SERVER["REQUEST_URI"] ?? 'UNKNOWN'));
logDebug("Content-Type: " . ($_SERVER["CONTENT_TYPE"] ?? 'UNKNOWN'));

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    logDebug("ERROR: Invalid method, expecting POST");
    http_response_code(405);
    exit;
}

$reqSecret = $_GET["s"] ?? "";
logDebug("Secret from query: " . substr($reqSecret, 0, 8) . "...");

if (!hash_equals("REPLACE_SECRET", $reqSecret)) {
    logDebug("ERROR: Secret mismatch");
    http_response_code(403);
    exit;
}
logDebug("✓ Secret validated");

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$host   = $_SERVER['HTTP_HOST'] ?? '';
logDebug("Origin: {$origin}, Host: {$host}");

if ($origin && stripos($origin, "https://$host") !== 0) {
    logDebug("ERROR: Origin mismatch");
    http_response_code(403);
    exit;
}

$secFetchSite = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? '';
if ($secFetchSite && $secFetchSite !== 'same-origin') {
    logDebug("ERROR: Not same-origin");
    http_response_code(403);
    exit;
}
logDebug("✓ CSRF checks passed");

$raw = file_get_contents("php://input");
logDebug("Raw input length: " . strlen($raw));

if (!$raw) {
    logDebug("ERROR: Empty input");
    http_response_code(400);
    exit;
}

$decoded = json_decode($raw, true);
logDebug("JSON decode: " . ($decoded ? "SUCCESS" : "FAILED"));

if (is_array($decoded) && isset($decoded["ek"], $decoded["iv"], $decoded["ct"])) {
    logDebug("Detected JWE encrypted payload");
    logDebug("ek (URL-safe base64) length: " . strlen($decoded["ek"]));
    logDebug("iv (URL-safe base64) length: " . strlen($decoded["iv"]));
    logDebug("ct (URL-safe base64) length: " . strlen($decoded["ct"]));
    
    // Use URL-safe Base64 decoding
    $ek = base64UrlDecode((string)$decoded["ek"]);
    $iv = base64UrlDecode((string)$decoded["iv"]);
    $ct = base64UrlDecode((string)$decoded["ct"]);

    if ($ek === false || $iv === false || $ct === false) {
        logDebug("ERROR: Base64 URL decode failed");
        http_response_code(400);
        exit;
    }
    logDebug("✓ Base64 URL decoded - ek:" . strlen($ek) . " iv:" . strlen($iv) . " ct:" . strlen($ct));

    $privPem = @file_get_contents("REPLACE_PRIVATE_KEY_PATH");
    if (!$privPem) {
        logDebug("ERROR: Private key not found");
        http_response_code(500);
        exit;
    }
    logDebug("✓ Private key loaded");

    $privKey = openssl_pkey_get_private($privPem);
    if (!$privKey) {
        logDebug("ERROR: Invalid private key");
        http_response_code(500);
        exit;
    }

    $aesKey = "";
    if (!openssl_private_decrypt($ek, $aesKey, $privKey, OPENSSL_PKCS1_OAEP_PADDING)) {
        logDebug("ERROR: RSA decryption failed - " . openssl_error_string());
        http_response_code(403);
        exit;
    }
    logDebug("✓ RSA decrypted AES key, length: " . strlen($aesKey));

    if (strlen($ct) < 16) {
        logDebug("ERROR: Ciphertext too short");
        http_response_code(400);
        exit;
    }

    $tag        = substr($ct, -16);
    $ciphertext = substr($ct, 0, -16);
    
    $plaintext  = openssl_decrypt($ciphertext, "aes-256-gcm", $aesKey, OPENSSL_RAW_DATA, $iv, $tag);

    if ($plaintext === false) {
        logDebug("ERROR: AES-GCM decryption failed - " . openssl_error_string());
        http_response_code(403);
        exit;
    }
    logDebug("✓ AES-GCM decrypted, plaintext length: " . strlen($plaintext));

    $raw = $plaintext;
} else {
    logDebug("Detected plaintext payload");
}

$rawTrim = trim($raw);

if (!preg_match('/^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\s+(.*)$/is', $rawTrim, $m)) {
    logDebug("ERROR: UID pattern not found");
    http_response_code(400);
    exit;
}

$uid     = strtolower($m[1]);
$jsonStr = $m[2];
logDebug("✓ Extracted UID: {$uid}");

$payload = json_decode($jsonStr, true);
if (!is_array($payload)) {
    logDebug("ERROR: Invalid JSON payload");
    http_response_code(400);
    exit;
}
logDebug("✓ JSON payload valid");

// ============ CREATE SESSION COOKIE ============
logDebug("Checking for JWE module...");
if (file_exists($_SERVER['DOCUMENT_ROOT'] . '/modules/jwe_module.php')) {
    logDebug("✓ JWE module found");
    require_once $_SERVER['DOCUMENT_ROOT'] . '/modules/jwe_module.php';
    
    try {
        $jwe = new JWEModule();
        logDebug("✓ JWE module loaded");
        
        // Check if user already has a token
        $existingToken = $_COOKIE['sess_jwe'] ?? null;
        logDebug("Existing token present: " . ($existingToken ? "YES" : "NO"));
        
        $existingSession = $existingToken ? $jwe->verifyToken($existingToken) : false;
        
        if ($existingSession && !empty($existingSession['UID'])) {
            logDebug("User has valid session, UID: " . $existingSession['UID']);
            // User already has valid session - update UID if needed
            if ($existingSession['UID'] !== $uid) {
                $token = $jwe->updateClaim($existingToken, 'UID', $uid);
                logDebug("✓ Updated UID in existing token");
            } else {
                $token = $existingToken;
                logDebug("Keeping existing token (UID matches)");
            }
        } else {
            logDebug("Creating new token for UID: {$uid}");
            // Create new token with default logout status
            $token = $jwe->createToken([
                'UID' => $uid, 
                'status' => 'logout',
                'action' => []
            ], 3600 * 24 * 7);
            logDebug("✓ New token created");
        }
        
        if ($token) {
            setcookie('sess_jwe', $token, [
                'expires'  => time() + 3600 * 24 * 7,
                'path'     => '/',
                'secure'   => true,
                'httponly' => true,
                'samesite' => 'Lax',
            ]);
            logDebug("✓ Cookie set: sess_jwe");
        } else {
            logDebug("ERROR: Token creation failed");
        }
    } catch (Exception $e) {
        logDebug("ERROR: JWE module exception: " . $e->getMessage());
    }
} else {
    logDebug("WARNING: JWE module not found at " . $_SERVER['DOCUMENT_ROOT'] . '/modules/jwe_module.php');
}
// ============ END COOKIE CREATION ============

$mongoUri        = "REPLACE_MONGO_URI";
$mongoDb         = "REPLACE_MONGO_DB";
$mongoCollection = "REPLACE_MONGO_COLLECTION";

$timestamp  = (int)(microtime(true) * 1000);
$rawLogLine = "[" . gmdate("d:M:Y:H:i:s") . " +0000] " . $uid . " " . $jsonStr;

$document = [
    'timestamp'   => $timestamp,
    'uid'         => $uid,
    'raw_log'     => $rawLogLine,
    'inserted_at' => $timestamp,
];

logDebug("Attempting MongoDB insertion...");

$inserted = false;

$autoloaders = [
    ($_SERVER['DOCUMENT_ROOT'] ?? '') . '/vendor/autoload.php',
    dirname(__DIR__) . '/vendor/autoload.php',
    '/var/www/html/vendor/autoload.php',
    '/opt/honeyprint/vendor/autoload.php',
];

foreach ($autoloaders as $autoloader) {
    if (file_exists($autoloader)) {
        require_once $autoloader;
        logDebug("Loaded autoloader: {$autoloader}");
        break;
    }
}

if (class_exists('MongoDB\Client')) {
    try {
        logDebug("Using MongoDB\Client...");
        $client     = new MongoDB\Client($mongoUri);
        $collection = $client->$mongoDb->$mongoCollection;
        $result = $collection->insertOne($document);
        $inserted = true;
        logDebug("✓ MongoDB insert SUCCESS");
    } catch (Exception $e) {
        logDebug("MongoDB\Client failed: " . $e->getMessage());
    }
}

if (!$inserted && class_exists('MongoDB\Driver\Manager')) {
    try {
        logDebug("Using MongoDB\Driver\Manager...");
        $manager = new MongoDB\Driver\Manager($mongoUri);
        $bulk    = new MongoDB\Driver\BulkWrite();
        $bulk->insert($document);
        $manager->executeBulkWrite("{$mongoDb}.{$mongoCollection}", $bulk);
        $inserted = true;
        logDebug("✓ MongoDB raw driver insert SUCCESS");
    } catch (Exception $e) {
        logDebug("MongoDB raw driver failed: " . $e->getMessage());
    }
}

if (!$inserted) {
    logDebug("CRITICAL: MongoDB insertion failed");
}

@unlink(__FILE__);
logDebug("✓ Endpoint self-destructed");
logDebug("============ COMPLETE ============\n");

http_response_code(204);
exit;
PHP;
    }

    public function renderScripts() {
        $endpointUrl  = $this->endpointWebPath . htmlspecialchars($this->endpointFile, ENT_QUOTES);
        $secret       = htmlspecialchars($this->endpointSecret, ENT_QUOTES);
        $rsaPublicKey = json_encode($this->rsaPublicKeyPem);

        echo <<<HTML
<script>
  window.FP_ENDPOINT_URL = "{$endpointUrl}?s={$secret}";
  window.FP_RSA_PUBLIC_KEY_PEM = {$rsaPublicKey};
</script>
<script src="/fingerprint_scripts/fingerprint.js"></script>
HTML;
    }

    private function autoCleanupStaleEndpoints($maxAge = 10) {
        if (!is_dir($this->endpointDir)) return;
        $now   = time();
        $files = glob($this->endpointDir . "fp_*.php");
        foreach ($files as $file) {
            if (is_file($file) && ($now - filemtime($file)) > $maxAge) {
                @unlink($file);
            }
        }
    }

    public function cleanupOldEndpoints($maxAge = 86400) {
        $this->autoCleanupStaleEndpoints($maxAge);
    }

    public function getEndpointUrl() {
        return $this->endpointWebPath . $this->endpointFile . "?s=" . $this->endpointSecret;
    }

    public function getEndpointDir() {
        return $this->endpointDir;
    }

    private function findPhpBinary() {
        if (defined('PHP_BINARY') && !empty(PHP_BINARY) && file_exists(PHP_BINARY)) {
            return PHP_BINARY;
        }

        $commonPaths = [
            '/usr/bin/php',
            '/usr/bin/php8.4',
            '/usr/bin/php8.3',
            '/usr/bin/php8.2',
            '/usr/bin/php8.1',
            '/usr/bin/php8.0',
            '/usr/bin/php7.4',
            '/usr/local/bin/php',
            '/opt/php/bin/php',
        ];

        foreach ($commonPaths as $path) {
            if (file_exists($path) && is_executable($path)) {
                return $path;
            }
        }

        $output = [];
        exec('which php 2>/dev/null', $output, $ret);
        if ($ret === 0 && !empty($output[0]) && file_exists($output[0])) {
            return $output[0];
        }

        $output = [];
        exec('command -v php 2>/dev/null', $output, $ret);
        if ($ret === 0 && !empty($output[0]) && file_exists($output[0])) {
            return $output[0];
        }

        return '';
    }
}
