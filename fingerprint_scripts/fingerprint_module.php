<?php
/**
 * Fingerprint Collection Module - Session-less Version
 * Uses cookies instead of PHP sessions
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

        // Build MongoDB URI
        $user     = urlencode($config['mongoUser']);
        $password = urlencode($config['mongoPassword']);
        $host     = $config['mongoHost'];
        $port     = $config['mongoPort'];
        $authDb   = $config['mongoAuthDb'];

        $this->mongoUri        = "mongodb://{$user}:{$password}@{$host}:{$port}/{$authDb}?authSource={$authDb}";
        $this->mongoDb         = $config['mongoDb'];
        $this->mongoCollection = $config['mongoCollection'];

        // Load RSA public key
        $this->rsaPublicKeyPem = "";
        if (is_readable($this->rsaPublicKeyPath)) {
            $this->rsaPublicKeyPem = trim(file_get_contents($this->rsaPublicKeyPath));
        }

        if (!is_dir($this->endpointDir)) {
            mkdir($this->endpointDir, 0755, true);
        }

        // NO session_start() - using cookies only
        $this->autoCleanupStaleEndpoints(10);
        $this->initializeEndpoint();
    }
    
    /**
     * Check if fingerprint was received for given UID
     * 
     * @param string $uid The UID to check
     * @return bool True if fingerprint exists in MongoDB
     */
    public function hasFingerprintForUID($uid) {
        if (empty($uid)) {
            return false;
        }
        
        try {
            // Load Composer autoloader
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
            
            // Try MongoDB PHP Library
            if (class_exists('MongoDB\Client')) {
                $client     = new MongoDB\Client($this->mongoUri);
                $collection = $client->{$this->mongoDb}->{$this->mongoCollection};
                
                // Check if UID exists in raw_logs
                $count = $collection->countDocuments(['uid' => $uid], ['limit' => 1]);
                return $count > 0;
            }
            
            // Try raw PECL driver
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
        // Always generate a fresh one-time endpoint (no cookie storage)
        // Each page load gets a unique endpoint that self-destructs after 10 seconds
        
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

        // NO cookie storage - endpoint is one-time use only
        // Self-destructs after fingerprint is sent or after 10 seconds
        
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

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    exit;
}

$reqSecret = $_GET["s"] ?? "";
if (!hash_equals("REPLACE_SECRET", $reqSecret)) {
    http_response_code(403);
    exit;
}

// Same-origin checks (CSRF protection via browser headers)
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$host   = $_SERVER['HTTP_HOST'] ?? '';
if ($origin && stripos($origin, "https://$host") !== 0) {
    http_response_code(403);
    exit;
}

$secFetchSite = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? '';
if ($secFetchSite && $secFetchSite !== 'same-origin') {
    http_response_code(403);
    exit;
}

$raw = file_get_contents("php://input");
if (!$raw) {
    http_response_code(400);
    exit;
}

// Decrypt JWE if present
$decoded = json_decode($raw, true);
if (is_array($decoded) && isset($decoded["ek"], $decoded["iv"], $decoded["ct"])) {
    $ek = base64_decode((string)$decoded["ek"], true);
    $iv = base64_decode((string)$decoded["iv"], true);
    $ct = base64_decode((string)$decoded["ct"], true);

    if ($ek === false || $iv === false || $ct === false) {
        http_response_code(400);
        exit;
    }

    $privPem = @file_get_contents("REPLACE_PRIVATE_KEY_PATH");
    if (!$privPem) { http_response_code(500); exit; }

    $privKey = openssl_pkey_get_private($privPem);
    if (!$privKey) { http_response_code(500); exit; }

    $aesKey = "";
    if (!openssl_private_decrypt($ek, $aesKey, $privKey, OPENSSL_PKCS1_OAEP_PADDING)) {
        http_response_code(403);
        exit;
    }

    if (strlen($ct) < 16) { http_response_code(400); exit; }

    $tag        = substr($ct, -16);
    $ciphertext = substr($ct, 0, -16);
    $plaintext  = openssl_decrypt($ciphertext, "aes-256-gcm", $aesKey, OPENSSL_RAW_DATA, $iv, $tag);

    if ($plaintext === false) { http_response_code(403); exit; }

    $raw = $plaintext;
}

// Extract UID from payload
$rawTrim = trim($raw);

if (!preg_match('/^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\s+(.*)$/is', $rawTrim, $m)) {
    http_response_code(400);
    exit;
}

$uid     = strtolower($m[1]);
$jsonStr = $m[2];

// Validate JSON
$payload = json_decode($jsonStr, true);
if (!is_array($payload)) {
    http_response_code(400);
    exit;
}

// Optional: Create/update JWE session token
if (file_exists($_SERVER['DOCUMENT_ROOT'] . '/modules/jwe_module.php') && 
    file_exists($_SERVER['DOCUMENT_ROOT'] . '/modules/uuid.php')) {
    
    require_once $_SERVER['DOCUMENT_ROOT'] . '/modules/jwe_module.php';
    
    $jwe = new JWEModule();
    
    // Check if user already has a token
    $existingToken = $_COOKIE['sess_jwe'] ?? null;
    $existingSession = $existingToken ? $jwe->verifyToken($existingToken) : false;
    
    if ($existingSession && !empty($existingSession['UID'])) {
        // User already has valid session - update UID if needed
        if ($existingSession['UID'] !== $uid) {
            $token = $jwe->updateClaim($existingToken, 'UID', $uid);
        } else {
            $token = $existingToken; // Keep existing token
        }
    } else {
        // Create new token with default logout status
        $token = $jwe->createToken([
            'UID' => $uid, 
            'status' => 'logout',
            'action' => []
        ], 3600 * 24 * 7);
    }
    
    if ($token) {
        setcookie('sess_jwe', $token, [
            'expires'  => time() + 3600 * 24 * 7,
            'path'     => '/',
            'secure'   => true,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }
}

// Insert into MongoDB
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

$inserted = false;

// Load Composer autoloader
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

// Try MongoDB PHP Library
if (class_exists('MongoDB\Client')) {
    try {
        $client     = new MongoDB\Client($mongoUri);
        $collection = $client->$mongoDb->$mongoCollection;
        $collection->insertOne($document);
        $inserted = true;
    } catch (Exception $e) {
        $errorMsg = "[" . gmdate("d:M:Y:H:i:s") . " +0000] MongoDB\Client insert failed: " . $e->getMessage() . "\n";
        @file_put_contents("/var/log/scythe/fingerprint_errors.log", $errorMsg, FILE_APPEND | LOCK_EX);
    }
}

// Fallback: Raw PECL driver
if (!$inserted && class_exists('MongoDB\Driver\Manager')) {
    try {
        $manager = new MongoDB\Driver\Manager($mongoUri);
        $bulk    = new MongoDB\Driver\BulkWrite();
        $bulk->insert($document);
        $manager->executeBulkWrite("{$mongoDb}.{$mongoCollection}", $bulk);
        $inserted = true;
    } catch (Exception $e) {
        $errorMsg = "[" . gmdate("d:M:Y:H:i:s") . " +0000] MongoDB raw driver insert failed: " . $e->getMessage() . "\n";
        @file_put_contents("/var/log/scythe/fingerprint_errors.log", $errorMsg, FILE_APPEND | LOCK_EX);
    }
}

// Critical error if MongoDB unavailable
if (!$inserted) {
    $errorMsg = "[" . gmdate("d:M:Y:H:i:s") . " +0000] CRITICAL: MongoDB unavailable - UID: {$uid} - Data lost\n";
    @file_put_contents("/var/log/scythe/fingerprint_errors.log", $errorMsg, FILE_APPEND | LOCK_EX);
}

// Self-destruct
@unlink(__FILE__);

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
