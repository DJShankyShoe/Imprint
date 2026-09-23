<?php
/**
 * Fingerprint Collection Endpoint - Sends submissions to the Imprint service
 *
 * Apache rewrites /endpoints/fp_<slot>.php to this file
 */
declare(strict_types=1);

require_once '/opt/imprint/imprint_client.php';

$logFile = '/var/log/imprint/endpoint_debug.log';
function logDebug($msg) {
    global $logFile;
    $timestamp = date('Y-m-d H:i:s');
    @file_put_contents($logFile, "[{$timestamp}] {$msg}\n", FILE_APPEND | LOCK_EX);
}

logDebug("============ ENDPOINT CALLED ============");

$slot   = (string)($_GET['slot'] ?? '');
$secret = (string)($_GET['s'] ?? '');
if (!preg_match('/^[0-9a-f]{32}$/', $slot) || !preg_match('/^[0-9a-f]{32}$/', $secret)) {
    logDebug("ERROR: Invalid slot format");
    http_response_code(404);
    exit;
}

if (($_SERVER["REQUEST_METHOD"] ?? '') !== "POST") {
    logDebug("ERROR: Invalid method, expecting POST");
    http_response_code(405);
    exit;
}

// ============ CSRF CHECKS ============
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$host   = $_SERVER['HTTP_HOST'] ?? '';
if ($origin && stripos($origin, "https://$host") !== 0) {
    logDebug("ERROR: Origin mismatch ({$origin})");
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
if (!$raw) {
    logDebug("ERROR: Empty input");
    http_response_code(400);
    exit;
}

// ============ SEND TO SERVICE ============
[$status, $uid] = imprint_collect($slot, $secret, $raw, $_SERVER['REMOTE_ADDR'] ?? '');
if ($status !== 200 || !$uid) {
    logDebug("ERROR: Service rejected submission (HTTP {$status})");
    http_response_code($status >= 400 && $status < 500 ? $status : 502);
    exit;
}
logDebug("✓ Fingerprint stored for UID: {$uid}");

// ============ CREATE TRACKING COOKIE ============
if (file_exists($_SERVER['DOCUMENT_ROOT'] . '/modules/jwe_module.php')) {
    require_once $_SERVER['DOCUMENT_ROOT'] . '/modules/jwe_module.php';

    try {
        $jwe = new JWEModule();

        // Check if visitor already has a tracking cookie
        $existingToken   = $_COOKIE['imprint_uid'] ?? null;
        $existingSession = $existingToken ? $jwe->verifyToken($existingToken) : false;

        if ($existingSession && !empty($existingSession['UID'])) {
            // Visitor already tracked - update UID if needed
            $token = ($existingSession['UID'] !== $uid)
                ? $jwe->updateClaim($existingToken, 'UID', $uid)
                : $existingToken;
        } else {
            // Holds the UID only - the site's own session cookie stays separate
            $token = $jwe->createToken(['UID' => $uid], 3600 * 24 * 7);
        }

        if ($token) {
            setcookie('imprint_uid', $token, [
                'expires'  => time() + 3600 * 24 * 7,
                'path'     => '/',
                'secure'   => true,
                'httponly' => true,
                'samesite' => 'Lax',
            ]);
            logDebug("✓ Cookie set: imprint_uid");
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

logDebug("============ COMPLETE ============\n");
http_response_code(204);
exit;
