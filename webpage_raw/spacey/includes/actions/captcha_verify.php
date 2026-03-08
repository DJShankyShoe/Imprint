<?php
declare(strict_types=1);

if (session_status() === PHP_SESSION_NONE) session_start();
header('Content-Type: application/json');

$cfg = require __DIR__ . '/action_config.php';

$secret = $cfg['RECAPTCHA_V2_SECRET'] ?? '';

if ($secret === '') {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'missing_recaptcha_v2_secret']);
    exit;
}

$raw  = file_get_contents('php://input');
$body = json_decode($raw ?: '[]', true);

$token = $body['token'] ?? '';
if ($token === '') {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'missing_token']);
    exit;
}

$verifyUrl = 'https://www.google.com/recaptcha/api/siteverify';
$postData  = http_build_query([
    'secret'   => $secret,
    'response' => $token,
    'remoteip' => $_SERVER['REMOTE_ADDR'] ?? '',
]);

$context = stream_context_create([
    'http' => [
        'method'  => 'POST',
        'header'  => "Content-Type: application/x-www-form-urlencoded\r\n"
                   . "Content-Length: " . strlen($postData) . "\r\n",
        'content' => $postData,
        'timeout' => 8,
    ]
]);

$result = file_get_contents($verifyUrl, false, $context);
if ($result === false) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'verify_request_failed']);
    exit;
}

$data = json_decode($result, true);
if (!is_array($data)) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'bad_verify_response', 'raw' => substr($result, 0, 200)]);
    exit;
}

if (!($data['success'] ?? false)) {
    http_response_code(401);
    echo json_encode(['ok' => false, 'error' => 'recaptcha_failed', 'codes' => $data['error-codes'] ?? []]);
    exit;
}

// No pass TTL — clear the flag immediately.
// Every enforce_action('CAPTCHA') call requires fresh completion.
//unset($_SESSION['captcha_required'], $_SESSION['captcha_ok_until']);
$_SESSION['captcha_ok_until'] = time() + ($cfg['CAPTCHA_TTL'] ?? 3600);
unset($_SESSION['captcha_required']);

echo json_encode(['ok' => true]);
