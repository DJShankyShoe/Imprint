<?php
require_once __DIR__ . '/jwe_module.php';

header('Content-Type: application/json');

$token = $_COOKIE['imprint_uid'] ?? null;
if (!$token) {
  http_response_code(400);
  echo json_encode(['ok' => false, 'error' => 'No imprint_uid cookie']);
  exit;
}

$jwe = new JWEModule();
$payload = $jwe->verifyToken($token);

if ($payload === false) {
  http_response_code(401);
  echo json_encode(['ok' => false, 'error' => 'Invalid/expired token']);
  exit;
}

echo json_encode(['ok' => true, 'payload' => $payload], JSON_PRETTY_PRINT);
