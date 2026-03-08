<?php
$type = $_GET['type'] ?? '';

match($type) {
    'captcha' => require __DIR__ . '/includes/actions/captcha_verify.php',
    'otp'     => require __DIR__ . '/includes/actions/otp_verify.php',
    default   => http_response_code(404),
};