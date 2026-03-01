<?php
declare(strict_types=1);

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

$cfg = require __DIR__ . '/action_config.php';
require_once __DIR__ . '/mailer.php';

function cfg_int(array $cfg, string $key, int $default): int {
    $v = $cfg[$key] ?? $default;
    $v = is_numeric($v) ? (int)$v : $default;
    return $v;
}

function fixed_otp(array $cfg): string {
    $fixed  = (string)($cfg['OTP_FIXED_CODE'] ?? '123456');
    $digits = preg_replace('/\D/', '', $fixed);
    if ($digits === '') $digits = '123456';
    return str_pad(substr($digits, 0, 6), 6, '0', STR_PAD_LEFT);
}

function json_out(array $payload, int $code = 200): never {
    http_response_code($code);
    header('Content-Type: application/json');
    echo json_encode($payload);
    exit;
}

function fail(string $msg, int $code = 400): never {
    json_out(['ok' => false, 'message' => $msg], $code);
}

function ok_out(array $extra = []): never {
    json_out(['ok' => true] + $extra);
}

// ── CSRF ─────────────────────────────────────────────────────────────────────
$csrf = (string)($_POST['csrf'] ?? '');
if (empty($_SESSION['otp_csrf']) || !hash_equals((string)$_SESSION['otp_csrf'], $csrf)) {
    fail('Invalid session token. Refresh and try again.', 403);
}

$op          = strtolower(trim((string)($_POST['op'] ?? '')));
$ttl         = cfg_int($cfg, 'OTP_TTL_SECONDS',  120);
$maxAttempts = cfg_int($cfg, 'OTP_MAX_ATTEMPTS',  5);
if ($ttl <= 0)         $ttl         = 120;
if ($maxAttempts <= 0) $maxAttempts = 5;

$now = time();

// Guard: only allow the verify flow when otp_required is set
// (change_email is a housekeeping op that doesn't need the flag)
if (empty($_SESSION['otp_required']) && $op !== 'change_email') {
    fail('OTP not required for this session.', 400);
}

// ── SEND ─────────────────────────────────────────────────────────────────────
if ($op === 'send') {
    $email = trim((string)($_POST['email'] ?? ''));
    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        fail('Please enter a valid email address.');
    }

    $code = fixed_otp($cfg);

    $_SESSION['otp_email']    = $email;
    $_SESSION['otp_expires']  = $now + $ttl;
    $_SESSION['otp_attempts'] = 0;

    try {
        send_mail($email, 'Your OTP Code',
            "Your OTP code is: {$code}. It expires in {$ttl} seconds.");
    } catch (Throwable $e) {
        fail('Failed to send OTP email. Check SMTP env vars / mailer config.', 500);
    }

    ok_out(['message' => 'OTP sent.', 'email' => $email, 'expires_in' => $ttl]);
}

// ── RESEND ────────────────────────────────────────────────────────────────────
if ($op === 'resend') {
    $email = (string)($_SESSION['otp_email'] ?? '');
    if ($email === '') fail('No email set. Please enter your email first.');

    $code = fixed_otp($cfg);

    $_SESSION['otp_expires']  = $now + $ttl;
    $_SESSION['otp_attempts'] = 0;

    try {
        send_mail($email, 'Your OTP Code',
            "Your OTP code is: {$code}. It expires in {$ttl} seconds.");
    } catch (Throwable $e) {
        fail('Failed to send OTP email. Check SMTP env vars / mailer config.', 500);
    }

    ok_out(['message' => 'OTP resent.', 'email' => $email, 'expires_in' => $ttl]);
}

// ── CHANGE EMAIL ──────────────────────────────────────────────────────────────
if ($op === 'change_email') {
    unset($_SESSION['otp_email'], $_SESSION['otp_expires'], $_SESSION['otp_attempts']);
    ok_out(['message' => 'Enter a new email address.']);
}

// ── VERIFY ────────────────────────────────────────────────────────────────────
if ($op === 'verify') {
    $codeIn = preg_replace('/\s+/', '', (string)($_POST['code'] ?? ''));
    if ($codeIn === '') fail('Please enter the OTP.');

    $expires = (int)($_SESSION['otp_expires'] ?? 0);
    if ($expires <= 0 || $now >= $expires) {
        unset($_SESSION['otp_expires'], $_SESSION['otp_attempts']);
        fail('OTP expired. Please resend.');
    }

    $attempts = (int)($_SESSION['otp_attempts'] ?? 0);
    if ($attempts >= $maxAttempts) {
        fail('Too many attempts. Please resend OTP.');
    }

    if (!hash_equals(fixed_otp($cfg), preg_replace('/\D/', '', $codeIn))) {
        $_SESSION['otp_attempts'] = $attempts + 1;
        fail('Incorrect OTP.');
    }

    // ── SUCCESS ───────────────────────────────────────────────────────────
    // Clear ALL OTP state so the next enforce_action('OTP') call starts fresh.
    // We deliberately do NOT set otp_verified_until — that was causing OTP to
    // be skipped on subsequent triggers within the same session.
    unset(
        $_SESSION['otp_required'],
        $_SESSION['otp_expires'],
        $_SESSION['otp_attempts'],
        $_SESSION['otp_email'],
        $_SESSION['otp_csrf'],
        $_SESSION['otp_verified_until'] // remove any leftover from old code
    );

    // Build the redirect URL, stripping ?a=... so it doesn't re-trigger
    $redirect = (string)($_SESSION['return_after_otp'] ?? '/');
    unset($_SESSION['return_after_otp']);

    $parts = parse_url($redirect);
    $path  = $parts['path'] ?? '/';
    parse_str($parts['query'] ?? '', $q);
    unset($q['a']);
    $query    = http_build_query($q);
    $redirect = $query ? ($path . '?' . $query) : $path;

    ok_out(['message' => 'OTP verified.', 'redirect' => $redirect]);
}

fail('Unknown operation.');