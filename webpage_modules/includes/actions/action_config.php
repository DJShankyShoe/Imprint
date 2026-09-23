<?php

// reCAPTCHA keys from mitigation.env
require_once '/opt/imprint/env.php';

// POC honeypot runs on the same host, port 8443 - override with HONEYPOT_URL in mitigation.env
$honeypot_host = preg_replace('/:\d+$/', '', $_SERVER['HTTP_HOST'] ?? 'localhost');
$honeypot_url  = imprint_mitigation_env('HONEYPOT_URL') ?: 'https://' . $honeypot_host . ':8443/';

return [
  // ── Block ─────────────────────────────────────────────────────────────────
  'BLOCK_TTL_SECONDS'  => 15,
  'BLOCK_STORE'        => __DIR__ . '/block.json',
  'BLOCKED_URL'        => '/spacey/includes/actions/block_page.php',
  'BLOCK_FALLBACK_URL' => '/spacey/index.php',

  // ── Honeypot ──────────────────────────────────────────────────────────────
  'HONEYPOT_URL'         => $honeypot_url,
  'HONEYPOT_STORE'       => __DIR__ . '/honeypot.json',
  'HONEYPOT_TTL_SECONDS' => 15,
  'HONEYPOT_COOKIE_NAME' => 'hp',

  // ── Rate limit ────────────────────────────────────────────────────────────
  // Normal tracking window: user is allowed RATE_LIMIT_MAX_REQUESTS hits
  // within RATE_LIMIT_WINDOW_SECONDS before being put in penalty.
  'RATE_LIMIT_WINDOW_SECONDS'          => 60,   // sliding window for counting
  'RATE_LIMIT_MAX_REQUESTS'            => 6,    // max hits before penalty kicks in
  'RATE_LIMIT_PENALTY_WINDOW_SECONDS'  => 60,   // how long the penalty lasts
  'RATE_LIMIT_STORE'                   => __DIR__ . '/ratelimiting.json',
  'RATE_LIMIT_FALLBACK_URL'            => '/spacey/index.php',

  // ── OTP ───────────────────────────────────────────────────────────────────
  'OTP_FIXED_CODE'    => '123456',
  'OTP_TTL_SECONDS'   => 120,   // how long the sent code is valid
  'OTP_MAX_ATTEMPTS'  => 5,     // wrong-code attempts before requiring resend
  // NOTE: OTP_PASS_TTL / OTP_PASS_TTL_SECONDS intentionally omitted.
  // OTP must be completed fresh every time enforce_action('OTP') is called.
  'OTP_VERIFY_PATH'   => '/verify.php?type=otp',

  // ── reCAPTCHA v2 ──────────────────────────────────────────────────────────
  'RECAPTCHA_V2_SITEKEY'    => imprint_mitigation_env('RECAPTCHA_V2_SITEKEY', ''),
  'RECAPTCHA_V2_SECRET'     => imprint_mitigation_env('RECAPTCHA_V2_SECRET', ''),
  'CAPTCHA_VERIFY_PATH'     => '/verify.php?type=captcha',
  'CAPTCHA_TTL'             => 180,
];
