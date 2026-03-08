<?php

return [
  // ── Block ─────────────────────────────────────────────────────────────────
  'BLOCK_TTL_SECONDS'  => 15,
  'BLOCK_STORE'        => __DIR__ . '/block.json',
  'BLOCKED_URL'        => '/spacey/includes/actions/block_page.php',
  'BLOCK_FALLBACK_URL' => '/spacey/index.php',

  // ── Honeypot ──────────────────────────────────────────────────────────────
  'HONEYPOT_URL'         => 'https://zebrapal.ddns.net/',
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
  'RECAPTCHA_V2_SITEKEY'    => '6LcDunwsAAAAAK6upTOxEVqfUZC2mijDgmZEx40V',
  'RECAPTCHA_V2_SECRET'     => '6LcDunwsAAAAAOb7pV19LgoW8nztSUUSyWmYje0d',
  'CAPTCHA_VERIFY_PATH'     => '/verify.php?type=captcha',
  'CAPTCHA_TTL'             => 180,
];
