<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// ── Bootstrap ────────────────────────────────────────────────────────────────
if (session_status() !== PHP_SESSION_ACTIVE) session_start();

require_once __DIR__ . '/enforce_action.php';   // pulls in action_engine, guards, combined_overlay
//require_once __DIR__ . '/action_engine.php';

// ── Global guards run automatically inside enforce_action.php on include ─────
// (block_guard, rate_limit_guard, honeypot_guard, combined_overlay check)

// ── Dispatch requested action(s) ─────────────────────────────────────────────
// Accept pipe-separated actions in ?a=  e.g. ?a=OTP|CAPTCHA
$rawAction = strtoupper(trim($_GET['a'] ?? ''));

if ($rawAction !== '') {
    run_action($rawAction, [
        'ip'         => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'route'      => 'action_test',
        'identifier' => session_id(),
    ]);

    // After flagging, check if a challenge overlay should appear
    require_once __DIR__ . '/combined_overlay.php';
    if (has_pending_challenges()) {
        render_combined_overlay();
        exit;
    }

    echo "<p>✅ Action executed: {$rawAction}</p>";
    exit;
}

// ── Test UI ───────────────────────────────────────────────────────────────────
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Action Test</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 700px; margin: 40px auto; padding: 0 20px; }
    h1   { margin-bottom: 6px; }
    p    { color: #555; margin: 0 0 16px; }
    ul   { list-style: none; padding: 0; display: flex; flex-wrap: wrap; gap: 10px; }
    li a {
      display: inline-block; padding: 10px 16px;
      background: #111827; color: #e5e7eb; border-radius: 8px;
      text-decoration: none; font-size: 14px;
    }
    li a:hover { background: #1f2937; }
    hr   { margin: 24px 0; border: none; border-top: 1px solid #e5e7eb; }
    .combo { margin-top: 20px; }
    .combo h2 { font-size: 16px; margin-bottom: 10px; }
  </style>
</head>
<body>

<h1>Action Test</h1>
<p>Session: <code><?= htmlspecialchars(session_id()) ?></code></p>
<hr>

<p>Single actions:</p>
<ul>
  <li><a href="?a=ALLOW">ALLOW</a></li>
  <li><a href="?a=RATE_LIMIT">RATE_LIMIT</a></li>
  <li><a href="?a=OTP">OTP</a></li>
  <li><a href="?a=CAPTCHA">CAPTCHA</a></li>
  <li><a href="?a=HONEYPOT">HONEYPOT</a></li>
  <li><a href="?a=BLOCK">BLOCK</a></li>
</ul>

<div class="combo">
  <h2>Combined actions (pipe-separated):</h2>
  <ul>
    <li><a href="?a=RATE_LIMIT|OTP">RATE_LIMIT + OTP</a></li>
    <li><a href="?a=CAPTCHA|OTP">CAPTCHA + OTP</a></li>
    <li><a href="?a=RATE_LIMIT|CAPTCHA">RATE_LIMIT + CAPTCHA</a></li>
    <li><a href="?a=RATE_LIMIT|CAPTCHA|OTP">RATE_LIMIT + CAPTCHA + OTP</a></li>
  </ul>
</div>

<hr>
<p style="font-size:13px; color:#888">
  BLOCK and HONEYPOT always run alone (they exit immediately).
</p>

</body>
</html>
<?php