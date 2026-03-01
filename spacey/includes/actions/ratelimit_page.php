<?php
// includes/actions/ratelimit_page.php
// This is a UI-only page. It expects these variables from rate_limit.php:
// $rl_retryIn, $rl_penMax, $rl_penWindow, $rl_identifier, $rl_fallback_url

$retryIn    = isset($rl_retryIn) ? (int)$rl_retryIn : 0;
$penMax     = isset($rl_penMax) ? (int)$rl_penMax : 0;
$penWindow  = isset($rl_penWindow) ? (int)$rl_penWindow : 0;
$identifier = isset($rl_identifier) ? (string)$rl_identifier : '';
$fallback   = isset($rl_fallback_url) ? (string)$rl_fallback_url : '/spacey/index.php';

$safeId = htmlspecialchars($identifier, ENT_QUOTES, 'UTF-8');
$safeFallback = htmlspecialchars($fallback, ENT_QUOTES, 'UTF-8');
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Too Many Requests</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">

  <style>
    :root{
      --bg1:#0b1220;
      --bg2:#0f1b34;
      --text:#e5e7eb;
      --muted:#9ca3af;
      --line:rgba(255,255,255,.10);
      --warn:#f59e0b;
      --danger:#ef4444;
      --shadow: 0 18px 60px rgba(0,0,0,.45);
      --radius: 18px;
    }
    *{ box-sizing:border-box; }
    html,body{ height:100%; }
    body{
      margin:0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, "Apple Color Emoji","Segoe UI Emoji";
      color: var(--text);
      background:
        radial-gradient(1200px 600px at 20% 10%, rgba(245,158,11,.18), transparent 60%),
        radial-gradient(900px 500px at 80% 20%, rgba(239,68,68,.12), transparent 55%),
        linear-gradient(180deg, var(--bg1), var(--bg2));
      display:flex;
      align-items:center;
      justify-content:center;
      padding: 22px;
    }
    .wrap{ width: min(860px, 100%); }
    .card{
      background: linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03));
      border: 1px solid var(--line);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      overflow:hidden;
    }
    .header{
      display:flex;
      gap:14px;
      align-items:flex-start;
      padding: 22px 22px 14px;
      border-bottom: 1px solid var(--line);
      background: linear-gradient(180deg, rgba(245,158,11,.12), transparent);
    }
    .icon{
      width:44px; height:44px;
      border-radius: 14px;
      display:grid; place-items:center;
      background: rgba(245,158,11,.18);
      border: 1px solid rgba(245,158,11,.25);
      flex: 0 0 auto;
    }
    .title{
      margin:0;
      font-size: 20px;
      line-height: 1.2;
      letter-spacing: .2px;
    }
    .subtitle{
      margin:6px 0 0;
      color: var(--muted);
      font-size: 14px;
      line-height: 1.5;
    }
    .body{
      padding: 18px 22px 22px;
      display:grid;
      gap: 14px;
    }
    .row{
      display:flex;
      gap: 16px;
      flex-wrap:wrap;
      align-items:center;
      justify-content:space-between;
    }
    .pill{
      display:inline-flex;
      align-items:center;
      gap: 8px;
      padding: 10px 12px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: rgba(17,24,39,.35);
      color: var(--text);
      font-size: 14px;
    }
    .pill b{ font-variant-numeric: tabular-nums; }
    .progress{
      width: 100%;
      height: 10px;
      border-radius: 999px;
      background: rgba(255,255,255,.08);
      border: 1px solid var(--line);
      overflow:hidden;
    }
    .bar{
      height: 100%;
      width: 0%;
      background: linear-gradient(90deg, rgba(245,158,11,.9), rgba(239,68,68,.75));
      transition: width .25s linear;
    }
    .hint{
      color: var(--muted);
      font-size: 13px;
      line-height: 1.5;
      border-top: 1px solid var(--line);
      padding-top: 14px;
    }
    .code{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 12px;
      color: rgba(229,231,235,.9);
      background: rgba(0,0,0,.25);
      border: 1px solid var(--line);
      padding: 8px 10px;
      border-radius: 12px;
      overflow:auto;
      max-width: 100%;
    }
    .auto{
      color: var(--muted);
      font-size: 13px;
      display:flex;
      gap: 8px;
      align-items:center;
      justify-content:flex-end;
      white-space:nowrap;
    }
    @media (prefers-reduced-motion: reduce){
      .bar{ transition:none; }
    }
  </style>
</head>

<body>
  <div class="wrap">
    <div class="card" role="alert" aria-live="polite">
      <div class="header">
        <div class="icon" aria-hidden="true">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
            <path d="M12 2l7 4v6c0 5-3 9-7 10C8 21 5 17 5 12V6l7-4z" stroke="rgba(245,158,11,.95)" stroke-width="1.6"/>
            <path d="M9 12h6" stroke="rgba(239,68,68,.9)" stroke-width="1.6" stroke-linecap="round"/>
          </svg>
        </div>
        <div>
          <h1 class="title">Too many requests</h1>
          <p class="subtitle">
            You are in penalty mode. Please wait for the cooldown to finish.
            You will be returned automatically when the timer ends.
          </p>
        </div>
      </div>

      <div class="body">
        <div class="row">
          <div class="pill" title="Time remaining">
            <span aria-hidden="true">⏳</span>
            Try again in <b id="secs"><?= (int)$retryIn ?></b> seconds
          </div>
          <div class="auto">
            <span aria-hidden="true">⚠</span>
            Allowed <?= (int)$penMax ?> requests / <?= (int)$penWindow ?>s during penalty
          </div>
        </div>

        <div class="progress" aria-label="Cooldown progress">
          <div class="bar" id="bar"></div>
        </div>

        <div class="hint">
          Tip: avoid repeatedly refreshing or resubmitting the same action.
          <div class="code" style="margin-top:10px;">
            HTTP 429 • Identifier: <?= $safeId ?>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script>
    (function(){
      const start = Date.now();
      const initial = Number(document.getElementById('secs').textContent) || 0;
      const secsEl = document.getElementById('secs');
      const bar = document.getElementById('bar');

      function goBackOrFallback(){
        if (history.length > 1) history.back();
        else window.location.assign('<?= $safeFallback ?>');
      }

      // prevent loops: only auto-return once per cooldown end
      if (initial > 0) {
        sessionStorage.removeItem('rl_return_attempted');
      }

      function tick(){
        const elapsed = Math.floor((Date.now() - start)/1000);
        const remaining = Math.max(0, initial - elapsed);
        secsEl.textContent = String(remaining);

        const pct = initial > 0 ? Math.min(100, (elapsed / initial) * 100) : 100;
        bar.style.width = pct + '%';

        if (remaining <= 0){
          if (!sessionStorage.getItem('rl_return_attempted')) {
            sessionStorage.setItem('rl_return_attempted', '1');
            goBackOrFallback();
          }
          return;
        }

        requestAnimationFrame(() => setTimeout(tick, 250));
      }

      tick();
    })();
  </script>
</body>
</html>