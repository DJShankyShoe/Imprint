<?php
if (session_status() !== PHP_SESSION_ACTIVE) session_start();

// Values passed from block.php
$retryIn = isset($block_retryIn) ? (int)$block_retryIn : 0;

// Fallback if no history
$goBackUrl = isset($block_fallback_url) ? (string)$block_fallback_url : '/spacey/index.php';
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Access Blocked</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">

  <style>
    :root{
      --bg1:#0b1220;
      --bg2:#0f1b34;
      --card:#0f172a;
      --card2:#111c33;
      --text:#e5e7eb;
      --muted:#9ca3af;
      --danger:#ef4444;
      --warn:#f59e0b;
      --line:rgba(255,255,255,.10);
      --btn:#1f2937;
      --btnHover:#273449;
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
        radial-gradient(1200px 600px at 20% 10%, rgba(239,68,68,.18), transparent 60%),
        radial-gradient(900px 500px at 80% 20%, rgba(245,158,11,.16), transparent 55%),
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
      background: linear-gradient(180deg, rgba(239,68,68,.10), transparent);
    }

    .icon{
      width:44px; height:44px;
      border-radius: 14px;
      display:grid; place-items:center;
      background: rgba(239,68,68,.18);
      border: 1px solid rgba(239,68,68,.25);
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

    .pill b{
      font-variant-numeric: tabular-nums;
      font-size: 14px;
    }

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
      background: linear-gradient(90deg, rgba(239,68,68,.9), rgba(245,158,11,.9));
      transition: width .25s linear;
    }

    .actions{
      display:flex;
      gap: 10px;
      flex-wrap:wrap;
      margin-top: 4px;
    }

    .btn{
      appearance:none;
      border: 1px solid var(--line);
      background: rgba(31,41,55,.55);
      color: var(--text);
      padding: 10px 14px;
      border-radius: 12px;
      text-decoration:none;
      font-size: 14px;
      display:inline-flex;
      gap: 8px;
      align-items:center;
      cursor:pointer;
      transition: transform .06s ease, background .15s ease, border-color .15s ease, opacity .15s ease;
      user-select:none;
    }
    .btn:hover{ background: rgba(39,52,73,.65); border-color: rgba(255,255,255,.16); }
    .btn:active{ transform: translateY(1px); }

    /* NEW: disabled state */
    .btn[disabled]{
      opacity: .55;
      cursor: not-allowed;
      transform: none !important;
    }
    .btn[disabled]:hover{
      background: rgba(31,41,55,.55);
      border-color: var(--line);
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

    @media (prefers-reduced-motion: reduce){
      .bar{ transition:none; }
      .btn{ transition:none; }
    }
  </style>
</head>

<body>
  <div class="wrap">
    <div class="card" role="alert" aria-live="polite">
      <div class="header">
        <div class="icon" aria-hidden="true">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
            <path d="M12 2l7 4v6c0 5-3 9-7 10C8 21 5 17 5 12V6l7-4z" stroke="rgba(239,68,68,.95)" stroke-width="1.6"/>
            <path d="M9 12h6" stroke="rgba(245,158,11,.95)" stroke-width="1.6" stroke-linecap="round"/>
          </svg>
        </div>
        <div>
          <h1 class="title">Access blocked</h1>
          <p class="subtitle">
            Your session has been temporarily restricted due to security rules.
            You can try again once the cooldown ends.
          </p>
        </div>
      </div>

      <div class="body">
        <div class="row">
          <div class="pill" title="Time remaining">
            <span aria-hidden="true">⏳</span>
            Try again in <b id="secs"><?= (int)$retryIn ?></b> seconds
          </div>

          <div class="actions">
            <!-- CHANGED: Go back exists but starts disabled -->
            <button class="btn" type="button" id="backBtn" disabled>
              <span aria-hidden="true">↩</span> Go back
            </button>
          </div>
        </div>

        <div class="progress" aria-label="Cooldown progress">
          <div class="bar" id="bar"></div>
        </div>

        <div class="hint">
          If you believe this is a mistake, wait for the timer to finish.
          Avoid rapidly refreshing or repeating the same request.
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
      const backBtn = document.getElementById('backBtn');

      function goBackOrFallback(){
        if (history.length > 1) history.back();
        else window.location.assign('<?= htmlspecialchars($goBackUrl) ?>');
      }

      // Prevent infinite loops: only auto-go-back once per cooldown end.
      if (initial > 0) {
        sessionStorage.removeItem('block_return_attempted');
      }

      backBtn.addEventListener('click', () => {
        // extra safety: don't allow clicks early
        if (backBtn.disabled) return;
        goBackOrFallback();
      });

      function tick(){
        const elapsed = Math.floor((Date.now() - start)/1000);
        const remaining = Math.max(0, initial - elapsed);
        secsEl.textContent = String(remaining);

        const pct = initial > 0 ? Math.min(100, (elapsed / initial) * 100) : 100;
        bar.style.width = pct + '%';

        if (remaining <= 0){
          // Enable the button once time is up
          backBtn.disabled = false;

          // Auto go back once
          if (!sessionStorage.getItem('block_return_attempted')) {
            sessionStorage.setItem('block_return_attempted', '1');
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