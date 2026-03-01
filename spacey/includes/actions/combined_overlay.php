<?php
declare(strict_types=1);
/**
 * combined_overlay.php
 *
 * Single overlay that renders any active combination of:
 *   - Rate-limit countdown  ($_SESSION['rl_required'])
 *   - reCAPTCHA v2          ($_SESSION['captcha_required'])
 *   - OTP verification      ($_SESSION['otp_required'])
 *
 * Usage:
 *   require_once __DIR__ . '/combined_overlay.php';
 *   if (has_pending_challenges()) {
 *       render_combined_overlay();
 *       exit;
 *   }
 */

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Returns true when at least one challenge needs to be shown.
 */
function has_pending_challenges(): bool {
    // Rate-limit flag
    if (!empty($_SESSION['rl_required'])) {
        return true;
    }

    // CAPTCHA: required — no pass TTL, must be completed every time
    if (!empty($_SESSION['captcha_required'])) {
        return true;
    }

    // OTP: required (no "verified_until" skip — OTP must be completed every time it's triggered)
    if (!empty($_SESSION['otp_required'])) {
        return true;
    }

    return false;
}

/**
 * Renders the full combined overlay page.
 * Caller must exit() afterwards if page should not continue rendering.
 */
function render_combined_overlay(): void {
    $cfg = function_exists('action_cfg') ? action_cfg() : (require __DIR__ . '/action_config.php');

    // ── Which steps are active? ───────────────────────────────────────────────
    $showRL = !empty($_SESSION['rl_required']);

    // When rate-limit is active the other steps are visible but locked
    // until the cooldown ends — they are still "active" if flagged.
    $showCaptcha = !empty($_SESSION['captcha_required']);

    $showOtp = !empty($_SESSION['otp_required']);

    if (!$showRL && !$showCaptcha && !$showOtp) return;

    // ── Rate-limit data ───────────────────────────────────────────────────────
    $rlRetryIn   = (int)($_SESSION['rl_retry_in']   ?? 0);
    $rlPenMax    = (int)($_SESSION['rl_pen_max']    ?? 0);
    $rlPenWindow = (int)($_SESSION['rl_pen_window'] ?? 0);
    $rlId        = htmlspecialchars((string)($_SESSION['rl_identifier'] ?? ''), ENT_QUOTES, 'UTF-8');
    // Where to send the user after the penalty expires
    $rlReturnUrl = (string)($_SESSION['rl_return_url'] ?? ($_SERVER['HTTP_REFERER'] ?? '/'));

    // ── CAPTCHA data ──────────────────────────────────────────────────────────
    $siteKey       = $showCaptcha ? ($cfg['RECAPTCHA_V2_SITEKEY'] ?? '') : '';
    $capVerifyPath = htmlspecialchars(
        (string)($cfg['CAPTCHA_VERIFY_PATH'] ?? 'captcha_verify.php'), ENT_QUOTES, 'UTF-8'
    );

    // ── OTP data ──────────────────────────────────────────────────────────────
    $otpEmail      = '';
    $otpRemaining  = 0;
    $otpReturnUrl  = '/';
    $otpCsrf       = '';
    $otpVerifyPath = 'otp_verify.php';

    if ($showOtp) {
        if (empty($_SESSION['otp_csrf'])) {
            $_SESSION['otp_csrf'] = bin2hex(random_bytes(16));
        }
        $otpEmail = (string)($_SESSION['otp_email'] ?? '');
        $otpExpires = (int)($_SESSION['otp_expires'] ?? 0);
        $now = time();
        $otpTtl = max(1, (int)($cfg['OTP_TTL_SECONDS'] ?? 120));

        if ($otpExpires > 0 && $now >= $otpExpires) {
            unset($_SESSION['otp_expires'], $_SESSION['otp_attempts']);
            $otpExpires = 0;
        }
        $otpRemaining  = $otpExpires > 0 ? max(0, $otpExpires - $now) : 0;
        $otpReturnUrl  = (string)($_SESSION['return_after_otp'] ?? ($_SERVER['REQUEST_URI'] ?? '/'));
        $otpCsrf       = (string)$_SESSION['otp_csrf'];
        $otpVerifyPath = (string)($cfg['OTP_VERIFY_PATH'] ?? 'otp_verify.php');
    }

    // ── Title / subtitle ──────────────────────────────────────────────────────
    $activeCount = (int)$showRL + (int)$showCaptcha + (int)$showOtp;
    if ($activeCount > 1) {
        $title    = 'Security Checks Required';
        $subtitle = 'Complete the following steps to continue.';
    } elseif ($showRL) {
        $title    = 'Too Many Requests';
        $subtitle = 'You are in penalty mode. Please wait for the cooldown to finish.';
    } elseif ($showCaptcha) {
        $title    = 'Verification Required';
        $subtitle = 'Complete the CAPTCHA to continue.';
    } else {
        $title    = 'OTP Required';
        $subtitle = 'Enter the code sent to your email to continue.';
    }
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title><?= htmlspecialchars($title) ?></title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <?php if ($showCaptcha && $siteKey !== ''): ?>
  <script src="https://www.google.com/recaptcha/api.js" async defer></script>
  <?php endif; ?>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg1:#0b1220; --bg2:#0f1b34;
      --text:#e5e7eb; --muted:#9ca3af;
      --line:rgba(255,255,255,.10);
      --ok:#22c55e; --warn:#f59e0b; --danger:#ef4444;
      --radius:16px; --shadow:0 24px 72px rgba(0,0,0,.6);
    }
    body {
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      background:
        radial-gradient(1200px 600px at 20% 10%, rgba(245,158,11,.15), transparent 60%),
        radial-gradient(900px 500px  at 80% 20%, rgba(239,68,68,.10),  transparent 55%),
        linear-gradient(180deg, var(--bg1), var(--bg2));
      color: var(--text);
      min-height: 100vh;
      display: flex; align-items: center; justify-content: center;
      padding: 20px;
    }
    .card {
      width: min(560px, 100%);
      background: rgba(15,23,42,.97);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      overflow: hidden;
    }
    /* ── Header ── */
    .card-header {
      padding: 20px 22px 16px;
      border-bottom: 1px solid var(--line);
      background: linear-gradient(180deg, rgba(255,255,255,.04), transparent);
    }
    .card-header h1 { font-size: 20px; line-height: 1.2; }
    .card-header p  { margin-top: 6px; font-size: 14px; color: var(--muted); }
    /* ── Steps ── */
    .step {
      padding: 18px 22px;
      border-bottom: 1px solid var(--line);
    }
    .step:last-child { border-bottom: none; }
    .step-label {
      display: flex; align-items: center; gap: 10px;
      font-size: 12px; font-weight: 700; color: var(--muted);
      text-transform: uppercase; letter-spacing: .7px;
      margin-bottom: 14px;
    }
    .step-badge {
      width: 22px; height: 22px; border-radius: 50%; flex-shrink: 0;
      background: rgba(255,255,255,.08); border: 1px solid var(--line);
      display: grid; place-items: center; font-size: 11px; font-weight: 700;
    }
    .step-label.done { color: var(--ok); }
    .step-label.done .step-badge {
      background: rgba(34,197,94,.18); border-color: rgba(34,197,94,.35);
    }
    /* ── Rate-limit ── */
    .rl-row {
      display: flex; align-items: center; justify-content: space-between;
      flex-wrap: wrap; gap: 10px; margin-bottom: 12px;
    }
    .pill {
      display: inline-flex; align-items: center; gap: 8px;
      padding: 8px 12px; border-radius: 999px;
      border: 1px solid var(--line); background: rgba(17,24,39,.4);
      font-size: 14px;
    }
    .pill b { font-variant-numeric: tabular-nums; }
    .rl-hint { margin-top: 10px; font-size: 12px; color: var(--muted); }
    .progress {
      width: 100%; height: 8px; border-radius: 999px;
      background: rgba(255,255,255,.07); border: 1px solid var(--line); overflow: hidden;
    }
    .bar {
      height: 100%; width: 0%;
      background: linear-gradient(90deg, rgba(245,158,11,.9), rgba(239,68,68,.75));
      transition: width .25s linear;
    }
    /* ── Form elements ── */
    .field { margin-bottom: 12px; }
    .field label { display: block; font-size: 13px; color: var(--muted); margin-bottom: 6px; }
    .field input {
      width: 100%; padding: 10px 12px;
      border: 1px solid rgba(255,255,255,.15); border-radius: 10px;
      background: rgba(255,255,255,.05); color: var(--text); font-size: 15px;
      outline: none; transition: border-color .15s;
    }
    .field input:focus { border-color: rgba(255,255,255,.3); }
    .btn-row { display: flex; gap: 10px; margin-top: 10px; }
    .btn {
      flex: 1; padding: 10px 14px; border-radius: 10px;
      border: 1px solid rgba(255,255,255,.12); background: rgba(255,255,255,.06);
      color: var(--text); font-size: 14px; cursor: pointer;
      transition: background .15s, border-color .15s;
    }
    .btn:hover  { background: rgba(255,255,255,.10); border-color: rgba(255,255,255,.2); }
    .btn.primary { background: rgba(255,255,255,.12); border-color: rgba(255,255,255,.22); font-weight: 600; }
    .btn.primary:hover { background: rgba(255,255,255,.18); }
    /* ── Messages ── */
    .msg { display: none; padding: 10px 12px; border-radius: 8px; font-size: 13px; margin-bottom: 12px; }
    .msg.ok  { display: block; background: rgba(34,197,94,.12); border: 1px solid rgba(34,197,94,.3);  color: #86efac; }
    .msg.err { display: block; background: rgba(239,68,68,.12);  border: 1px solid rgba(239,68,68,.3);  color: #fca5a5; }
    /* ── OTP meta ── */
    .otp-meta { font-size: 13px; color: var(--muted); min-height: 18px; margin-bottom: 10px; }
    /* ── Locked overlay for steps blocked by RL ── */
    .step-locked { opacity: .35; pointer-events: none; user-select: none; }
  </style>
</head>
<body>
<div class="card" role="dialog" aria-modal="true" aria-label="<?= htmlspecialchars($title) ?>">

  <div class="card-header">
    <h1><?= htmlspecialchars($title) ?></h1>
    <p><?= htmlspecialchars($subtitle) ?></p>
  </div>

  <?php $stepNum = 0; ?>

  <?php /* ══ STEP: RATE LIMIT ══════════════════════════════════════════════ */ ?>
  <?php if ($showRL): $stepNum++; ?>
  <div class="step" id="step-rl">
    <?php if ($activeCount > 1): ?>
    <div class="step-label" id="rl-label">
      <span class="step-badge" id="rl-badge"><?= $stepNum ?></span>
      Wait for cooldown
    </div>
    <?php endif; ?>

    <div class="rl-row">
      <div class="pill">⏳ Try again in <b id="rl-secs"><?= $rlRetryIn ?></b>s</div>
      <span style="font-size:12px; color:var(--muted)">
        Limit: <?= $rlPenMax ?> req / <?= $rlPenWindow ?>s
      </span>
    </div>
    <div class="progress"><div class="bar" id="rl-bar"></div></div>
    <div class="rl-hint">Avoid rapidly refreshing or resubmitting the same action.</div>
  </div>
  <?php endif; ?>

  <?php /* ══ STEP: CAPTCHA ════════════════════════════════════════════════ */ ?>
  <?php if ($showCaptcha): $stepNum++; ?>
  <div class="step <?= $showRL ? 'step-locked' : '' ?>" id="step-captcha">
    <?php if ($activeCount > 1): ?>
    <div class="step-label" id="captcha-label">
      <span class="step-badge" id="captcha-badge"><?= $stepNum ?></span>
      Complete CAPTCHA
    </div>
    <?php endif; ?>

    <div id="captcha-msg" class="msg"></div>

    <?php if ($siteKey !== ''): ?>
    <div class="g-recaptcha"
         id="captcha-widget"
         data-sitekey="<?= htmlspecialchars($siteKey) ?>"
         data-callback="onCaptchaSolved"
         data-expired-callback="onCaptchaExpired"
         data-error-callback="onCaptchaError">
    </div>
    <?php else: ?>
    <div class="msg err" style="display:block">
      Missing RECAPTCHA_V2_SITEKEY in action_config.php.
    </div>
    <?php endif; ?>
  </div>
  <?php endif; ?>

  <?php /* ══ STEP: OTP ════════════════════════════════════════════════════ */ ?>
  <?php if ($showOtp): $stepNum++; ?>
  <div class="step <?= $showRL ? 'step-locked' : '' ?>" id="step-otp">
    <?php if ($activeCount > 1): ?>
    <div class="step-label" id="otp-label">
      <span class="step-badge" id="otp-badge"><?= $stepNum ?></span>
      Verify via OTP
    </div>
    <?php endif; ?>

    <div id="otp-msg" class="msg"></div>

    <div class="otp-meta">
      <span id="otp-sent-line"    style="display:none">
        Sent to <strong id="otp-email-label"></strong>.
        <span id="otp-expire-label"></span>
      </span>
      <span id="otp-not-sent-line" style="display:none; font-size:12px">
        Enter your email to receive an OTP.
      </span>
    </div>

    <div id="otp-email-block" style="display:none">
      <div class="field">
        <label for="otp-email">Email</label>
        <input id="otp-email" type="email" placeholder="name@example.com"
               value="<?= htmlspecialchars($otpEmail) ?>">
      </div>
      <div class="btn-row">
        <button class="btn primary" id="otp-send-btn">Send OTP</button>
      </div>
    </div>

    <div id="otp-code-block" style="display:none">
      <div class="field">
        <label for="otp-code">6-digit code</label>
        <input id="otp-code" inputmode="numeric" autocomplete="one-time-code" placeholder="123456">
      </div>
      <div class="btn-row">
        <button class="btn primary" id="otp-verify-btn">Verify OTP</button>
      </div>
      <div class="btn-row" style="margin-top:6px">
        <button class="btn" id="otp-resend-btn">Resend</button>
        <button class="btn" id="otp-change-btn">Change Email</button>
      </div>
    </div>

    <input type="hidden" id="otp-csrf"   value="<?= htmlspecialchars($otpCsrf) ?>">
    <input type="hidden" id="otp-return" value="<?= htmlspecialchars($otpReturnUrl) ?>">
  </div>
  <?php endif; ?>

</div><!-- /.card -->

<script>
(function () {
  'use strict';

  const ACTIVE_COUNT  = <?= (int)$activeCount ?>;
  const SHOW_RL       = <?= $showRL      ? 'true' : 'false' ?>;
  const SHOW_CAPTCHA  = <?= $showCaptcha ? 'true' : 'false' ?>;
  const SHOW_OTP      = <?= $showOtp     ? 'true' : 'false' ?>;

  let captchaDone = false;
  let otpDone     = false;

  // ── Helpers ───────────────────────────────────────────────────────────────
  function markStepDone(labelId, badgeId) {
    if (ACTIVE_COUNT <= 1) return;
    const lbl   = document.getElementById(labelId);
    const badge = document.getElementById(badgeId);
    if (lbl)   lbl.classList.add('done');
    if (badge) badge.textContent = '✓';
  }

  function unlockStep(stepId) {
    const el = document.getElementById(stepId);
    if (el) el.classList.remove('step-locked');
  }

  // Redirect helper — strips ?a= from URL
  function redirectTo(url) {
    try {
      const u = new URL(url, window.location.href);
      u.searchParams.delete('a');
      window.location.replace(u.toString());
    } catch (_) {
      window.location.replace(url || '/');
    }
  }

  function checkAllDone(otpRedirect) {
    const capOk = !SHOW_CAPTCHA || captchaDone;
    const otpOk = !SHOW_OTP     || otpDone;
    if (capOk && otpOk) {
      const dest = otpRedirect
                || document.getElementById('otp-return')?.value
                || window.location.href;
      redirectTo(dest);
    }
  }

  // ════════════════════════════════════════════════════════════════════════
  // RATE LIMIT COUNTDOWN
  // ════════════════════════════════════════════════════════════════════════
  if (SHOW_RL) {
    const initial      = <?= $rlRetryIn ?>;
    const RL_RETURN    = <?= json_encode($rlReturnUrl) ?>;
    const start        = Date.now();
    const secsEl       = document.getElementById('rl-secs');
    const bar          = document.getElementById('rl-bar');

    function tick() {
      const elapsed   = Math.floor((Date.now() - start) / 1000);
      const remaining = Math.max(0, initial - elapsed);
      secsEl.textContent = String(remaining);
      bar.style.width    = Math.min(100, initial > 0 ? (elapsed / initial) * 100 : 100) + '%';

      if (remaining <= 0) {
        markStepDone('rl-label', 'rl-badge');
        unlockStep('step-captcha');
        unlockStep('step-otp');

        if (!SHOW_CAPTCHA && !SHOW_OTP) {
          // Penalty is the only challenge — redirect back to where the user was.
          // The guard will clear the session flag on that next request.
          redirectTo(RL_RETURN || window.location.href);
        }
        // If other challenges are also active, just unlock them (checkAllDone
        // will redirect once they're completed).
        return;
      }
      requestAnimationFrame(() => setTimeout(tick, 250));
    }
    tick();
  }

  // ════════════════════════════════════════════════════════════════════════
  // CAPTCHA
  // ════════════════════════════════════════════════════════════════════════
  if (SHOW_CAPTCHA) {
    const VERIFY_URL = <?= json_encode($capVerifyPath) ?>;

    window.onCaptchaSolved = async function (token) {
      const msgEl = document.getElementById('captcha-msg');
      msgEl.className = 'msg'; msgEl.textContent = '';

      try {
        const resp = await fetch(VERIFY_URL, {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token })
        });

        let data;
        try { data = await resp.json(); }
        catch (_) { throw new Error('Non-JSON response from verify endpoint.'); }

        if (!resp.ok || !data.ok) {
          throw new Error(data.error || 'Verification failed (HTTP ' + resp.status + ').');
        }

        captchaDone = true;
        markStepDone('captcha-label', 'captcha-badge');
        msgEl.className = 'msg ok';
        msgEl.textContent = '✓ CAPTCHA passed.';
        checkAllDone();

      } catch (e) {
        const msgEl2 = document.getElementById('captcha-msg');
        msgEl2.className = 'msg err';
        msgEl2.textContent = e.message || 'CAPTCHA verification error.';
        if (window.grecaptcha) grecaptcha.reset();
      }
    };

    window.onCaptchaExpired = function () {
      captchaDone = false;
      const msgEl = document.getElementById('captcha-msg');
      msgEl.className = 'msg err';
      msgEl.textContent = 'CAPTCHA expired. Please solve it again.';
    };

    window.onCaptchaError = function () {
      // Widget-level error (e.g. invalid domain, network failure).
      // Show a helpful message but do NOT block OTP if it's also active.
      const msgEl = document.getElementById('captcha-msg');
      msgEl.className = 'msg err';
      msgEl.textContent = 'CAPTCHA failed to load. Check that your domain is registered '
                        + 'in the Google reCAPTCHA console, then refresh.';
      captchaDone = false;
      // If OTP is also required, don't hold it hostage to CAPTCHA being broken
      if (SHOW_OTP) unlockStep('step-otp');
    };
  }

  // ════════════════════════════════════════════════════════════════════════
  // OTP
  // ════════════════════════════════════════════════════════════════════════
  if (SHOW_OTP) {
    const OTP_VERIFY_URL = <?= json_encode($otpVerifyPath) ?>;

    const emailBlock  = document.getElementById('otp-email-block');
    const codeBlock   = document.getElementById('otp-code-block');
    const emailInput  = document.getElementById('otp-email');
    const codeInput   = document.getElementById('otp-code');
    const sentLine    = document.getElementById('otp-sent-line');
    const notSentLine = document.getElementById('otp-not-sent-line');
    const emailLabel  = document.getElementById('otp-email-label');
    const expireLbl   = document.getElementById('otp-expire-label');
    const msgBox      = document.getElementById('otp-msg');
    const csrf        = document.getElementById('otp-csrf').value;

    let currentEmail = <?= json_encode($otpEmail) ?>;
    let remaining    = <?= (int)$otpRemaining ?>;

    function setMsg(kind, text) {
      msgBox.className = 'msg';
      msgBox.textContent = '';
      if (!text) return;
      msgBox.classList.add(kind === 'ok' ? 'ok' : 'err');
      msgBox.textContent = text;
    }

    function updateExpire() {
      expireLbl.textContent = remaining > 0 ? ` Expires in ${remaining}s.` : '';
    }

    function showEmailUI() {
      emailBlock.style.display  = 'block';
      codeBlock.style.display   = 'none';
      sentLine.style.display    = 'none';
      notSentLine.style.display = 'inline';
      setMsg('', '');
      setTimeout(() => emailInput.focus(), 50);
    }

    function showCodeUI() {
      emailBlock.style.display  = 'none';
      codeBlock.style.display   = 'block';
      notSentLine.style.display = 'none';
      sentLine.style.display    = 'inline';
      emailLabel.textContent    = currentEmail || '';
      updateExpire();
      setTimeout(() => codeInput.focus(), 50);
    }

    // Countdown timer
    const rlTimer = setInterval(() => {
      if (remaining > 0) remaining--;
      updateExpire();
      if (remaining <= 0) clearInterval(rlTimer);
    }, 1000);

    // Init
    if (!currentEmail) showEmailUI(); else showCodeUI();

    async function otpApi(op, extra = {}) {
      const fd = new FormData();
      fd.set('op', op);
      fd.set('csrf', csrf);
      for (const [k, v] of Object.entries(extra)) fd.set(k, v);
      const resp = await fetch(OTP_VERIFY_URL, {
        method: 'POST', body: fd,
        headers: { 'X-Requested-With': 'XMLHttpRequest' }
      });
      return resp.json().catch(() => ({ ok: false, message: 'Bad server response.' }));
    }

    document.getElementById('otp-send-btn').addEventListener('click', async () => {
      const email = (emailInput.value || '').trim();
      if (!email) return setMsg('err', 'Please enter an email.');
      const r = await otpApi('send', { email });
      if (!r.ok) return setMsg('err', r.message || 'Failed to send OTP.');
      currentEmail = r.email || email;
      remaining    = r.expires_in || 0;
      setMsg('ok', r.message || 'OTP sent.');
      showCodeUI();
    });

    document.getElementById('otp-resend-btn').addEventListener('click', async () => {
      const r = await otpApi('resend');
      if (!r.ok) return setMsg('err', r.message || 'Failed to resend OTP.');
      remaining = r.expires_in || 0;
      setMsg('ok', r.message || 'OTP resent.');
      showCodeUI();
    });

    document.getElementById('otp-change-btn').addEventListener('click', async () => {
      const r = await otpApi('change_email');
      if (!r.ok) return setMsg('err', r.message || 'Failed.');
      currentEmail = '';
      remaining    = 0;
      setMsg('ok', r.message || 'Enter a new email.');
      showEmailUI();
    });

    document.getElementById('otp-verify-btn').addEventListener('click', async () => {
      const code = (codeInput.value || '').trim();
      if (!code) return setMsg('err', 'Please enter the OTP.');
      const r = await otpApi('verify', { code });
      if (!r.ok) return setMsg('err', r.message || 'OTP verification failed.');
      otpDone = true;
      markStepDone('otp-label', 'otp-badge');
      setMsg('ok', '✓ OTP verified.');
      checkAllDone(r.redirect);
    });
  }

})();
</script>
</body>
</html>
<?php
} // end render_combined_overlay()