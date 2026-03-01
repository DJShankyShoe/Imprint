<?php
declare(strict_types=1);

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

$cfg = require __DIR__ . '/action_config.php';

// Show overlay only when OTP is required
//$required = !empty($_SESSION['otp_required']);
//if (!$required) return;

$required = !empty($_SESSION['otp_required']);
$verifiedUntil = (int)($_SESSION['otp_verified_until'] ?? 0);
$verified = ($verifiedUntil > time());

// show overlay only if required AND not currently verified
if (!$required || $verified) return;




// CSRF token for overlay actions
if (empty($_SESSION['otp_csrf'])) {
    $_SESSION['otp_csrf'] = bin2hex(random_bytes(16));
}

$email   = (string)($_SESSION['otp_email'] ?? '');
$expires = (int)($_SESSION['otp_expires'] ?? 0);
$now     = time();

$ttl = (int)($cfg['OTP_TTL_SECONDS'] ?? 120);
if ($ttl <= 0) $ttl = 120;

// If expired, clear expiry state (but keep otp_required so overlay remains)
if ($expires > 0 && $now >= $expires) {
    unset($_SESSION['otp_expires'], $_SESSION['otp_attempts']);
    $expires = 0;
    $_SESSION['otp_info'] = 'OTP expired. Please resend.';
}

$info  = (string)($_SESSION['otp_info'] ?? '');
$error = (string)($_SESSION['otp_error'] ?? '');
unset($_SESSION['otp_info'], $_SESSION['otp_error']);

$remaining = $expires > 0 ? max(0, $expires - $now) : 0;

// Optional: where to go after success (verify endpoint will handle redirect)
$returnUrl = (string)($_SESSION['return_after_otp'] ?? ($_SERVER['REQUEST_URI'] ?? '/'));
?>
<style>
#otp-modal-backdrop{
  position:fixed; inset:0; background:rgba(0,0,0,.55);
  display:flex; align-items:center; justify-content:center;
  z-index:99999;
}
#otp-modal{
  width:min(560px, 92vw); background:#fff; border-radius:10px;
  box-shadow:0 10px 40px rgba(0,0,0,.35);
  padding:22px 22px 18px; font-family:system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
}
#otp-modal h2{ margin:0 0 6px; font-size:22px; }
#otp-modal p{ margin:0 0 14px; color:#444; }
#otp-msg{ margin:10px 0 12px; padding:10px 12px; border-radius:8px; display:none; }
#otp-msg.ok{ background:#e8f7ee; color:#14532d; border:1px solid #bbf7d0; display:block; }
#otp-msg.err{ background:#fdecec; color:#7f1d1d; border:1px solid #fecaca; display:block; }

.otp-row{ margin:10px 0; }
.otp-row label{ display:block; font-size:13px; margin:0 0 6px; color:#333; }
.otp-row input{
  width:100%; padding:10px 12px; border:1px solid #cfcfcf; border-radius:8px;
  font-size:15px;
}
.otp-actions{ display:flex; gap:10px; margin-top:12px; }
.otp-actions button{
  flex:1; padding:10px 12px; border:1px solid #cfcfcf; background:#f6f6f6;
  border-radius:8px; cursor:pointer; font-size:14px;
}
.otp-actions button.primary{
  background:#111827; border-color:#111827; color:#fff;
}
.otp-meta{ margin-top:8px; font-size:13px; color:#555; }
.otp-split{ display:flex; gap:10px; }
.otp-split button{ flex:1; }
.otp-small{ font-size:12px; color:#666; }
</style>

<div id="otp-modal-backdrop" aria-modal="true" role="dialog">
  <div id="otp-modal">
    <h2>OTP Required</h2>
    <p>Enter the code sent to your email to continue.</p>

    <div id="otp-msg"></div>

    <div class="otp-meta">
      <span id="otp-sent-line" style="display:none;">
        Sent to <strong id="otp-email-label"></strong>.
        <span id="otp-expire-label"></span>
      </span>
      <span id="otp-not-sent-line" class="otp-small" style="display:none;">
        Enter your email to receive an OTP.
      </span>
    </div>

    <div id="otp-email-block" class="otp-row" style="display:none;">
      <label for="otp-email">Email</label>
      <input id="otp-email" type="email" placeholder="name@example.com" value="<?= htmlspecialchars($email) ?>">
      <div class="otp-actions">
        <button class="primary" id="otp-send-btn">Send OTP</button>
      </div>
    </div>

    <div id="otp-code-block" style="display:none;">
      <div class="otp-row">
        <label for="otp-code">OTP</label>
        <input id="otp-code" inputmode="numeric" autocomplete="one-time-code" placeholder="6-digit code">
      </div>

      <div class="otp-actions">
        <button class="primary" id="otp-verify-btn">Verify</button>
      </div>

      <div class="otp-actions otp-split">
        <button id="otp-resend-btn">Resend</button>
        <button id="otp-change-btn">Change Email</button>
      </div>
    </div>

    <input type="hidden" id="otp-csrf" value="<?= htmlspecialchars($_SESSION['otp_csrf']) ?>">
    <input type="hidden" id="otp-return" value="<?= htmlspecialchars($returnUrl) ?>">
  </div>
</div>

<script>
(() => {
  const msgBox = document.getElementById('otp-msg');

  const emailBlock = document.getElementById('otp-email-block');
  const codeBlock  = document.getElementById('otp-code-block');

  const emailInput = document.getElementById('otp-email');
  const codeInput  = document.getElementById('otp-code');

  const sentLine   = document.getElementById('otp-sent-line');
  const notSentLine= document.getElementById('otp-not-sent-line');
  const emailLabel = document.getElementById('otp-email-label');
  const expireLbl  = document.getElementById('otp-expire-label');

  const csrf = document.getElementById('otp-csrf').value;

  // initial state from PHP
  let currentEmail = <?= json_encode($email) ?>;
  let remaining    = <?= (int)$remaining ?>;

  function setMsg(kind, text){
    msgBox.className = '';
    msgBox.textContent = '';
    msgBox.style.display = 'none';
    if (!text) return;
    msgBox.classList.add(kind === 'ok' ? 'ok' : 'err');
    msgBox.textContent = text;
    msgBox.style.display = 'block';
  }

  function showEmailUI(){
    emailBlock.style.display = 'block';
    codeBlock.style.display  = 'none';
    sentLine.style.display   = 'none';
    notSentLine.style.display= 'inline';
    setMsg('', '');
    setTimeout(() => emailInput.focus(), 50);
  }

  function showCodeUI(){
    emailBlock.style.display = 'none';
    codeBlock.style.display  = 'block';
    notSentLine.style.display= 'none';
    sentLine.style.display   = 'inline';
    emailLabel.textContent   = currentEmail || '';
    updateExpireLabel();
    setTimeout(() => codeInput.focus(), 50);
  }

  function updateExpireLabel(){
    if (remaining > 0) {
      expireLbl.textContent = ` Expires in ${remaining}s.`;
    } else {
      expireLbl.textContent = '';
    }
  }

  async function api(op, extra = {}){
    const fd = new FormData();
    fd.set('op', op);
    fd.set('csrf', csrf);
    for (const [k,v] of Object.entries(extra)) fd.set(k, v);

    const res = await fetch('<?= htmlspecialchars((string)($cfg['OTP_VERIFY_PATH'] ?? 'otp_verify.php')) ?>', {
      method: 'POST',
      body: fd,
      headers: { 'X-Requested-With': 'XMLHttpRequest' }
    });

    const data = await res.json().catch(() => ({ ok:false, message:'Bad response from server.' }));
    return data;
  }

  // countdown
  if (remaining > 0) {
    setInterval(() => {
      if (remaining > 0) remaining--;
      updateExpireLabel();
    }, 1000);
  }

  // hydrate message from server
  const initialInfo  = <?= json_encode($info) ?>;
  const initialError = <?= json_encode($error) ?>;
  if (initialError) setMsg('err', initialError);
  else if (initialInfo) setMsg('ok', initialInfo);

  // initial UI choice
  if (!currentEmail) showEmailUI();
  else showCodeUI();

  document.getElementById('otp-send-btn').addEventListener('click', async () => {
    const email = (emailInput.value || '').trim();
    if (!email) return setMsg('err', 'Please enter an email.');
    const r = await api('send', { email });
    if (!r.ok) return setMsg('err', r.message || 'Failed to send OTP.');
    currentEmail = r.email || email;
    remaining = r.expires_in || 0;
    setMsg('ok', r.message || 'OTP sent.');
    showCodeUI();
  });

  document.getElementById('otp-resend-btn').addEventListener('click', async () => {
    const r = await api('resend');
    if (!r.ok) return setMsg('err', r.message || 'Failed to resend OTP.');
    remaining = r.expires_in || 0;
    setMsg('ok', r.message || 'OTP resent.');
    showCodeUI();
  });

  document.getElementById('otp-change-btn').addEventListener('click', async () => {
    const r = await api('change_email');
    if (!r.ok) return setMsg('err', r.message || 'Failed.');
    currentEmail = '';
    remaining = 0;
    setMsg('ok', r.message || 'Enter a new email.');
    showEmailUI();
  });

  document.getElementById('otp-verify-btn').addEventListener('click', async () => {
    const code = (codeInput.value || '').trim();
    if (!code) return setMsg('err', 'Please enter the OTP.');
    const r = await api('verify', { code });
    if (!r.ok) return setMsg('err', r.message || 'OTP verification failed.');
    // success: redirect
    const url = r.redirect || document.getElementById('otp-return').value || '/';
    window.location.assign(url);
  });
})();
</script>