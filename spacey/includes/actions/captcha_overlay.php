<?php

if (session_status() === PHP_SESSION_NONE) session_start();

if (!function_exists('action_captcha')) {
    function action_captcha(array $ctx = []): void
    {
        // Load config either from ctx or from action_config
        $cfg = $ctx['cfg'] ?? (require __DIR__ . '/action_config.php');

        $siteKey = $cfg['RECAPTCHA_V2_SITEKEY'] ?? '';
        if ($siteKey === '') {
            echo "<div style='color:#b00020'>Missing RECAPTCHA_V2_SITEKEY in action_config.php</div>";
            return;
        }

        // IMPORTANT: action_test.php is at /spacey/includes/actions/action_test.php
        // dirname(SCRIPT_NAME) => /spacey/includes/actions
        $basePath  = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/');
        $verifyUrl = $basePath . '/captcha_verify.php';
        ?>
        <style>
            .overlay-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center;z-index:9999}
            .overlay-card{background:#fff;max-width:680px;width:90%;padding:28px;border-radius:14px}
            .overlay-error{color:#b00020;margin-top:10px;display:none;white-space:pre-wrap}
        </style>

        <div class="overlay-backdrop" id="captchaOverlay">
            <div class="overlay-card">
                <h2 style="margin:0 0 8px 0">Verification Required</h2>
                <p style="margin:0 0 14px 0">Complete the CAPTCHA to continue.</p>

                <div class="g-recaptcha"
                     data-sitekey="<?php echo htmlspecialchars($siteKey); ?>"
                     data-callback="onCaptchaSolved"
                     data-expired-callback="onCaptchaExpired"
                     data-error-callback="onCaptchaError"></div>

                <div class="overlay-error" id="verifyError"></div>
            </div>
        </div>

        <script>
            const VERIFY_URL = <?php echo json_encode($verifyUrl); ?>;

            async function onCaptchaSolved(token) {
                const errEl = document.getElementById('verifyError');
                errEl.style.display = 'none';
                errEl.textContent = '';

                try {
                    const resp = await fetch(VERIFY_URL, {
                        method: 'POST',
                        credentials: 'same-origin', // make sure session cookie is sent
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ token })
                    });

                    const raw = await resp.text();
                    if (!raw) {
                        throw new Error(`Empty response (HTTP ${resp.status}). Check VERIFY_URL: ${VERIFY_URL}`);
                    }

                    let data;
                    try { data = JSON.parse(raw); }
                    catch (e) { throw new Error(`Non-JSON (HTTP ${resp.status}): ${raw.slice(0,200)}`); }

                    if (!resp.ok || !data.ok) {
                        throw new Error(data.error || ('HTTP ' + resp.status));
                    }

                    // Success -> remove overlay + reload WITHOUT forcing captcha action again
                    document.getElementById('captchaOverlay').remove();

                    const url = new URL(window.location.href);
                    url.searchParams.delete('a'); // stops action_test loop
                    window.location.replace(url.toString());
                } catch (e) {
                    errEl.textContent = e.message || String(e);
                    errEl.style.display = 'block';
                    if (window.grecaptcha) grecaptcha.reset();
                }
            }

            function onCaptchaExpired() {}
            function onCaptchaError() {
                const errEl = document.getElementById('verifyError');
                errEl.textContent = 'CAPTCHA error. Please try again.';
                errEl.style.display = 'block';
                if (window.grecaptcha) grecaptcha.reset();
            }
        </script>

        <script src="https://www.google.com/recaptcha/api.js" async defer></script>
        <?php
    }
}