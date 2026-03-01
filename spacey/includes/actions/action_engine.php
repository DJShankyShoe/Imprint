<?php
// includes/actions/action_engine.php
if (session_status() === PHP_SESSION_NONE) session_start();

function action_cfg(): array {
    return require __DIR__ . '/action_config.php';
}

/**
 * Run one or more actions.
 *
 * $action can be:
 *  - A single string:  run_action('OTP', $ctx)
 *  - A pipe-separated string: run_action('CAPTCHA|OTP', $ctx)
 *  - An array: run_action(['CAPTCHA', 'OTP'], $ctx)
 *
 * Actions that set session flags (OTP, CAPTCHA, RATE_LIMIT) do NOT exit here.
 * After calling run_action() you must call:
 *
 *   require_once __DIR__ . '/combined_overlay.php';
 *   if (has_pending_challenges()) {
 *       render_combined_overlay();
 *       exit;
 *   }
 *
 * Actions that always exit immediately (BLOCK, HONEYPOT) still do so.
 */
function run_action(string|array $action, array $ctx = []): void
{
    // Normalise to array of uppercase tokens
    if (is_array($action)) {
        $actions = array_map('strtoupper', array_map('trim', $action));
    } else {
        // Support both pipe-separated and single strings
        $actions = array_map('strtoupper', array_map('trim', explode('|', $action)));
    }
    $actions = array_filter($actions); // remove empties

    $cfg = action_cfg();
    $ctx['cfg']        = $ctx['cfg']        ?? $cfg;
    $ctx['identifier'] = $ctx['identifier'] ?? session_id();
    $ctx['ip']         = $ctx['ip']         ?? ($_SERVER['REMOTE_ADDR'] ?? '');
    $ctx['return_url'] = $ctx['return_url'] ?? ($_SERVER['REQUEST_URI'] ?? '/');

    foreach ($actions as $a) {
        _run_single_action($a, $ctx);
    }
}

/** @internal */
function _run_single_action(string $action, array $ctx): void
{
    switch ($action) {

        // ── Immediate-exit actions ────────────────────────────────────────
        case 'BLOCK':
            require_once __DIR__ . '/block.php';
            action_block_3_min($ctx); // renders page + exit
            return;

        case 'HONEYPOT':
            require_once __DIR__ . '/honeypot.php';
            action_honeypot($ctx); // redirect + exit
            return;

        // ── Flag-and-defer actions (combined overlay will render them) ────
        case 'RATE_LIMIT':
            require_once __DIR__ . '/rate_limit.php';
            action_rate_limit($ctx); // sets $_SESSION['rl_required']
            return;

        case 'OTP':
            require_once __DIR__ . '/otp.php';
            action_otp($ctx); // sets $_SESSION['otp_required']
            return;

        case 'RECAPTCHA':
        case 'CAPTCHA':
            // Check if already verified
            if (!empty($_SESSION['captcha_ok_until']) && time() < (int)$_SESSION['captcha_ok_until']) {
                unset($_SESSION['captcha_required']);
                return;
            }
            $_SESSION['captcha_required'] = true;
            return;

        case 'ALLOW':
        default:
            return;
    }
}