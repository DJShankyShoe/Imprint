<?php
// includes/actions/enforce_action.php
//
// HOW ENFORCEMENT WORKS
// ─────────────────────
// This file is require_once'd at the top of EVERY protected page.
// The top-level code (outside any function) runs immediately on include and
// enforces all active challenges, so users can't bypass them by changing URLs.
//
// Guard order:
//   1. Block guard      – renders block_page + exit  (always-on)
//   2. Rate-limit guard – sets rl_required flag      (always-on)
//   3. Honeypot guard   – cookie redirect + exit     (always-on)
//   4. Combined overlay – if any challenge flag is set, render overlay + exit
//
// enforce_action($action) is called by your rules engine to SET new flags.
// It runs the same overlay check afterwards so the overlay appears immediately.

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

// ── Prevent browser from caching protected pages ─────────────────────────────
// Without this, the browser back button serves the previous page from its own
// cache — the server never gets the request, guards never run, and actions like
// honeypot or rate-limit can be trivially bypassed.
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

require_once __DIR__ . '/action_engine.php';
require_once __DIR__ . '/blocklist.php';
require_once __DIR__ . '/block.php';
require_once __DIR__ . '/rate_limit.php';
require_once __DIR__ . '/honeypot.php';
require_once __DIR__ . '/combined_overlay.php';

// ── GUARD 1: Block ────────────────────────────────────────────────────────────
// If the session/identifier is in the block list, render block page and exit.
action_block_guard();

// ── GUARD 2: Rate-limit ───────────────────────────────────────────────────────
// If the user is over the penalty threshold, set $_SESSION['rl_required'] and
// send a 429 header. The combined overlay will render the countdown UI below.
rate_limit_action_guard();

// ── GUARD 3: Honeypot ─────────────────────────────────────────────────────────
// If the honeypot cookie is present, redirect to the honeypot URL and exit.
action_honeypot_guard(['cfg' => action_cfg()]);

// ── GUARD 4: Combined challenge overlay ───────────────────────────────────────
// This is the enforcement gate. If ANY challenge flag is active in the session
// (rl_required, captcha_required, otp_required) the user sees the overlay and
// the protected page is NOT rendered. Changing the URL doesn't help because
// this block runs on every include of enforce_action.php.
if (has_pending_challenges()) {
    render_combined_overlay();
    exit;
}

// ─────────────────────────────────────────────────────────────────────────────
// FUNCTIONS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * enforce_action()
 *
 * Call this once on a page when your rules engine decides an action is needed.
 * It sets the appropriate session flags and then immediately runs the combined
 * overlay check — so the overlay appears on the same request it was triggered.
 *
 * Supports single or combined actions:
 *   enforce_action('OTP');
 *   enforce_action('CAPTCHA|OTP');
 *   enforce_action(['RATE_LIMIT', 'CAPTCHA', 'OTP']);
 *
 * BLOCK and HONEYPOT always exit immediately and cannot be combined.
 */
function enforce_action(string|array $action, array $ctx = []): void
{
    $cfg = action_cfg();

    $ctx['cfg']        = $cfg;
    $ctx['identifier'] = $ctx['identifier'] ?? session_id();
    $ctx['ip']         = $ctx['ip']         ?? ($_SERVER['REMOTE_ADDR'] ?? '');
    $ctx['return_url'] = $ctx['return_url'] ?? ($_SERVER['REQUEST_URI'] ?? '/');

    // Set all requested flags (BLOCK/HONEYPOT will exit inside run_action)
    run_action($action, $ctx);

    // After flagging, check if overlay is now needed
    if (has_pending_challenges()) {
        render_combined_overlay();
        exit;
    }
}

/**
 * otp_guard()
 * Kept for backwards compatibility if any page calls it directly.
 */
function otp_guard(array $ctx = []): void
{
    if (empty($_SESSION['otp_required'])) return;

    $until = (int)($_SESSION['otp_verified_until'] ?? 0);
    if ($until > time()) {
        unset($_SESSION['otp_required']);
        return;
    }

    if (empty($_SESSION['return_after_otp'])) {
        $_SESSION['return_after_otp'] = $ctx['return_url'] ?? ($_SERVER['REQUEST_URI'] ?? '/');
    }

    render_combined_overlay();
    exit;
}

/**
 * captcha_guard()
 * Kept for backwards compatibility if any page calls it directly.
 */
function captcha_guard(array $ctx = []): void
{
    if (empty($_SESSION['captcha_required'])) return;

    // No pass TTL — must be completed fresh every time
    render_combined_overlay();
    exit;
}

/**
 * render_security_overlays()
 * Kept for backwards compatibility. Delegates to the combined overlay.
 */
function render_security_overlays(): void
{
    if (has_pending_challenges()) {
        render_combined_overlay();
        exit;
    }
}