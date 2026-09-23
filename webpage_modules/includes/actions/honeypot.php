<?php
// includes/actions/honeypot.php
//
// Honeypot flag is stored SERVER-SIDE in the PHP session.
// This avoids all cookie SameSite/Secure/domain issues entirely.
// The guard runs on every page load via enforce_action.php and redirects
// any flagged session to the honeypot URL until the TTL expires.

if (session_status() !== PHP_SESSION_ACTIVE) session_start();

/**
 * ACTION: flag this session as honeypot and redirect immediately.
 * Stores the expiry timestamp in $_SESSION so the guard can enforce it
 * on every subsequent request, regardless of how the user navigates.
 */
function action_honeypot(array $ctx = []): void
{
    $cfg = $ctx['cfg'] ?? (function_exists('action_cfg') ? action_cfg() : require __DIR__ . '/action_config.php');

    $ttl = (int)($cfg['HONEYPOT_TTL_SECONDS'] ?? 15);
    $url = $cfg['HONEYPOT_URL'] ?? 'https://' . preg_replace('/:\d+$/', '', $_SERVER['HTTP_HOST'] ?? 'localhost') . ':8443/';

    // Flag the session with an expiry time
    $_SESSION['hp_until'] = time() + $ttl;

    header("Location: {$url}", true, 302);
    exit;
}

/**
 * GUARD: runs on every page load (called from enforce_action.php).
 * If the session is flagged and the TTL hasn't expired, redirect to
 * the honeypot URL. The user cannot bypass this by changing the URL
 * because the flag lives in the server-side session, not a cookie.
 */
function action_honeypot_guard(array $ctx = []): void
{
    if (empty($_SESSION['hp_until'])) {
        return; // never flagged
    }

    $until = (int)$_SESSION['hp_until'];

    if (time() > $until) {
        // TTL expired — unset and let the user through
        unset($_SESSION['hp_until']);
        return;
    }

    $cfg = $ctx['cfg'] ?? (function_exists('action_cfg') ? action_cfg() : require __DIR__ . '/action_config.php');
    $url = $cfg['HONEYPOT_URL'] ?? 'https://' . preg_replace('/:\d+$/', '', $_SERVER['HTTP_HOST'] ?? 'localhost') . ':8443/';

    // Avoid redirect loop if somehow this guard runs on the honeypot host
    $hpHost  = parse_url($url, PHP_URL_HOST);
    $curHost = $_SERVER['HTTP_HOST'] ?? '';
    if ($hpHost && strcasecmp($hpHost, $curHost) === 0) {
        return;
    }

    header("Location: {$url}", true, 302);
    exit;
}