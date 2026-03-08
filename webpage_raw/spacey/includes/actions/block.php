<?php

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . '/blocklist.php'; // provides block_set(), block_is_blocked()

/**
 * SET BLOCK + render blocked page.
 * Same behavior as testsite: block user for TTL.
 * DIFFERENCE: no redirect; we render the blocked UI inline (URL stays the same).
 */
function action_block_3_min(array $ctx = []): void
{
    $cfg = $ctx['cfg'] ?? (function_exists('action_cfg') ? action_cfg() : (require __DIR__ . '/action_config.php'));

    // IMPORTANT: use the SAME key everywhere (guard + set)
    $key = $ctx['identifier'] ?? session_id();

    // Set the block (TTL comes from config BLOCK_TTL_SECONDS default 180)
    block_set($key, $cfg);

    // Get remaining time for display
    $remaining = 0;
    block_is_blocked($key, $cfg, $remaining);

    // Render blocked UI (no redirect)
    http_response_code(403);
    header('Content-Type: text/html; charset=utf-8');

    // Pass countdown to the UI page
    $block_retryIn = (int)$remaining;

    // Optional fallback if history.back() can't work (new tab)
    $block_fallback_url = (string)($cfg['BLOCK_FALLBACK_URL'] ?? '/spacey/index.php');

    // UI template
    require __DIR__ . '/block_page.php';
    exit;
}

/**
 * GLOBAL GUARD:
 * If already blocked, render blocked UI (prevents URL change bypass).
 * Call this ONCE per request, early (e.g., in enforce_action.php or bootstrap).
 */
function action_block_guard(array $ctx = []): void
{
    $cfg = $ctx['cfg'] ?? (function_exists('action_cfg') ? action_cfg() : (require __DIR__ . '/action_config.php'));
    $key = $ctx['identifier'] ?? session_id();

    // If already blocked, show the block UI
    $remaining = 0;
    if (block_is_blocked($key, $cfg, $remaining)) {
        http_response_code(403);
        header('Content-Type: text/html; charset=utf-8');

        $block_retryIn = (int)$remaining;
        $block_fallback_url = (string)($cfg['BLOCK_FALLBACK_URL'] ?? '/spacey/index.php');

        require __DIR__ . '/block_page.php';
        exit;
    }
}