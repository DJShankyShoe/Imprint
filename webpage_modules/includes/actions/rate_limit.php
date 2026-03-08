<?php
// includes/actions/rate_limit.php
if (session_status() === PHP_SESSION_NONE) session_start();

function rl_cfg(array $ctx = []): array {
    return $ctx['cfg'] ?? (function_exists('action_cfg') ? action_cfg() : []);
}

function rl_store_path(array $cfg): string {
    return $cfg['RATE_LIMIT_STORE'] ?? (__DIR__ . '/ratelimiting.json');
}

function rl_read_store(string $path): array {
    if (!file_exists($path)) return [];
    $raw = @file_get_contents($path);
    $data = json_decode($raw ?: '[]', true);
    return is_array($data) ? $data : [];
}

function rl_write_store(string $path, array $data): void {
    $dir = dirname($path);
    if (!is_dir($dir)) @mkdir($dir, 0775, true);

    $fp = @fopen($path, 'c+');
    if (!$fp) return;

    flock($fp, LOCK_EX);
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($data, JSON_PRETTY_PRINT));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
}

function rl_identifier(array $ctx = []): string {
    return $ctx['identifier'] ?? session_id();
}

/**
 * ACTION: opt this user's identifier into rate-limit tracking.
 *
 * Sets a 'tracked' flag in the JSON store so the guard starts
 * counting every subsequent request (including plain page refreshes).
 * Also records the return URL so the overlay can redirect back after
 * the penalty expires.
 *
 * Safe to call multiple times — repeated calls only record the
 * return URL once and do not reset an active penalty.
 */
function action_rate_limit(array $ctx = []): void {
    $cfg = rl_cfg($ctx);
    $id  = rl_identifier($ctx);

    // Capture where the user should return after penalty
    if (empty($_SESSION['rl_return_url'])) {
        $_SESSION['rl_return_url'] = $ctx['return_url'] ?? ($_SERVER['REQUEST_URI'] ?? '/');
    }

    $path  = rl_store_path($cfg);
    $store = rl_read_store($path);
    $rec   = $store[$id] ?? [];

    // If already in penalty or already tracked, nothing to change
    if (!empty($rec['penalty_start']) || !empty($rec['tracked'])) {
        return;
    }

    // Mark as tracked so the guard starts counting from the next request
    $rec['tracked'] = true;
    $rec['hits']    = [];

    $store[$id] = $rec;
    rl_write_store($path, $store);
}

/** @internal Sets $_SESSION rl_* keys so combined_overlay.php can read them */
function rl_apply_session_flags(array $rec, array $cfg, string $id): void {
    $penWindow = (int)($cfg['RATE_LIMIT_PENALTY_WINDOW_SECONDS'] ?? 60);
    $max       = (int)($cfg['RATE_LIMIT_MAX_REQUESTS']           ?? 6);
    $now       = time();

    $start   = (int)($rec['penalty_start'] ?? $now);
    $retryIn = max(1, ($start + $penWindow) - $now);

    $_SESSION['rl_required']   = true;
    $_SESSION['rl_retry_in']   = $retryIn;
    $_SESSION['rl_pen_max']    = $max;
    $_SESSION['rl_pen_window'] = $penWindow;
    $_SESSION['rl_identifier'] = $id;
}

/**
 * GUARD: runs on every page load (called from enforce_action.php).
 *
 * Two responsibilities:
 *  1. If the user's identifier is being tracked (has hits in the store),
 *     record this request as another hit and check the threshold.
 *  2. If already in penalty, set session flags so combined_overlay shows
 *     the countdown, and return false.
 *
 * "Tracking" is opted into by calling action_rate_limit() once.
 * After that, every page load (including plain refreshes) counts.
 */
function rate_limit_action_guard(array $ctx = []): bool {
    $cfg = rl_cfg($ctx);
    $id  = rl_identifier($ctx);
    $now = time();

    $window    = (int)($cfg['RATE_LIMIT_WINDOW_SECONDS']         ?? 60);
    $max       = (int)($cfg['RATE_LIMIT_MAX_REQUESTS']           ?? 6);
    $penWindow = (int)($cfg['RATE_LIMIT_PENALTY_WINDOW_SECONDS'] ?? 60);

    $path  = rl_store_path($cfg);
    $store = rl_read_store($path);
    $rec   = $store[$id] ?? [];

    // ── Already in penalty? ───────────────────────────────────────────────────
    $start = (int)($rec['penalty_start'] ?? 0);

    if ($start > 0) {
        $end = $start + $penWindow;

        if ($now > $end) {
            // Penalty expired — clear everything
            unset($rec['penalty_start'], $rec['penalty_count'], $rec['hits'], $rec['tracked']);
            $store[$id] = $rec;
            rl_write_store($path, $store);
            rl_clear_session_flags();
            return true;
        }

        // Still in penalty — refresh session flags and block
        $retryIn = max(1, $end - $now);
        $_SESSION['rl_required']   = true;
        $_SESSION['rl_retry_in']   = (int)$retryIn;
        $_SESSION['rl_pen_max']    = $max;
        $_SESSION['rl_pen_window'] = $penWindow;
        $_SESSION['rl_identifier'] = (string)$id;
        if (empty($_SESSION['rl_return_url'])) {
            $_SESSION['rl_return_url'] = $_SERVER['REQUEST_URI'] ?? '/';
        }
        http_response_code(429);
        header("Retry-After: {$retryIn}");
        return false;
    }

    // ── Not in penalty — is this identifier being tracked? ───────────────────
    // Only count hits for users who have been opted in via action_rate_limit().
    if (empty($rec['tracked'])) {
        // Not tracked yet — nothing to count, clear any stale session flags
        rl_clear_session_flags();
        return true;
    }

    // ── Tracked — count this request ─────────────────────────────────────────
    $hits = array_values(array_filter(
        $rec['hits'] ?? [],
        fn($t) => $t > ($now - $window)
    ));
    $hits[] = $now;
    sort($hits);
    $rec['hits'] = $hits;

    if (count($hits) > $max) {
        // Threshold crossed — enter penalty
        $rec['penalty_start'] = $now;
        $rec['penalty_count'] = 0;
        unset($rec['hits']);

        $store[$id] = $rec;
        rl_write_store($path, $store);

        rl_apply_session_flags($rec, $cfg, $id);
        http_response_code(429);
        header("Retry-After: " . max(1, $penWindow));
        return false;
    }

    $store[$id] = $rec;
    rl_write_store($path, $store);
    return true;
}

/** @internal Clears all rl_* session flags */
function rl_clear_session_flags(): void {
    unset(
        $_SESSION['rl_required'],   $_SESSION['rl_retry_in'],
        $_SESSION['rl_pen_max'],    $_SESSION['rl_pen_window'],
        $_SESSION['rl_identifier'],  $_SESSION['rl_return_url']
    );
}