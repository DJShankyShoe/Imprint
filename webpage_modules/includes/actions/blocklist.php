<?php

function bl_read_store(string $path): array
{
    if (!file_exists($path)) {
        // create empty store
        file_put_contents($path, json_encode(new stdClass()));
    }

    $fp = fopen($path, 'r');
    if (!$fp) return [];

    // Shared lock for reading
    flock($fp, LOCK_SH);
    $raw = stream_get_contents($fp);
    flock($fp, LOCK_UN);
    fclose($fp);

    $data = json_decode($raw ?: "{}", true);
    return is_array($data) ? $data : [];
}

function bl_write_store(string $path, array $data): void
{
    $fp = fopen($path, 'c+');
    if (!$fp) return;

    // Exclusive lock for writing
    flock($fp, LOCK_EX);

    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($data, JSON_PRETTY_PRINT));
    fflush($fp);

    flock($fp, LOCK_UN);
    fclose($fp);
}

function bl_prune_expired(array &$store): void
{
    $now = time();
    foreach ($store as $key => $until) {
        $untilInt = (int)$until;
        if ($untilInt <= $now) {
            unset($store[$key]);
        }
    }
}

/**
 * Block an identifier/session key until now+ttl.
 */
function block_set(string $key, array $cfg, ?int $ttlSeconds = null): void
{
    $ttl = $ttlSeconds ?? (int)($cfg['BLOCK_TTL_SECONDS'] ?? 180);
    $path = (string)$cfg['BLOCK_STORE'];

    $store = bl_read_store($path);
    bl_prune_expired($store);

    $store[$key] = time() + $ttl;
    bl_write_store($path, $store);
}

/**
 * Returns true if blocked; also outputs remaining seconds.
 */
function block_is_blocked(string $key, array $cfg, int &$remainingSeconds = 0): bool
{
    $path = (string)$cfg['BLOCK_STORE'];
    $store = bl_read_store($path);

    if (!isset($store[$key])) {
        return false;
    }

    $until = (int)$store[$key];
    $now = time();

    if ($until <= $now) {
        // expired: cleanup
        unset($store[$key]);
        bl_write_store($path, $store);
        return false;
    }

    $remainingSeconds = $until - $now;
    return true;
}
