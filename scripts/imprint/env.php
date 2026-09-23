<?php
/**
 * Imprint Environment - Loads settings from .env files
 *
 * Files:
 *   /opt/imprint/.env            Site settings (or IMPRINT_ENV_FILE)
 *   /opt/imprint/mitigation.env  Mitigation PoC settings (or IMPRINT_MITIGATION_ENV_FILE)
 */

// Parse .env file (cached per request)
function imprint_parse_env_file(string $path): array {
    static $cache = [];

    if (!isset($cache[$path])) {
        $values = [];
        if (is_readable($path)) {
            foreach (file($path, FILE_IGNORE_NEW_LINES) as $line) {
                $line = trim($line);
                if ($line === '' || $line[0] === '#' || strpos($line, '=') === false) {
                    continue;
                }
                if (strpos($line, 'export ') === 0) {
                    $line = substr($line, 7);
                }
                [$k, $v] = array_map('trim', explode('=', $line, 2));
                // Strip matching surrounding quotes
                if (strlen($v) >= 2 && $v[0] === $v[strlen($v) - 1] && ($v[0] === '"' || $v[0] === "'")) {
                    $v = substr($v, 1, -1);
                }
                $values[$k] = $v;
            }
        } else {
            error_log("imprint_env: cannot read {$path}");
        }
        $cache[$path] = $values;
    }
    return $cache[$path];
}

// Get value from environment or .env file
function imprint_env_lookup(string $path, string $key, $default) {
    $real = getenv($key);
    if ($real !== false && $real !== '') {
        return $real;
    }
    return imprint_parse_env_file($path)[$key] ?? $default;
}

// Get site setting
function imprint_env(string $key, $default = null) {
    $path = getenv('IMPRINT_ENV_FILE') ?: '/opt/imprint/.env';
    return imprint_env_lookup($path, $key, $default);
}

// Get mitigation PoC setting
function imprint_mitigation_env(string $key, $default = null) {
    $path = getenv('IMPRINT_MITIGATION_ENV_FILE') ?: '/opt/imprint/mitigation.env';
    return imprint_env_lookup($path, $key, $default);
}
