<?php
// Load settings from .env
require_once '/opt/imprint/env.php';

// Database configuration (for future use)
define('DB_HOST', imprint_env('SPACEY_DB_HOST', 'localhost'));
define('DB_NAME', imprint_env('SPACEY_DB_NAME', 'spacey'));
define('DB_USER', imprint_env('SPACEY_DB_USER', 'root'));
define('DB_PASS', imprint_env('SPACEY_DB_PASS', ''));

// NO session_start() - using JWE tokens instead

// Demo users (in production, use a database)
$GLOBALS['users'] = [];
foreach (explode(',', (string)imprint_env('SPACEY_USERS', '')) as $pair) {
    [$name, $pass] = array_pad(explode(':', trim($pair), 2), 2, '');
    if ($name !== '' && $pass !== '') {
        $GLOBALS['users'][$name] = password_hash($pass, PASSWORD_DEFAULT);
    }
}

// Base path
define('BASE_PATH', __DIR__ . '/..');
define('BASE_URL', '');
