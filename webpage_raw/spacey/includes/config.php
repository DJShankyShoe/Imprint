<?php
// Database configuration (for future use)
define('DB_HOST', 'localhost');
define('DB_NAME', 'spacey');
define('DB_USER', 'root');
define('DB_PASS', '');

// NO session_start() - using JWE tokens instead

// Demo users (in production, use a database)
$GLOBALS['users'] = [
    'admin' => password_hash('space2024', PASSWORD_DEFAULT),
    'astronaut' => password_hash('cosmos', PASSWORD_DEFAULT)
];

// Base path
define('BASE_PATH', __DIR__ . '/..');
define('BASE_URL', '');
