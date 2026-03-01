<?php
// Check if user is logged in
function isLoggedIn() {
    return isset($_SESSION['user']);
}

// Redirect to login if not authenticated
function requireLogin() {
    if (!isLoggedIn()) {
        header('Location: ' . BASE_URL . '/login/');
        exit;
    }
}

// Redirect to home if already authenticated
function requireGuest() {
    if (isLoggedIn()) {
        header('Location: ' . BASE_URL . '/home/');
        exit;
    }
}

// Validate login credentials
function validateLogin($username, $password) {
    if (empty($username) || empty($password)) {
        return false;
    }
    
    if (!isset($GLOBALS['users'][$username])) {
        return false;
    }
    
    return password_verify($password, $GLOBALS['users'][$username]);
}

// Login user
function loginUser($username) {
    $_SESSION['user'] = $username;
    $_SESSION['login_time'] = time();
}

// Logout user
function logoutUser() {
    session_destroy();
}

// Get current user
function getCurrentUser() {
    return $_SESSION['user'] ?? null;
}

// Sanitize output
function escape($string) {
    return htmlspecialchars($string, ENT_QUOTES, 'UTF-8');
}

// Generate stars for background (returns HTML)
function generateStars($count = 100) {
    $stars = '';
    for ($i = 0; $i < $count; $i++) {
        $left = rand(0, 100);
        $top = rand(0, 100);
        $delay = rand(0, 30) / 10;
        $stars .= "<div class='star' style='left: {$left}%; top: {$top}%; animation-delay: {$delay}s;'></div>";
    }
    return $stars;
}
