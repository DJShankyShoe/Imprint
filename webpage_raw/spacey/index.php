<?php
require_once 'includes/config.php';
require_once 'includes/functions.php';

// Redirect to appropriate page based on login status
if (isLoggedIn()) {
    header('Location: ' . BASE_URL . '/home/');
} else {
    header('Location: ' . BASE_URL . '/login/');
}
exit;
