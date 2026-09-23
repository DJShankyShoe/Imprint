<?php
// ===== ENABLE ERROR DISPLAY =====
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

// ===== MODULAR AUTHENTICATION (FIRST - before config) =====
require_once $_SERVER['DOCUMENT_ROOT'] . '/modules/auth_check.php';

// Check if already logged in and redirect
$auth = new AuthCheck([
    'auto_redirect' => true,
    'redirect_on_login' => '/home/'
]);

// ===== CHECK IF FINGERPRINTING IS NEEDED =====
$needsFingerprinting = $auth->needsFingerprinting(
    $_SERVER['DOCUMENT_ROOT'] . '/fingerprint_scripts/fingerprint_module.php'
);

// ===== MODULAR FINGERPRINT LOADER =====
require_once $_SERVER['DOCUMENT_ROOT'] . '/fingerprint_scripts/fingerprint_loader.php';
$fpLoader = new FingerprintLoader($needsFingerprinting);

// ===== ALERT CHECK =====
// Get actions from the Imprint service
require_once $_SERVER['DOCUMENT_ROOT'] . '/modules/insert_actions.php';
updateTokenActions();

// Execute any actions
executeActions([
    'identifier' => session_id(),
    'ip' => $_SERVER['REMOTE_ADDR'],
    'return_url' => $_SERVER['REQUEST_URI'] ?? '/',
]);

// ===== NOW LOAD CONFIG (modified to not start sessions) =====
require_once '../includes/config.php';
require_once '../includes/functions.php';

$error = '';

// Handle login form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    if (validateLogin($username, $password)) {
        // Create JWE token login
        $auth->createLoginToken($username);
        header('Location: /home/');
        exit;
    } else {
        $error = 'Invalid credentials. Please try again.';
    }
}

$pageTitle = 'SpaceY - Login';
$extraCSS = ['login.css'];
include '../includes/header.php';

// Render fingerprint blocking UI
$fpLoader->renderBlockingUI();
?>

<?php
// Render fingerprint blocking elements
$fpLoader->renderBlockingElements();
?>

<div class="container">
    <div class="login-panel">
        <div class="logo">SPACEY</div>
        <div class="tagline">Mission Control Access</div>
        
        <?php if ($error): ?>
            <div class="error"><?php echo escape($error); ?></div>
        <?php endif; ?>
        
        <form method="POST" action="">
            <div class="form-group">
                <label for="username">Astronaut ID</label>
                <input type="text" id="username" name="username" required autocomplete="username">
            </div>
            
            <div class="form-group">
                <label for="password">Access Code</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
            </div>
            
            <button type="submit" class="btn">
                <span>Initialize Launch Sequence</span>
            </button>
        </form>

    </div>
</div>

<?php include '../includes/footer.php'; ?>

<?php
// Render fingerprint scripts
$fpLoader->renderScripts();
?>
