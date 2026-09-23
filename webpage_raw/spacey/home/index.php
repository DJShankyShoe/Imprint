<?php
// ===== ENABLE ERROR DISPLAY =====
//error_reporting(E_ALL);
//ini_set('display_errors', 1);
//ini_set('display_startup_errors', 1);

// ===== MODULAR AUTHENTICATION (FIRST - before config) =====
require_once $_SERVER['DOCUMENT_ROOT'] . '/modules/auth_check.php';

// Initialize auth and require login
$auth = new AuthCheck();
$auth->requireLogin('/login/');

// User is authenticated - get user info
$username = $auth->getUsername();
$uid = $auth->getUID();

// ===== ALERT CHECK =====
// Get actions from the Imprint service
require_once $_SERVER['DOCUMENT_ROOT'] . '/modules/insert_actions.php';
$output = updateTokenActions();

// Log the output to browser console (for debugging)
if (!empty($output)) {
    echo "<script>console.log('Alert Check Output:', " . json_encode($output) . ");</script>\n";
}

// Execute any actions
$ctx = [
    'identifier' => session_id(),  // Or any custom ID like 'user-123'

    'ip' => $_SERVER['REMOTE_ADDR'],  // Fallback to localhost if not set

    'return_url' => $_SERVER['REQUEST_URI'] ?? '/', 
];
executeActions($ctx);


// ===== NOW LOAD CONFIG (modified to not start sessions) =====
require_once '../includes/config.php';
require_once '../includes/functions.php';

// Handle logout - clears the site's login cookie, tracking stays
if (isset($_GET['logout'])) {
    $auth->logout();
    header('Location: /login/');
    exit;
}

$currentUser = $username;
$pageTitle = 'SpaceY - Mission Control Dashboard';
$extraCSS = ['home.css'];
include '../includes/header.php';
?>

<div class="container">
    <div class="dashboard">
        <div class="header">
            <div class="welcome">Welcome, <?php echo escape($currentUser); ?></div>
            <a href="?logout=1" class="logout-btn">Terminate Session</a>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Active Missions</div>
                <div class="stat-value">7</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Spacecraft Online</div>
                <div class="stat-value">12</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Light Years Traveled</div>
                <div class="stat-value">2.4M</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Systems Operational</div>
                <div class="stat-value">98%</div>
            </div>
        </div>
        
        <div class="mission-panel">
            <div class="mission-title">Active Mission Briefings</div>
            
            <div class="mission-item">
                <h4>Mars Colony Expansion</h4>
                <p>Deploy additional habitat modules to Olympus Mons base. Mission duration: 180 sols.</p>
                <span class="status-badge">In Progress</span>
            </div>
            
            <div class="mission-item">
                <h4>Europa Ice Core Sampling</h4>
                <p>Analyze subsurface ocean composition. Autonomous drilling initiated at coordinates 47.2°N, 118.5°W.</p>
                <span class="status-badge">Active</span>
            </div>
            
            <div class="mission-item">
                <h4>Titan Atmospheric Research</h4>
                <p>Long-duration atmospheric balloon deployment. Collecting methane lake formation data.</p>
                <span class="status-badge">Monitoring</span>
            </div>
            
            <div class="mission-item">
                <h4>Asteroid Mining Survey</h4>
                <p>Prospecting mission to 16 Psyche. Analyzing rare earth element concentrations for extraction viability.</p>
                <span class="status-badge">Planning</span>
            </div>
        </div>
    </div>
</div>

<?php include '../includes/footer.php'; ?>
