<?php
/**
 * Authentication Module - With Debug Logging
 * 
 * Usage:
 *   $auth = new AuthCheck(['debug' => true]);  // Debug ON
 *   $auth = new AuthCheck(['debug' => false]); // Debug OFF (production)
 *   $auth = new AuthCheck();                   // Debug ON by default
 */

class AuthCheck {
    
    private $jwe;
    private $token;
    private $session;
    private $hasValidToken;
    private $userUID;
    private $status;
    private $fingerprintModule;
    private $debug;
    
    public function __construct($config = []) {
        $defaults = [
            'jwe_module_path' => $_SERVER['DOCUMENT_ROOT'] . '/modules/jwe_module.php',
            'fingerprint_module_path' => $_SERVER['DOCUMENT_ROOT'] . '/fingerprint_scripts/fingerprint_module.php',
            'redirect_on_login' => '/home/',
            'auto_redirect' => false,
            'debug' => false,  // ON by default for debugging
        ];
        
        $config = array_merge($defaults, $config);
        $this->debug = $config['debug'];
        
        $this->debugLog('========================================');
        $this->debugLog('🔐 AuthCheck Initialized');
        $this->debugLog('========================================');
        $this->debugLog('Request URI: ' . ($_SERVER['REQUEST_URI'] ?? 'unknown'));
        $this->debugLog('Config:');
        $this->debugLog('  redirect_on_login: ' . $config['redirect_on_login']);
        $this->debugLog('  auto_redirect: ' . ($config['auto_redirect'] ? 'true' : 'false'));
        $this->debugLog('  debug: ' . ($this->debug ? 'ON' : 'OFF'));
        
        // Load JWE module
        if (!class_exists('JWEModule')) {
            $this->debugLog('Loading JWE module...');
            require_once $config['jwe_module_path'];
        } else {
            $this->debugLog('JWE module already loaded');
        }
        
        $this->jwe = new JWEModule();
        $this->debugLog('✓ JWE module initialized');
        
        // Check for token
        $this->token = $_COOKIE['sess_jwe'] ?? null;
        $this->debugLog('Checking for sess_jwe cookie...');
        $this->debugLog('  Cookie present: ' . ($this->token ? 'YES' : 'NO'));
        
        if ($this->token) {
            $this->debugLog('  Cookie value: ' . substr($this->token, 0, 50) . '...');
            $this->debugLog('Verifying token...');
        }
        
        $this->session = $this->token ? $this->jwe->verifyToken($this->token) : false;
        
        if ($this->session) {
            $this->debugLog('✓ Token verified successfully');
            $this->debugLog('  Session data: ' . json_encode($this->session));
        } else {
            $this->debugLog('❌ Token verification failed or no token');
        }
        
        // Determine authentication status
        $this->hasValidToken = ($this->session && !empty($this->session['UID']));
        $this->debugLog('Has valid token: ' . ($this->hasValidToken ? 'YES' : 'NO'));
        
        if ($this->hasValidToken) {
            $this->userUID = $this->session['UID'];
            $this->status = $this->session['status'] ?? 'logout';
            
            $this->debugLog('✓ Valid token found');
            $this->debugLog('  UID: ' . $this->userUID);
            $this->debugLog('  Status: ' . $this->status);
            $this->debugLog('  Username: ' . ($this->session['username'] ?? 'N/A'));
            
            // Auto-redirect if configured
            if ($config['auto_redirect'] && $this->status === 'pass') {
                $this->debugLog('');
                $this->debugLog('🔄 AUTO-REDIRECT TRIGGERED');
                $this->debugLog('  User is logged in (status=pass)');
                $this->debugLog('  Redirecting to: ' . $config['redirect_on_login']);
                $this->debugLog('========================================');
                
                header('Location: ' . $config['redirect_on_login']);
                exit;
            } else {
                if (!$config['auto_redirect']) {
                    $this->debugLog('Auto-redirect disabled');
                } elseif ($this->status !== 'pass') {
                    $this->debugLog('Status=' . $this->status . ' (needs "pass" for redirect)');
                }
            }
        } else {
            $this->userUID = null;
            $this->status = null;
            $this->debugLog('No valid token');
        }
        
        $this->debugLog('========================================');
        $this->debugLog('✅ AuthCheck Complete');
        $this->debugLog('  isLoggedIn(): ' . ($this->isLoggedIn() ? 'true' : 'false'));
        $this->debugLog('  hasToken(): ' . ($this->hasToken() ? 'true' : 'false'));
        $this->debugLog('========================================');
    }
    
    private function debugLog($message) {
        if ($this->debug) {
            // Write to dedicated auth debug log
            $logFile = '/var/log/imprint/auth_debug.log';
            $timestamp = date('Y-m-d H:i:s');
            @file_put_contents($logFile, "[{$timestamp}] {$message}\n", FILE_APPEND | LOCK_EX);
            
            // Also output as HTML comment (visible in page source)
            if (!headers_sent()) {
                echo "<!-- [AuthCheck] " . htmlspecialchars($message) . " -->\n";
            }
        }
    }
    
    public function isLoggedIn() {
        return $this->hasValidToken && $this->status === 'pass';
    }
    
    public function hasToken() {
        return $this->hasValidToken;
    }
    
    public function getUID() {
        return $this->userUID;
    }
    
    public function getStatus() {
        return $this->status;
    }
    
    public function getUsername() {
        return $this->session['username'] ?? null;
    }
    
    public function getSession() {
        return $this->session;
    }
    
    public function needsFingerprinting($fingerprint_module_path = null) {
        $this->debugLog('needsFingerprinting() called');
        
        if (!$this->hasValidToken) {
            $this->debugLog('  No token - needs fingerprint: YES');
            return true;
        }
        
        if ($this->status === 'pass') {
            $this->debugLog('  Logged in - needs fingerprint: NO');
            return false;
        }
        
        if ($fingerprint_module_path && !$this->fingerprintModule) {
            if (!class_exists('FingerprintModule')) {
                require_once $fingerprint_module_path;
            }
            $this->fingerprintModule = new FingerprintModule();
        }
        
        if ($this->fingerprintModule) {
            $exists = $this->fingerprintModule->hasFingerprintForUID($this->userUID);
            $this->debugLog('  Fingerprint in DB: ' . ($exists ? 'YES' : 'NO'));
            return !$exists;
        }
        
        return false;
    }
    
    public function requireLogin($login_url = '/login/') {
        if (!$this->isLoggedIn()) {
            $this->debugLog('requireLogin() - Not logged in, redirecting to: ' . $login_url);
            header('Location: ' . $login_url);
            exit;
        }
        $this->debugLog('requireLogin() - User is logged in');
    }
    
    public function createLoginToken($username, $uid = null, $expiry = 604800) {
        $this->debugLog('createLoginToken() - Username: ' . $username);
        
        if (empty($uid)) {
            if ($this->hasValidToken && !empty($this->userUID)) {
                $uid = $this->userUID;
            } else {
                if (!function_exists('uuidv7')) {
                    require_once $_SERVER['DOCUMENT_ROOT'] . '/modules/uuid.php';
                }
                $uid = uuidv7();
            }
        }
        $this->debugLog('  Using UID: ' . $uid);
        
        $token = $this->jwe->createToken([
            'UID' => $uid,
            'username' => $username,
            'status' => 'pass',
            'action' => []
        ], $expiry);
        
        if ($token) {
            $this->debugLog('✓ Token created');
            setcookie('sess_jwe', $token, [
                'expires' => time() + $expiry,
                'path' => '/',
                'secure' => true,
                'httponly' => true,
                'samesite' => 'Lax',
            ]);
            $this->debugLog('✓ Cookie set');
            
            $this->token = $token;
            $this->session = $this->jwe->verifyToken($token);
            $this->hasValidToken = true;
            $this->userUID = $uid;
            $this->status = 'pass';
            
            return true;
        }
        
        $this->debugLog('❌ Token creation failed');
        return false;
    }
    
    public function logout() {
        $this->debugLog('logout() called');
        setcookie('sess_jwe', '', [
            'expires' => time() - 3600,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
        
        $this->token = null;
        $this->session = false;
        $this->hasValidToken = false;
        $this->userUID = null;
        $this->status = null;
    }
}

//if (!isset($auth)) {
//    $auth = new AuthCheck();
//}
