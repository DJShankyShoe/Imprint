<?php
/**
 * Authentication Module
 * 
 * Handles JWE token verification and authentication status checking.
 * Drop this file into /modules/ and include it at the top of any page.
 * 
 * Usage:
 *   require_once $_SERVER['DOCUMENT_ROOT'] . '/modules/auth_check.php';
 *   
 *   if ($auth->isLoggedIn()) {
 *       // User is authenticated
 *   }
 *   
 *   if ($auth->needsFingerprinting()) {
 *       // User needs to be fingerprinted
 *   }
 */

class AuthCheck {
    
    private $jwe;
    private $token;
    private $session;
    private $hasValidToken;
    private $userUID;
    private $status;
    private $fingerprintModule;
    
    /**
     * Constructor - Automatically checks authentication on initialization
     * 
     * @param array $config Configuration options
     */
    public function __construct($config = []) {
        $defaults = [
            'jwe_module_path' => $_SERVER['DOCUMENT_ROOT'] . '/modules/jwe_module.php',
            'fingerprint_module_path' => $_SERVER['DOCUMENT_ROOT'] . '/fingerprint_scripts/fingerprint_module.php',
            'redirect_on_login' => '/home',  // Where to redirect authenticated users
            'auto_redirect' => false,        // Automatically redirect logged-in users
        ];
        
        $config = array_merge($defaults, $config);
        
        // Load JWE module
        if (!class_exists('JWEModule')) {
            require_once $config['jwe_module_path'];
        }
        
        $this->jwe = new JWEModule();
        
        // Check for token
        $this->token = $_COOKIE['sess_jwe'] ?? null;
        $this->session = $this->token ? $this->jwe->verifyToken($this->token) : false;
        
        // Determine authentication status
        $this->hasValidToken = ($this->session && !empty($this->session['UID']));
        
        if ($this->hasValidToken) {
            $this->userUID = $this->session['UID'];
            $this->status = $this->session['status'] ?? 'logout';
            
            // Auto-redirect if configured
            if ($config['auto_redirect'] && $this->status === 'pass') {
                header('Location: ' . $config['redirect_on_login']);
                exit;
            }
        } else {
            $this->userUID = null;
            $this->status = null;
        }
    }
    
    /**
     * Check if user is logged in (authenticated)
     * 
     * @return bool True if user has valid token with status='pass'
     */
    public function isLoggedIn() {
        return $this->hasValidToken && $this->status === 'pass';
    }
    
    /**
     * Check if user has a valid token (regardless of login status)
     * 
     * @return bool True if token exists and is valid
     */
    public function hasToken() {
        return $this->hasValidToken;
    }
    
    /**
     * Get the user's UID
     * 
     * @return string|null UID if token exists, null otherwise
     */
    public function getUID() {
        return $this->userUID;
    }
    
    /**
     * Get the user's status (pass/logout)
     * 
     * @return string|null Status if token exists, null otherwise
     */
    public function getStatus() {
        return $this->status;
    }
    
    /**
     * Get the user's username
     * 
     * @return string|null Username if logged in, null otherwise
     */
    public function getUsername() {
        return $this->session['username'] ?? null;
    }
    
    /**
     * Get full session data
     * 
     * @return array|false Session data if token valid, false otherwise
     */
    public function getSession() {
        return $this->session;
    }
    
    /**
     * Check if fingerprinting is needed
     * 
     * @param string $fingerprint_module_path Path to fingerprint_module.php
     * @return bool True if fingerprinting is required
     */
    public function needsFingerprinting($fingerprint_module_path = null) {
        // If no token, definitely need fingerprinting
        if (!$this->hasValidToken) {
            return true;
        }
        
        // If logged in, no need to fingerprint
        if ($this->status === 'pass') {
            return false;
        }
        
        // Token exists with status='logout' - verify fingerprint in MongoDB
        if ($fingerprint_module_path && !$this->fingerprintModule) {
            if (!class_exists('FingerprintModule')) {
                require_once $fingerprint_module_path;
            }
            $this->fingerprintModule = new FingerprintModule();
        }
        
        if ($this->fingerprintModule) {
            // Check if fingerprint exists in MongoDB
            $fingerprintExists = $this->fingerprintModule->hasFingerprintForUID($this->userUID);
            
            // Need fingerprinting if NOT in database
            return !$fingerprintExists;
        }
        
        // Default: if token exists with logout status, assume fingerprint exists
        return false;
    }
    
    /**
     * Redirect to login page if not authenticated
     * 
     * @param string $login_url Login page URL
     */
    public function requireLogin($login_url = '/login/') {
        if (!$this->isLoggedIn()) {
            header('Location: ' . $login_url);
            exit;
        }
    }
    
    /**
     * Create a login token for a user
     * 
     * @param string $username Username
     * @param string $uid UID (optional, will use existing or generate new)
     * @param int $expiry Expiry in seconds (default: 7 days)
     * @return bool True on success
     */
    public function createLoginToken($username, $uid = null, $expiry = 604800) {
        // Use existing UID or generate new
        if (empty($uid)) {
            if ($this->hasValidToken && !empty($this->userUID)) {
                $uid = $this->userUID;
            } else {
                // Generate new UID
                if (!function_exists('uuidv7')) {
                    require_once $_SERVER['DOCUMENT_ROOT'] . '/modules/uuid.php';
                }
                $uid = uuidv7();
            }
        }
        
        // Create token
        $token = $this->jwe->createToken([
            'UID' => $uid,
            'username' => $username,
            'status' => 'pass',
            'action' => []
        ], $expiry);
        
        if ($token) {
            // Set cookie
            setcookie('sess_jwe', $token, [
                'expires' => time() + $expiry,
                'path' => '/',
                'secure' => true,
                'httponly' => true,
                'samesite' => 'Lax',
            ]);
            
            // Update local state
            $this->token = $token;
            $this->session = $this->jwe->verifyToken($token);
            $this->hasValidToken = true;
            $this->userUID = $uid;
            $this->status = 'pass';
            
            return true;
        }
        
        return false;
    }
    
    /**
     * Logout the user
     */
    public function logout() {
        // Delete cookie
        setcookie('sess_jwe', '', [
            'expires' => time() - 3600,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
        
        // Clear local state
        $this->token = null;
        $this->session = false;
        $this->hasValidToken = false;
        $this->userUID = null;
        $this->status = null;
    }
}

// Auto-initialize for easy usage
if (!isset($auth)) {
    $auth = new AuthCheck();
}
