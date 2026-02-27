<?php
/**
 * Fingerprint Loader Module
 * 
 * Handles fingerprint collection initialization and rendering.
 * Drop this file into /fingerprint_scripts/ and include it on any page that needs fingerprinting.
 * 
 * Usage:
 *   require_once $_SERVER['DOCUMENT_ROOT'] . '/fingerprint_scripts/fingerprint_loader.php';
 *   
 *   if ($fpLoader->shouldCollect()) {
 *       $fpLoader->renderBlockingUI();  // Shows loading spinner, blocks page
 *       $fpLoader->renderScripts();      // Loads fingerprint.js at bottom
 *   }
 */

class FingerprintLoader {
    
    private $fingerprintModule;
    private $needsFingerprinting;
    private $config;
    
    /**
     * Constructor
     * 
     * @param bool $needsFingerprinting Whether fingerprinting is needed
     * @param array $config Configuration options
     */
    public function __construct($needsFingerprinting = false, $config = []) {
        $defaults = [
            'fingerprint_module_path' => $_SERVER['DOCUMENT_ROOT'] . '/fingerprint_scripts/fingerprint_module.php',
            'blocked_check_delay' => 3000,  // 3 seconds
            'timeout' => 15000,              // 15 seconds
            'show_loading_spinner' => true,  // Show loading overlay
            'silent_mode' => true,           // No text, just spinner
        ];
        
        $this->config = array_merge($defaults, $config);
        $this->needsFingerprinting = $needsFingerprinting;
        
        // Initialize fingerprint module if needed
        if ($this->needsFingerprinting) {
            if (!class_exists('FingerprintModule')) {
                require_once $this->config['fingerprint_module_path'];
            }
            $this->fingerprintModule = new FingerprintModule();
        }
    }
    
    /**
     * Check if fingerprinting should be collected
     * 
     * @return bool True if fingerprinting is needed
     */
    public function shouldCollect() {
        return $this->needsFingerprinting;
    }
    
    /**
     * Render the blocking UI (loading spinner, error messages)
     * Call this in the <head> section of your HTML
     */
    public function renderBlockingUI() {
        if (!$this->needsFingerprinting) {
            return;
        }
        ?>
    <style>
        /* Hide page content until fingerprint is collected */
        body {
            visibility: hidden;
        }
        
        /* Show loading indicator (no mention of fingerprinting) */
        #loading-overlay {
            visibility: visible;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: #1a1a2e;
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 10000;
        }
        
        #loading-overlay .spinner {
            width: 50px;
            height: 50px;
            border: 4px solid rgba(255, 255, 255, 0.1);
            border-top: 4px solid #fff;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        /* Error message for blocked scripts */
        #blocked-message {
            display: none;
            visibility: visible;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: #1a1a2e;
            color: #fff;
            align-items: center;
            justify-content: center;
            z-index: 10001;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        #blocked-message.show {
            display: flex;
        }
        
        #blocked-message .message-box {
            text-align: center;
            padding: 40px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            max-width: 500px;
        }
        
        #blocked-message h1 {
            color: #ff6b6b;
            margin-bottom: 20px;
            font-size: 24px;
        }
        
        #blocked-message p {
            font-size: 16px;
            line-height: 1.6;
            margin-bottom: 15px;
            color: #e0e0e0;
        }
        
        #blocked-message ul {
            text-align: left;
            margin: 20px auto;
            max-width: 400px;
            list-style: none;
            padding: 0;
        }
        
        #blocked-message li {
            padding: 8px 0;
            color: #ffd93d;
        }
        
        #blocked-message li:before {
            content: "→ ";
            margin-right: 8px;
        }
        
        /* Show error only if JavaScript is disabled */
        #js-required-message {
            display: none;
            visibility: visible;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: #1a1a2e;
            color: #fff;
            align-items: center;
            justify-content: center;
            z-index: 10001;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        #js-required-message .message-box {
            text-align: center;
            padding: 40px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            max-width: 500px;
        }
        
        #js-required-message h1 {
            color: #ff6b6b;
            margin-bottom: 20px;
        }
        
        #js-required-message p {
            font-size: 16px;
            line-height: 1.6;
            margin-bottom: 15px;
        }
    </style>
    
    <!-- Only show error if JavaScript is completely disabled -->
    <noscript>
        <style>
            #loading-overlay { display: none; }
            #js-required-message { display: flex !important; }
        </style>
        <div id="js-required-message">
            <div class="message-box">
                <h1>⚠️ JavaScript Required</h1>
                <p>This page requires JavaScript to function properly.</p>
                <p><strong>Please enable JavaScript in your browser settings and refresh this page.</strong></p>
            </div>
        </div>
    </noscript>
        <?php
    }
    
    /**
     * Render the blocking UI elements in the body
     * Call this right after <body> tag
     */
    public function renderBlockingElements() {
        if (!$this->needsFingerprinting) {
            return;
        }
        ?>
<!-- Silent loading overlay (no mention of fingerprinting) -->
<div id="loading-overlay">
    <div class="spinner"></div>
</div>

<!-- Error message if scripts are blocked by ad blocker or browser -->
<div id="blocked-message">
    <div class="message-box">
        <h1>⚠️ Scripts Blocked</h1>
        <p>Certain JavaScript scripts required for this page are being blocked.</p>
        <p><strong>Please try the following:</strong></p>
        <ul>
            <li>Disable your ad blocker for this site</li>
            <li>Disable browser extensions that block scripts</li>
            <li>Check your browser's privacy/security settings</li>
            <li>Whitelist this site in your security software</li>
        </ul>
        <p style="font-size: 14px; opacity: 0.7; margin-top: 20px;">
            After making changes, please refresh this page.
        </p>
    </div>
</div>

<script>
// Silent fingerprinting with error detection
(function() {
    const TIMEOUT = <?php echo $this->config['timeout']; ?>;
    const BLOCKED_CHECK_DELAY = <?php echo $this->config['blocked_check_delay']; ?>;
    
    let fingerprintCompleted = false;
    
    const timeoutId = setTimeout(function() {
        if (!fingerprintCompleted) {
            showBlockedMessage();
        }
    }, TIMEOUT);
    
    // Check if fingerprinting script has loaded
    setTimeout(function() {
        if (!window.FINGERPRINT_STARTED && !fingerprintCompleted) {
            showBlockedMessage();
        }
    }, BLOCKED_CHECK_DELAY);
    
    function showBlockedMessage() {
        clearTimeout(timeoutId);
        document.getElementById('loading-overlay').style.display = 'none';
        document.getElementById('blocked-message').classList.add('show');
    }
    
    // Listen for fingerprint completion
    window.addEventListener('fingerprintSuccess', function() {
        fingerprintCompleted = true;
        clearTimeout(timeoutId);
    });
    
    window.addEventListener('fingerprintError', function(e) {
        clearTimeout(timeoutId);
        showBlockedMessage();
    });
})();
</script>
        <?php
    }
    
    /**
     * Render fingerprint scripts
     * Call this before </body> tag
     */
    public function renderScripts() {
        if (!$this->needsFingerprinting || !$this->fingerprintModule) {
            return;
        }
        
        // Delegate to fingerprint module
        $this->fingerprintModule->renderScripts();
    }
    
    /**
     * Get the fingerprint module instance
     * 
     * @return FingerprintModule|null
     */
    public function getModule() {
        return $this->fingerprintModule;
    }
}
