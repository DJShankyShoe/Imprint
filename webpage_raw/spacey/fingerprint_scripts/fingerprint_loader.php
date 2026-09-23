<?php
/**
 * Fingerprint Loader Module
 * 
 * Handles fingerprint collection initialization and rendering.
 * 
 * Usage:
 *   $fpLoader = new FingerprintLoader($needsFingerprinting, ['debug' => true]); // Enable debug
 *   $fpLoader = new FingerprintLoader($needsFingerprinting); // Debug off (default)
 */

class FingerprintLoader {
    
    private $fingerprintModule;
    private $needsFingerprinting;
    private $config;
    
    public function __construct($needsFingerprinting = false, $config = []) {
        $defaults = [
            'fingerprint_module_path' => $_SERVER['DOCUMENT_ROOT'] . '/fingerprint_scripts/fingerprint_module.php',
            'blocked_check_delay' => 3000,  // 3 seconds
            'timeout' => 15000,              // 15 seconds
            'show_loading_spinner' => true,
            'silent_mode' => true,
            'debug' => false,                // Debug logging (off by default)
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
    
    public function shouldCollect() {
        return $this->needsFingerprinting;
    }
    
    public function renderBlockingUI() {
        if (!$this->needsFingerprinting) {
            return;
        }
        ?>
    <style>
        body { visibility: hidden; }
        
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
        
        #blocked-message.show { display: flex; }
        
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
    
    public function renderBlockingElements() {
        if (!$this->needsFingerprinting) {
            return;
        }
        
        $debug = $this->config['debug'] ? 'true' : 'false';
        ?>
<div id="loading-overlay">
    <div class="spinner"></div>
</div>

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
(function() {
    const DEBUG = <?php echo $debug; ?>;
    const TIMEOUT = <?php echo $this->config['timeout']; ?>;
    const BLOCKED_CHECK_DELAY = <?php echo $this->config['blocked_check_delay']; ?>;
    
    function debugLog(...args) {
        if (DEBUG) console.log('[FP Loader]', ...args);
    }
    
    function debugError(...args) {
        if (DEBUG) console.error('[FP Loader]', ...args);
    }
    
    debugLog('========================================');
    debugLog('🔧 Fingerprint Loader Started');
    debugLog('========================================');
    debugLog('Config:');
    debugLog('  Timeout:', TIMEOUT + 'ms');
    debugLog('  Blocked check delay:', BLOCKED_CHECK_DELAY + 'ms');
    debugLog('  Debug mode:', DEBUG ? 'ON' : 'OFF');
    
    let fingerprintCompleted = false;
    
    const cookies = document.cookie.split(';').map(c => c.trim());
    const trackingCookie = cookies.find(c => c.startsWith('imprint_uid='));
    const hasCookie = !!trackingCookie;
    
    debugLog('Checking for existing tracking cookie...');
    debugLog('  imprint_uid cookie present:', hasCookie);
    if (hasCookie && DEBUG) {
        debugLog('  Cookie value:', trackingCookie.substring(0, 50) + '...');
    }
    
    if (hasCookie) {
        debugLog('✅ Session cookie found - showing page immediately');
        document.getElementById('loading-overlay').style.display = 'none';
        document.body.style.visibility = 'visible';
        debugLog('========================================');
        debugLog('✅ Page Unblocked (Cookie Exists)');
        debugLog('========================================');
        return;
    }
    
    debugLog('⚠️  No session cookie - will collect fingerprint');
    debugLog('Starting timers...');
    
    const timeoutId = setTimeout(function() {
        if (!fingerprintCompleted) {
            debugError('❌ TIMEOUT - Fingerprint not completed after', TIMEOUT + 'ms');
            showBlockedMessage();
        }
    }, TIMEOUT);
    debugLog('✓ Set timeout timer:', TIMEOUT + 'ms');
    
    setTimeout(function() {
        debugLog('Checking if fingerprint script loaded...');
        debugLog('  window.FINGERPRINT_STARTED:', window.FINGERPRINT_STARTED);
        debugLog('  fingerprintCompleted:', fingerprintCompleted);
        
        if (!window.FINGERPRINT_STARTED && !fingerprintCompleted) {
            debugError('❌ Fingerprint script did not start - may be blocked');
            showBlockedMessage();
        } else {
            debugLog('✓ Fingerprint script is running');
        }
    }, BLOCKED_CHECK_DELAY);
    debugLog('✓ Set script check timer:', BLOCKED_CHECK_DELAY + 'ms');
    
    function showBlockedMessage() {
        debugError('========================================');
        debugError('⚠️  SHOWING BLOCKED MESSAGE');
        debugError('========================================');
        clearTimeout(timeoutId);
        document.getElementById('loading-overlay').style.display = 'none';
        document.getElementById('blocked-message').classList.add('show');
    }
    
    window.addEventListener('fingerprintSuccess', function() {
        debugLog('========================================');
        debugLog('🎉 fingerprintSuccess event received!');
        debugLog('========================================');
        fingerprintCompleted = true;
        clearTimeout(timeoutId);
        debugLog('✓ Cleared timeout timer');
        debugLog('⏳ Page will reload soon...');
    });
    
    window.addEventListener('fingerprintError', function(e) {
        debugError('========================================');
        debugError('❌ fingerprintError event received!');
        debugError('  Error detail:', e.detail);
        debugError('========================================');
        clearTimeout(timeoutId);
        showBlockedMessage();
    });
    
    debugLog('✓ Event listeners registered');
    debugLog('⏳ Waiting for fingerprint collection...');
})();
</script>
        <?php
    }
    
    public function renderScripts() {
        if (!$this->needsFingerprinting || !$this->fingerprintModule) {
            return;
        }
        
        $this->fingerprintModule->renderScripts();
    }
    
    public function getModule() {
        return $this->fingerprintModule;
    }
}
