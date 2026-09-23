<?php
/**
 * Fingerprint Collection Module - Uses one-time slots from the Imprint service
 */

require_once '/opt/imprint/imprint_client.php';

class FingerprintModule {

    private $endpointWebPath;
    private $slot = null;

    public function __construct($config = []) {
        $defaults = [
            'endpointWebPath' => "/endpoints/",
        ];
        $config = array_merge($defaults, $config);
        $this->endpointWebPath = rtrim($config['endpointWebPath'], '/') . '/';
    }

    public function hasFingerprintForUID($uid) {
        if (empty($uid)) {
            return false;
        }

        $exists = imprint_has_fingerprint($uid);
        if ($exists === null) {
            // Service down - skip fingerprinting
            error_log("hasFingerprintForUID: Imprint service unreachable");
            return true;
        }
        return $exists;
    }

    // Create slot on first use
    private function getSlot() {
        if ($this->slot === null) {
            $this->slot = imprint_create_slot() ?: false;
            if ($this->slot === false) {
                error_log("FingerprintModule: could not create collection slot");
            }
        }
        return $this->slot;
    }

    public function renderScripts() {
        $slot = $this->getSlot();
        if (!$slot) {
            return;
        }

        $endpointUrl  = htmlspecialchars($this->endpointWebPath . "fp_" . $slot['slot'] . ".php", ENT_QUOTES);
        $secret       = htmlspecialchars($slot['secret'], ENT_QUOTES);
        $rsaPublicKey = json_encode($slot['public_key']);

        echo <<<HTML
<script>
  window.FP_ENDPOINT_URL = "{$endpointUrl}?s={$secret}";
  window.FP_RSA_PUBLIC_KEY_PEM = {$rsaPublicKey};
</script>
<script src="/fingerprint_scripts/fingerprint.js"></script>
HTML;
    }

    public function getEndpointUrl() {
        $slot = $this->getSlot();
        return $slot ? $this->endpointWebPath . "fp_" . $slot['slot'] . ".php?s=" . $slot['secret'] : '';
    }

    // Slots expire in the service
    public function cleanupOldEndpoints($maxAge = 86400) {
    }

    public function getEndpointDir() {
        return '';
    }
}
