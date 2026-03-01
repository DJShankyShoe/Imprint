<?php
/**
 * JWE (JSON Web Encryption) Module
 * 
 * Handles RSA-OAEP encryption for secure token generation and verification
 * 
 * Usage:
 *   require_once 'jwe_module.php';
 *   
 *   // Generate token
 *   $jwe = new JWEModule();
 *   $token = $jwe->createToken(['user_id' => 123, 'role' => 'admin'], 3600);
 *   
 *   // Verify and decode token
 *   $payload = $jwe->verifyToken($token);
 *   if ($payload) {
 *       echo "User ID: " . $payload['user_id'];
 *   }
 */

class JWEModule {
    
    private $publicKeyPath;
    private $privateKeyPath;
    private $publicKey;
    private $privateKey;
    private $algorithm = 'RSA-OAEP';
    private $encryption = 'A256GCM';
    
    /**
     * Initialize JWE Module
     * 
     * @param array $config Configuration options
     */
    public function __construct($config = []) {
        $defaults = [
            'publicKeyPath' => '/opt/keys/server_public.pem',
            'privateKeyPath' => '/opt/keys/server_private.pem',
            'algorithm' => 'RSA-OAEP',
            'encryption' => 'A256GCM'
        ];
        
        $config = array_merge($defaults, $config);
        
        $this->publicKeyPath = $config['publicKeyPath'];
        $this->privateKeyPath = $config['privateKeyPath'];
        $this->algorithm = $config['algorithm'];
        $this->encryption = $config['encryption'];
        
        // Load keys
        $this->loadKeys();
    }
    
    /**
     * Load RSA keys from files
     */
    private function loadKeys() {
        // Load public key
        if (!file_exists($this->publicKeyPath)) {
            throw new Exception("Public key not found: " . $this->publicKeyPath);
        }
        
        $publicKeyPem = file_get_contents($this->publicKeyPath);
        $this->publicKey = openssl_pkey_get_public($publicKeyPem);
        
        if (!$this->publicKey) {
            throw new Exception("Invalid public key");
        }
        
        // Load private key
        if (!file_exists($this->privateKeyPath)) {
            throw new Exception("Private key not found: " . $this->privateKeyPath);
        }
        
        $privateKeyPem = file_get_contents($this->privateKeyPath);
        $this->privateKey = openssl_pkey_get_private($privateKeyPem);
        
        if (!$this->privateKey) {
            throw new Exception("Invalid private key");
        }
    }
    
    /**
     * Create an encrypted JWE token
     * 
     * @param array $payload Data to encrypt (will be JSON encoded)
     * @param int $expiresIn Expiration time in seconds (default: 3600 = 1 hour)
     * @return string JWE token (5-part compact serialization)
     */
    public function createToken($payload, $expiresIn = 3600) {
        // Add standard claims
        $now = time();
        $payload['iat'] = $now;              // Issued at
        $payload['exp'] = $now + $expiresIn; // Expiration
        $payload['nbf'] = $now;              // Not before
        
        // Convert payload to JSON
        $plaintextPayload = json_encode($payload);
        
        // Generate random AES key (256-bit for A256GCM)
        $aesKey = openssl_random_pseudo_bytes(32); // 256 bits
        
        // Generate random IV (96-bit for GCM)
        $iv = openssl_random_pseudo_bytes(12); // 12 bytes = 96 bits
        
        // Encrypt the payload with AES-256-GCM
        $ciphertext = openssl_encrypt(
            $plaintextPayload,
            'aes-256-gcm',
            $aesKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );
        
        if ($ciphertext === false) {
            throw new Exception("Encryption failed");
        }
        
        // Encrypt the AES key with RSA-OAEP
        $encryptedKey = '';
        $result = openssl_public_encrypt(
            $aesKey,
            $encryptedKey,
            $this->publicKey,
            OPENSSL_PKCS1_OAEP_PADDING
        );
        
        if (!$result) {
            throw new Exception("RSA key encryption failed");
        }
        
        // Build JWE Header
        $header = [
            'alg' => $this->algorithm,  // RSA-OAEP
            'enc' => $this->encryption,  // A256GCM
            'typ' => 'JWE'
        ];
        
        $encodedHeader = $this->base64UrlEncode(json_encode($header));
        
        // Empty encrypted key (CEK) for compact serialization
        $encodedEncryptedKey = $this->base64UrlEncode($encryptedKey);
        
        // IV
        $encodedIv = $this->base64UrlEncode($iv);
        
        // Ciphertext + Authentication Tag (GCM appends tag)
        $encodedCiphertext = $this->base64UrlEncode($ciphertext);
        
        // Authentication Tag
        $encodedTag = $this->base64UrlEncode($tag);
        
        // JWE Compact Serialization: header.encrypted_key.iv.ciphertext.tag
        return implode('.', [
            $encodedHeader,
            $encodedEncryptedKey,
            $encodedIv,
            $encodedCiphertext,
            $encodedTag
        ]);
    }
    
    /**
     * Verify and decrypt a JWE token
     * 
     * @param string $token JWE token
     * @return array|false Decrypted payload or false if invalid
     */
    public function verifyToken($token) {
        try {
            // Split token into 5 parts
            $parts = explode('.', $token);
            
            if (count($parts) !== 5) {
                return false;
            }
            
            list($encodedHeader, $encodedEncryptedKey, $encodedIv, $encodedCiphertext, $encodedTag) = $parts;
            
            // Decode header
            $header = json_decode($this->base64UrlDecode($encodedHeader), true);
            
            if (!$header || !isset($header['alg'], $header['enc'])) {
                return false;
            }
            
            // Verify algorithm
            if ($header['alg'] !== $this->algorithm || $header['enc'] !== $this->encryption) {
                return false;
            }
            
            // Decode components
            $encryptedKey = $this->base64UrlDecode($encodedEncryptedKey);
            $iv = $this->base64UrlDecode($encodedIv);
            $ciphertext = $this->base64UrlDecode($encodedCiphertext);
            $tag = $this->base64UrlDecode($encodedTag);
            
            // Decrypt AES key with RSA private key
            $aesKey = '';
            $result = openssl_private_decrypt(
                $encryptedKey,
                $aesKey,
                $this->privateKey,
                OPENSSL_PKCS1_OAEP_PADDING
            );
            
            if (!$result) {
                return false;
            }
            
            // Decrypt payload with AES-256-GCM
            $plaintext = openssl_decrypt(
                $ciphertext,
                'aes-256-gcm',
                $aesKey,
                OPENSSL_RAW_DATA,
                $iv,
                $tag
            );
            
            if ($plaintext === false) {
                return false;
            }
            
            // Decode JSON payload
            $payload = json_decode($plaintext, true);
            
            if (!$payload) {
                return false;
            }
            
            // Verify expiration
            if (isset($payload['exp']) && $payload['exp'] < time()) {
                return false; // Token expired
            }
            
            // Verify not before
            if (isset($payload['nbf']) && $payload['nbf'] > time()) {
                return false; // Token not yet valid
            }
            
            return $payload;
            
        } catch (Exception $e) {
            return false;
        }
    }
    
    /**
     * Base64 URL encode (RFC 4648)
     * 
     * @param string $data Data to encode
     * @return string Base64 URL encoded string
     */
    private function base64UrlEncode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
    
    /**
     * Base64 URL decode (RFC 4648)
     * 
     * @param string $data Base64 URL encoded string
     * @return string Decoded data
     */
    private function base64UrlDecode($data) {
        return base64_decode(strtr($data, '-_', '+/'));
    }
    
    /**
     * Get token payload without verification (for debugging)
     * WARNING: Do not use for authentication - use verifyToken() instead
     * 
     * @param string $token JWE token
     * @return array|false Token header and metadata
     */
    public function inspectToken($token) {
        $parts = explode('.', $token);
        
        if (count($parts) !== 5) {
            return false;
        }
        
        $header = json_decode($this->base64UrlDecode($parts[0]), true);
        
        return [
            'header' => $header,
            'parts' => count($parts),
            'valid_structure' => true
        ];
    }
    
    /**
     * Check if token is expired (without full verification)
     * 
     * @param string $token JWE token
     * @return bool True if expired, false if valid or cannot determine
     */
    public function isExpired($token) {
        $payload = $this->verifyToken($token);
        
        if (!$payload) {
            return true; // Invalid token = treat as expired
        }
        
        if (isset($payload['exp'])) {
            return $payload['exp'] < time();
        }
        
        return false;
    }
    
    /**
     * Refresh a token (create new token with same payload but new expiration)
     * 
     * @param string $token Existing token
     * @param int $expiresIn New expiration time in seconds
     * @return string|false New token or false if original token invalid
     */
    public function refreshToken($token, $expiresIn = 3600) {
        $payload = $this->verifyToken($token);
        
        if (!$payload) {
            return false;
        }
        
        // Remove old timing claims (they'll be regenerated)
        unset($payload['iat'], $payload['exp'], $payload['nbf']);
        
        return $this->createToken($payload, $expiresIn);
    }
    
    /**
     * Modify an existing token's payload
     * This decrypts, modifies, and re-encrypts the token
     * 
     * @param string $token Original token
     * @param array $updates Key-value pairs to update/add
     * @param int|null $expiresIn New expiration (null = keep original)
     * @return string|false New token or false if original invalid
     */
    public function modifyToken($token, $updates = [], $expiresIn = null) {
        // Verify and decode original token
        $payload = $this->verifyToken($token);
        
        if (!$payload) {
            return false; // Invalid token
        }
        
        // Apply updates
        foreach ($updates as $key => $value) {
            $payload[$key] = $value;
        }
        
        // Remove old timing claims (will be regenerated)
        unset($payload['iat'], $payload['nbf']);
        
        // Determine expiration
        if ($expiresIn !== null) {
            // Use new expiration
            unset($payload['exp']);
            return $this->createToken($payload, $expiresIn);
        } else {
            // Keep original expiration
            $originalExp = $payload['exp'] ?? (time() + 3600);
            $remainingTime = $originalExp - time();
            
            if ($remainingTime <= 0) {
                return false; // Token expired
            }
            
            unset($payload['exp']);
            return $this->createToken($payload, $remainingTime);
        }
    }
    
    /**
     * Add claims to existing token
     * Convenience method for adding without removing existing data
     * 
     * @param string $token Original token
     * @param array $claims Claims to add
     * @return string|false New token or false if invalid
     */
    public function addClaims($token, $claims) {
        return $this->modifyToken($token, $claims, null);
    }
    
    /**
     * Remove claims from existing token
     * 
     * @param string $token Original token
     * @param array $claimKeys Array of keys to remove
     * @return string|false New token or false if invalid
     */
    public function removeClaims($token, $claimKeys) {
        $payload = $this->verifyToken($token);
        
        if (!$payload) {
            return false;
        }
        
        // Remove specified keys
        foreach ($claimKeys as $key) {
            unset($payload[$key]);
        }
        
        // Preserve expiration
        $exp = $payload['exp'] ?? (time() + 3600);
        $remainingTime = $exp - time();
        
        if ($remainingTime <= 0) {
            return false;
        }
        
        unset($payload['iat'], $payload['exp'], $payload['nbf']);
        return $this->createToken($payload, $remainingTime);
    }
    
    /**
     * Update specific claim value
     * 
     * @param string $token Original token
     * @param string $claimKey Key to update
     * @param mixed $claimValue New value
     * @return string|false New token or false if invalid
     */
    public function updateClaim($token, $claimKey, $claimValue) {
        return $this->modifyToken($token, [$claimKey => $claimValue], null);
    }
}
