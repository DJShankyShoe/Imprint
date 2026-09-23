<?php
/**
 * Imprint Service Client - Calls the Imprint service API
 *
 * Settings (/opt/imprint/.env):
 *   IMPRINT_SERVICE_URL  e.g. http://imprint:8080
 *   IMPRINT_SITE_TOKEN   site API token
 */

require_once '/opt/imprint/env.php';

// Fallback actions if the service is down
const IMPRINT_FAILSAFE_ACTIONS = ['CAPTCHA'];

// Send request to the service, returns [status, json]
function imprint_request(string $method, string $path, ?string $body = null, array $headers = [], int $timeout = 3): array {
    $base  = rtrim((string)imprint_env('IMPRINT_SERVICE_URL', 'http://127.0.0.1:8080'), '/');
    $token = (string)imprint_env('IMPRINT_SITE_TOKEN', '');

    $ch = curl_init($base . $path);
    curl_setopt_array($ch, [
        CURLOPT_CUSTOMREQUEST  => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 2,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_HTTPHEADER     => array_merge(["Authorization: Bearer {$token}"], $headers),
    ]);
    if ($body !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    }
    $response = curl_exec($ch);
    $status   = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    if ($response === false) {
        error_log('imprint_request ' . $path . ' failed: ' . curl_error($ch));
    }
    curl_close($ch);

    $decoded = is_string($response) ? json_decode($response, true) : null;
    return [$status, is_array($decoded) ? $decoded : null];
}

// Create one-time collection slot
function imprint_create_slot(): ?array {
    [$status, $data] = imprint_request('POST', '/api/v1/slots');
    return ($status === 200 && !empty($data['slot'])) ? $data : null;
}

// Send fingerprint submission to the service
function imprint_collect(string $slot, string $secret, string $body, string $clientIp): array {
    $path = '/api/v1/collect/' . rawurlencode($slot) . '?s=' . rawurlencode($secret);
    [$status, $data] = imprint_request('POST', $path, $body, [
        'Content-Type: application/octet-stream',
        'X-Client-IP: ' . $clientIp,
    ], 10);
    return [$status, $data['uid'] ?? null];
}

// Get actions for a visitor
function imprint_decision(string $uid): array {
    [$status, $data] = imprint_request('GET', '/api/v1/decision?uid=' . rawurlencode($uid));
    if ($status !== 200 || !isset($data['actions']) || !is_array($data['actions'])) {
        return IMPRINT_FAILSAFE_ACTIONS;
    }
    return $data['actions'];
}

// Check if a fingerprint exists for a UID (null if service is down)
function imprint_has_fingerprint(string $uid): ?bool {
    [$status, $data] = imprint_request('GET', '/api/v1/fingerprints/' . rawurlencode($uid));
    if ($status !== 200 || !isset($data['exists'])) {
        return null;
    }
    return (bool)$data['exists'];
}
