<?php
declare(strict_types=1);
if (session_status() !== PHP_SESSION_ACTIVE) session_start();

function action_otp(array $ctx = []): void
{
    $_SESSION['otp_required'] = 1;
    unset($_SESSION['otp_verified'], $_SESSION['otp_ok_until']); // clean state

    $uri = $_SERVER['REQUEST_URI'] ?? '/';
    $parts = parse_url($uri);
    $path = $parts['path'] ?? '/';

    parse_str($parts['query'] ?? '', $q);
    unset($q['a']); // remove action trigger like ?a=OTP
    $query = http_build_query($q);

    $_SESSION['return_after_otp'] = $ctx['return_url'] ?? ($query ? ($path . '?' . $query) : $path);
}