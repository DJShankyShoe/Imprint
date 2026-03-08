<?php
require_once $_SERVER['DOCUMENT_ROOT'] . '/auth_scripts/jwe_module.php';

$jwe = new JWEModule();
$token = $_COOKIE['sess_jwe'] ?? null;
$session = $token ? $jwe->verifyToken($token) : false;
// Check if we have a valid token
$hasValidToken = ($session && !empty($session['UID']));
// Determine what to do
if ($hasValidToken) {
	$status = $session['status'] ?? 'logout';
	$userUID = $session['UID'];

	// If user is logged in, redirect to home
	if ($status === 'pass') {
		header('Location: /home');
		exit;
	}

	$actions = exec("python3 /opt/honeyprint/check.py $userUID 2>&1");
	$session['actions'] =  $actions;
}

$newToken = $jwe->createToken($session);
$_COOKIE['sess_jwe'] = $newToken;

?>
