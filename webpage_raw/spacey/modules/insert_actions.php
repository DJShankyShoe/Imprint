<?php
require_once $_SERVER['DOCUMENT_ROOT'] . '/modules/jwe_module.php';
require_once $_SERVER['DOCUMENT_ROOT'] . '/includes/actions/action_engine.php';
require_once '/opt/imprint/imprint_client.php';

function updateTokenActions()
{
	$jwe = new JWEModule();
	$token = $_COOKIE['sess_jwe'] ?? null;
	$session = $token ? $jwe->verifyToken($token) : false;
	$actions = [];
	// Check if we have a valid token
	$hasValidToken = ($session && !empty($session['UID']));
	// Determine what to do
	if ($hasValidToken) {
		$status = $session['status'] ?? 'logout';
		$userUID = $session['UID'];

		// Get actions from the Imprint service
		$actions = imprint_decision($userUID);
		$session['actions'] =  $actions;
	}

	$newToken = $jwe->createToken($session);
	$_COOKIE['sess_jwe'] = $newToken;
	return $actions;
}

function executeActions($ctx)
{
	$jwe = new JWEModule();
	$token = $_COOKIE['sess_jwe'] ?? null;
	$session = $token ? $jwe->verifyToken($token) : false;
	// Check if we have a valid token
	$hasValidToken = ($session && !empty($session['UID']));
	// Determine what to do
	if ($hasValidToken) {
		$actions = $session['actions'];
		require_once $_SERVER['DOCUMENT_ROOT'] . '/includes/actions/enforce_action.php';
		enforce_action($actions);
	}
}
?>
