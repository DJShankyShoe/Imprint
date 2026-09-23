<?php
require_once $_SERVER['DOCUMENT_ROOT'] . '/modules/jwe_module.php';
require_once $_SERVER['DOCUMENT_ROOT'] . '/includes/actions/action_engine.php';
require_once '/opt/imprint/imprint_client.php';

// Actions for this request (set by updateTokenActions, read by executeActions)
function actionCache($actions = null)
{
	static $cached = null;
	if ($actions !== null) {
		$cached = $actions;
	}
	return $cached;
}

// Read the visitor's UID from the Imprint tracking cookie
function trackingUID()
{
	$jwe = new JWEModule();
	$token = $_COOKIE['imprint_uid'] ?? null;
	$session = $token ? $jwe->verifyToken($token) : false;
	return ($session && !empty($session['UID'])) ? $session['UID'] : null;
}

function updateTokenActions()
{
	$uid = trackingUID();
	// Get actions from the Imprint service
	$actions = $uid ? imprint_decision($uid) : [];
	actionCache($actions);
	return $actions;
}

function executeActions($ctx)
{
	$actions = actionCache();
	if ($actions === null) {
		$actions = updateTokenActions();
	}
	if (!empty($actions)) {
		require_once $_SERVER['DOCUMENT_ROOT'] . '/includes/actions/enforce_action.php';
		enforce_action($actions);
	}
}
?>
