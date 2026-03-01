<?php
require_once $_SERVER['DOCUMENT_ROOT'] . '/modules/jwe_module.php';

function updateTokenActions()
{
	$jwe = new JWEModule();
	$token = $_COOKIE['sess_jwe'] ?? null;
	$session = $token ? $jwe->verifyToken($token) : false;
	// Check if we have a valid token
	$hasValidToken = ($session && !empty($session['UID']));
	// Determine what to do
	if ($hasValidToken) {
		$status = $session['status'] ?? 'logout';
		$userUID = $session['UID'];


		$output = null;
		$retval = null;
		$actions = exec("python3 /opt/honeyprint/check.py" . escapeshellarg($userUID) . " 2>&1", $output, $retval);
		
		// Print to console for debugging purposes
		// Remove before deployment to production
		if (!empty($output)) {
			echo "<script>console.log('Alert Check Output:', " . json_encode($output) . ");</script>\n";
		}
		$session['actions'] =  $actions;
	}

	$newToken = $jwe->createToken($session);
	$_COOKIE['sess_jwe'] = $newToken;
	return $actions;
}
?>
