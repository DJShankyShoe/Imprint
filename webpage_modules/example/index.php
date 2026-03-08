<?php
// ===== INCLUDE MODULAR AUTHENTICATION MODULE =====
require_once $_SERVER['DOCUMENT_ROOT'] . '/modules/auth_check.php';

// Configuration: auto-redirect to /home if already logged in
$auth = new AuthCheck([
    'auto_redirect' => true,
    'redirect_on_login' => '/home'
]);

// ===== CHECK IF FINGERPRINTING IS NEEDED =====
$needsFingerprinting = $auth->needsFingerprinting(
    $_SERVER['DOCUMENT_ROOT'] . '/fingerprint_scripts/fingerprint_module.php'
);

// ===== INCLUDE MODULAR FINGERPRINT LOADER =====
require_once $_SERVER['DOCUMENT_ROOT'] . '/fingerprint_scripts/fingerprint_loader.php';
$fpLoader = new FingerprintLoader($needsFingerprinting);

// ===== ERROR REPORTING (disable in production) =====
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Zebrapal | Login</title>
    <meta name="description" content="">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="//code.jquery.com/jquery-1.11.1.min.js"></script>
    <link href="//netdna.bootstrapcdn.com/bootstrap/3.0.0/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
    <link rel="stylesheet" href="css/main.css">
    <script src="//netdna.bootstrapcdn.com/bootstrap/3.0.0/js/bootstrap.min.js"></script>
    <script src="//cdnjs.cloudflare.com/ajax/libs/jquery-validate/1.19.2/jquery.validate.min.js"></script>
    <script src="js/main.js"></script>
    <link rel="shortcut icon" href="images/favicon.png" >
    
    <?php
    // Render blocking UI styles (loading spinner, error messages)
    $fpLoader->renderBlockingUI();
    ?>
</head>
<body>

<meta name="viewport" content="width=800" />

<?php
// Render blocking elements (spinner, blocked message)
$fpLoader->renderBlockingElements();
?>

<div class="wrapper">
    <div class="container">
        <h1>Admin Panel</h1>
        <?php
        
        function logLoginStatus($user, $uid, $status){
            $time = '[' . date('d:M:Y:H:i:s', time()) . ' +0000] ';
            $log = $time . $uid . " User " . $user . " attempted a " . $status . " login\n";
            
            $fh = fopen('/var/log/honeyprint/status.txt', 'a');
            fwrite($fh, $log);
            fclose($fh);
        }
        
        $error = '';
        
        if (isset($_POST['is_login'])) {
            
            // Hardcoded credentials
            $validUsername = 'admin';
            $validPassword = 'admin';
            
            $inputUsername = $_POST['username'] ?? '';
            $inputPassword = $_POST['password'] ?? '';
            
            sleep(1); // Delay to prevent brute force
            
            // Check credentials
            if ($inputUsername === $validUsername && $inputPassword === $validPassword) {
                // Successful login
                $username = $inputUsername;
                
                // Use modular auth to create login token
                $auth->createLoginToken($username);
                
                logLoginStatus($username, $auth->getUID(), "successful");
                
                echo '<div class="welcome">' . $username . ', you are logged in<br/><br/></div>';
                echo '<script>setTimeout(function(){ window.location.href = "/home"; }, 3000);</script>';
            } else {
                // Failed login
                $error = 'Invalid username or password';
                
                // Use UID from token or generate temporary one for logging
                $failUID = $auth->getUID() ?? bin2hex(random_bytes(16));
                logLoginStatus($inputUsername, $failUID, "failed");
            }
        }
        
        if ($error !== '') {
            ?>
            <div class="alert alert-danger">
                <strong>Error</strong> <?php echo $error; ?>
            </div>
            <?php
        }
        ?>
        
        <form id="login-form" class="login-form" name="form1" method="post" action="/login/">
            <input type="hidden" name="is_login" value="1">
            <input id="username" name="username" class="required" type="text" placeholder="Username">
            <input id="password" name="password" class="required" type="password" placeholder="Password">
            <div class="row"><button type="submit" id="login-button">Login</button></div>
        </form>
        
    </div>
    
    <ul class="bg-bubbles">
        <li></li>
        <li></li>
        <li></li>
        <li></li>
        <li></li>
        <li></li>
        <li></li>
        <li></li>
        <li></li>
        <li></li>
    </ul>
</div>

<?php
// Render fingerprint scripts (if needed)
$fpLoader->renderScripts();
?>

</body>
</html>
