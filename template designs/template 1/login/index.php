<?php
###########################################################
/*
Simple Login Script
Copyright (C) StivaSoft ltd. All rights Reserved.
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program.  If not, see http://www.gnu.org/licenses/gpl-3.0.html.
For further information visit:
http://www.phpjabbers.com/
info@phpjabbers.com
Version:  2.0
Released: 2020-06-09
*/
###########################################################

// declare(strict_types=1);
// error_reporting(-1); // maximum errors
// ini_set('display_errors', '1');

session_start();
error_reporting(0);
?>

<!DOCTYPE html>
<html>
<head>
    <noscript>
       This page needs JavaScript activated to work.
       <style>div { display:none; }</style>
    </noscript>
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
    <style class="cp-pen-styles">
    </style>

    <!-- Added for fingerprint -->
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <!-- Added for fingerprint -->

    <link rel="shortcut icon" href="images/favicon.png" >
</head>
<body>

<meta name="viewport" content="width=800" />
<!--
<div id="preloader">
  <div id="status">
     <img src="images/preloader.gif" height="64" width="64" alt="">
  </div>
</div>
-->

<div class="wrapper">
    <div class="container">
        <h1>Admin Panel</h1>
        <?php

        function logLoginStatus($user, $randStr, $status){
          $time = '[' . date('d:M:Y:H:i:s', time()) . ' +0000] ';
          $log = $time . $randStr . " User " . $user . " attempted a " . $status . " login\n";

          $fh = fopen('/var/log/scythe/status.txt', 'a');
          fwrite($fh, $log);
          fclose($fh);
        }

        $error = '';

        // action when logout is pressed
        if (isset($_GET['ac']) && $_GET['ac'] == 'logout') {
            $_SESSION['user_info'] = null;
            unset($_SESSION['user_info']);
        }

        // Added for fingerprint
		
		require "../manage.php";

        if (!isset($_SESSION["randStr"])) {
          header('Location: process.php');
          exit();
        }

        $randStr = $_SESSION["randStr"];
        exec("python3 /opt/scripts/check.py $randStr 2>&1", $output, $return_var);
        $alert = $output[0];

        if (isset($_GET['cap'])) {
          $value = '<div class="g-recaptcha" style="center; margin-top:50px; margin-left:65px" data-sitekey="' . $sitePub . '"></div>';
          $page = '/login/?cap=t';
          $captcha_val = "unidentified";
        } else {
          $value = "";
          $page = '/login/';
          $captcha_val = "notActive";
        }


        if ($alert == "captcha" && $captcha_val == "notActive") {
            header("Location: /login/?cap=t");
            exit();
        } elseif ($alert != "captcha" && $captcha_val == "unidentified") {
            header("Location: /login");
            exit();
        } elseif ($alert == "block") {
            $_SESSION['user_info'] = null;
            unset($_SESSION['user_info']);
            header("Location: /blocked.html");
            exit();
        }

        // Added for fingerprint


        if (isset($_POST['is_login'])) {

            $userlist = file ('/opt/signatures/creds.txt');
            $success = false;
			sleep(1);
      	    foreach ($userlist as $user) {
      	        $user_details = explode(' ', $user);
      	        if ($user_details[0] == $_POST['email'] && $user_details[1] == $_POST['password']) {
      		          $success = true;
      		          break;
      	        }
      	    }

            // Added for fingerprint

            if (isset($_GET['cap'])) {
              $captcha_val = captchaValidate();
            }


            if ($success && $alert == "captcha" && $captcha_val == "success"){
                $_SESSION['user_info'] = "WDFWZWJURjR4NXVYbTlwMFUxaUZiM1hXbUxUaERYcXJQYnRRU1lLZA==";
                $_SESSION['username'] = (explode('@', $user_details[0])[0]);
                logLoginStatus($_POST['email'], $randStr, "successful");

            } elseif ($success && $alert == "none") {
                $_SESSION['user_info'] = "WDFWZWJURjR4NXVYbTlwMFUxaUZiM1hXbUxUaERYcXJQYnRRU1lLZA==";
                $_SESSION['username'] = (explode('@', $user_details[0])[0]);
                logLoginStatus($_POST['email'], $randStr, "successful");

            } elseif ($alert == "captcha" && $captcha_val == "failed") {
                $error = '- Captcha Required!';

            } elseif ($success && $alert != "none" && $alert != "block" && $alert != "captcha") {
                $error = 'something went wrong - Try using Chrome!';

            } else {
                logLoginStatus($_POST['email'], $randStr, "failed");
                $error = 'Wrong email or password!';
            }

            // Added for fingerprint

        }

        if ($error !==''){
            ?><div class="alert alert-danger">
                <strong>Error</strong> <?php echo $error; ?>
            </div>
            <?php
        }
        ?>
        <?php
        // logged in info
        if (isset($_SESSION['user_info'])) { ?>

            <form id="login-form" class="login-form" name="form1">

                <div id="form-content">
                    <?php
                      echo '<div class="welcome">' . $_SESSION['username'] . ', you are logged in - Rights : Admin';
                      header("refresh:5;url=/home");
                    ?>
                        <br/><br/>
                        <a href="index.php?ac=logout" style="color:#006400">Logout</a>
                    </div>
                </div>

            </form>

        <?php } else {
            //login form
            ?>

            <form id="login-form" class="login-form" name="form1" method="post" action="<?php echo $page; ?>">
                <input type="hidden" name="is_login" value="1">
                <input id="email" name="email" class="required" type="email" placeholder="Email">
                <input id="password" name="password" class="required" type="password" placeholder="Password">
                <div class="row"><button type="submit" id="login-button">Login</button></div>

                <!-- Added for fingerprint -->
                <?php
                  if (isset($value)){
                    echo $value;
                  }
                ?>
                <!-- Added for fingerprint -->

            </form>
        <?php } ?>
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
</body>
</html>
