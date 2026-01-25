<?php
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
    <div class="wrapper">
        <div class="container">

            <?php
              if (!isset($_SESSION["randStr"])) {

                  require "../manage.php";
                  $randStr = generateRandomString();
                  $_SESSION["randStr"] = $randStr;

                  require "../fingerprint.php";
              }
            ?>


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
