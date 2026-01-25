<?php

function generateRandomString($length = 39) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
	$only_alpha = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString = $only_alpha[rand(0, strlen($only_alpha)-1)];
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
    }
    return $randomString;
}

function captchaValidate(){
  // give your captcha secret key
  $secret = "";
  
  $response = $_POST["g-recaptcha-response"];
  $remoteip = $_SERVER["REMOTE_ADDR"];
  $url = "https://www.google.com/recaptcha/api/siteverify?secret=$secret&response=$response&remoteip=$remoteip";
  $data = file_get_contents($url);
  $row = json_decode($data, true);

  if ($row['success'] == "true") {
    // echo "<script>alert('good');</script>";
    $captcha_val = "success";
  } else {
    // echo "<script>alert('bad');</script>";
    $captcha_val = "failed";
  }

  return $captcha_val;
}

// give your captcha site key
$sitePub = "";

?>
