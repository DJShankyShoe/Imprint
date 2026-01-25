<?php

if ( ! ($_SERVER['HTTP_HOST'] == 'localhost' || $_SERVER['REMOTE_ADDR'] == '127.0.0.1') ) {
    header("HTTP/1.1 404 Not Found");
    exit();
}

if (isset($_GET['id'])) {
  $id = $_GET['id'];

  if (isset($_GET['type'])) {

    if ($_GET['type'] == "finger"){
      $data = file_get_contents("/var/log/scythe/fingerprint.txt");
      $pattern = '/\[\d+:\w+:\d+:\d+:\d+:\d+\s(\W|\D)\d+\]\s' . $id . '\s(.*)/';

      preg_match($pattern, $data, $match);
      $array = json_decode($match[2], true);
      $json_string = json_encode($array, JSON_PRETTY_PRINT);

      header('Content-Type: application/json');
      echo $json_string;

    }elseif ($_GET['type'] == "yara") {
      $data = file_get_contents("/opt/signatures/live.yara");
      $data = str_replace("\\","\\\\", $data);
      
      exec("python3 -c 'import re; data = \"\"\"" . nl2br($data) . "\"\"\"; x = re.search(\"(rule\\\\s$id:\\\\slevel_\\\\d(.|\\n)*})\", data); print(\"rule\" + x.group().split(\"rule\")[1])'", $output, $return_var);
	  
      foreach($output as $value) {
        print $value;
      }
    }
  }
}

?>