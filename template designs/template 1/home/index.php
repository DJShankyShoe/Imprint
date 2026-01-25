<?php

    session_start();
    error_reporting(0);

    $randStr = $_SESSION["randStr"];

    exec("python3 /opt/scripts/check.py $randStr 2>&1", $output, $return_var);
    $alert = $output[0];

    if ($alert == "block") {
        $_SESSION['user_info'] = null;
        unset($_SESSION['user_info']);
        header("Location: /blocked.html");
        exit();
    }

    session_start();
    if (!isset($_SESSION['user_info'])) {
        header("location: /login");
    }
?>

<script>
    if(document.location.href.indexOf('user') > -1) {
        document.location.href = '/home';
    }
</script>

<!DOCTYPE html>
<!--[if lt IE 8 ]><html class="no-js ie ie7" lang="en"> <![endif]-->
<!--[if IE 8 ]><html class="no-js ie ie8" lang="en"> <![endif]-->
<!--[if (gte IE 8)|!(IE)]><!--><html class="no-js" lang="en"> <!--<![endif]-->
<head>

   <!--- Basic Page Needs
   ================================================== -->
   <meta charset="utf-8">
	<title>Zebrapal</title>
	<meta name="description" content="">
	<meta name="author" content="">

   <!-- Mobile Specific Metas
   ================================================== -->
	<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">

	<!-- CSS
    ================================================== -->
   <link rel="stylesheet" href="css/default.css">
	<link rel="stylesheet" href="css/layout.css">
   <link rel="stylesheet" href="css/media-queries.css">

   <!-- Script
   ================================================== -->
	<script src="js/modernizr.js"></script>

   <!-- Favicons
	================================================== -->
	<link rel="shortcut icon" href="images/favicon.png" >

</head>

<body>

    <div id="preloader">
      <div id="status">
         <img src="images/preloader.gif" height="64" width="64" alt="">
      </div>
   </div>

   <!-- Intro Section
   ================================================== -->
   <section id="intro">

   	<header class="row">

		   <nav id="nav-wrap">

		      <a class="menu-btn" href="#nav-wrap" title="Show navigation">Show navigation</a>
			   <a class="menu-btn" href="#" title="Hide navigation">Hide navigation</a>

		      <ul id="nav" class="nav">
                          <li><a class="smoothscroll" href="/login">Login</a></li>
		      </ul> <!-- end #nav -->

		   </nav> <!-- end #nav-wrap -->

   	</header> <!-- Header End -->

   	<div  id="main" class="row">

	   	<div class="twelve columns">

	   		<h1>We are currently working on something awesome. Stay tuned!</h1>

	   		<p>Some rise by sin, and some by virtue fall — from Measure for Measure</p>

	   		<h5>Time Left Until Launching</h5>

			<div id="getting-started"></div>

	   		<div id="counter" class="cf">
	   			<span id="day"></span>
 				<span id="hour"></span>
				<span id="min"></span>
 				<span id="sec"></span>
   			</div>

         </div>

      </div> <!-- main end -->

   </section> <!-- end intro section -->

   <!-- footer
   ================================================== -->
   <footer>

      <div class="row">

         <div class="twelve columns">

            <ul class="copyright">
               <li>&copy; Copyright 2014 Zoon</li>
               <li>Design by <a title="Styleshout" href="http://www.styleshout.com/">Styleshout</a></li>
            </ul>

         </div>

      </div>

      <div id="go-top"><a class="smoothscroll" title="Back to Top" href="#intro"><i class="icon-up-open"></i></a></div>

   </footer> <!-- Footer End-->

   <!-- Java Script
   ================================================== -->
   <script src="http://ajax.googleapis.com/ajax/libs/jquery/1.10.2/jquery.min.js"></script>
   <script src="js/jquery.countdown.js"></script>
   <script src="js/main.js"></script>
   <script src="js/jquery.placeholder.js"></script>
   <script src="js/backstretch.js"></script>
   <script src="js/init.js"></script>

</body>

</html>
