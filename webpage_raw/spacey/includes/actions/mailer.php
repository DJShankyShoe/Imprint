<?php

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// require '/var/www/spacey/vendor/autoload.php';

// mailer.php (APT-based PHPMailer)
require_once '/usr/share/php/libphp-phpmailer/autoload.php';

// or if autoload.php doesn't exist on your distro, use:
/// require_once '/usr/share/php/PHPMailer/PHPMailer.php';
/// require_once '/usr/share/php/PHPMailer/SMTP.php';
/// require_once '/usr/share/php/PHPMailer/Exception.php';


function send_mail(string $to, string $subject, string $body): void
{
    $providers = [
        [
            'name' => 'gmail',
            'host' => 'smtp.gmail.com',
            'port' => 587,
            'secure' => PHPMailer::ENCRYPTION_STARTTLS,
            'user' => getenv('GMAIL_USER'),
            'pass' => getenv('GMAIL_APP_PASS'),
            'from_email' => getenv('GMAIL_USER'),
            'from_name' => 'Honeyprint OTP',
        ],
        [
            'name' => 'outlook',
            'host' => 'smtp.office365.com',
            'port' => 587,
            'secure' => PHPMailer::ENCRYPTION_STARTTLS,
            'user' => getenv('OUTLOOK_USER'),
            'pass' => getenv('OUTLOOK_APP_PASS'),
            'from_email' => getenv('OUTLOOK_USER'),
            'from_name' => 'Honeyprint OTP',
        ],
    ];

    $lastErr = null;

    foreach ($providers as $p) {
        if (empty($p['user']) || empty($p['pass'])) {
            continue; // skip if not configured
        }

        $mail = new PHPMailer(true);
        try {
            $mail->isSMTP();
            $mail->Host = $p['host'];
            $mail->SMTPAuth = true;
            $mail->Username = $p['user'];
            $mail->Password = $p['pass'];
            $mail->SMTPSecure = $p['secure'];
            $mail->Port = $p['port'];

            $mail->setFrom($p['from_email'], $p['from_name']);
            $mail->addAddress($to);

            $mail->Subject = $subject;
            $mail->Body = $body;

            $mail->send();
            return; // success
        } catch (Exception $e) {
            $lastErr = $p['name'] . ": " . $mail->ErrorInfo;
        }
    }

    throw new Exception("All SMTP providers failed. Last error: " . ($lastErr ?? "none"));
}
