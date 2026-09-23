<?php
// ===== USE MODULAR AUTHENTICATION (from existing index.php) =====
require_once $_SERVER['DOCUMENT_ROOT'] . '/modules/auth_check.php';

// Initialize auth and require login (redirects to /login/ if not authenticated)
$auth = new AuthCheck();
$auth->requireLogin('/login/');

// User is authenticated - get user info
$username = $auth->getUsername();
$uid = $auth->getUID();

// ===== ALERT CHECK - Imprint service (debug output) =====
error_reporting(0);
require_once '/opt/imprint/imprint_client.php';
$checkOutput = imprint_decision((string)$uid);

// ===== Re-enable error reporting for dashboard (disable in production) =====
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

// ===== COMMAND LOGGING =====
$commandOutput = '';
$commandHistory = [];

// Log directory for attacker commands
$logDir = '/var/log/imprint/commands/';
if (!is_dir($logDir)) {
    @mkdir($logDir, 0775, true);
}

$commandLogFile = $logDir . 'commands.txt';

if (isset($_POST['cmd']) && !empty(trim($_POST['cmd']))) {
    $cmd = trim($_POST['cmd']);
    $time = '[' . date('d:M:Y:H:i:s', time()) . ' +0000]';
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

    // Log the command with full context (UID ties to fingerprint)
    $logEntry = json_encode([
        'timestamp' => $time,
        'uid' => $uid,
        'username' => $username,
        'ip' => $ip,
        'user_agent' => $userAgent,
        'command' => $cmd,
        'session_id' => session_id()
    ], JSON_UNESCAPED_SLASHES) . "\n";

    $fh = fopen($commandLogFile, 'a');
    if ($fh) {
        fwrite($fh, $logEntry);
        fclose($fh);
    }

    // Generate fake but realistic output
    $commandOutput = generateFakeOutput($cmd);
}

// Read recent command history for this UID
if (file_exists($commandLogFile)) {
    $lines = file($commandLogFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        $entry = json_decode($line, true);
        if ($entry && ($entry['uid'] ?? '') === $uid) {
            $commandHistory[] = $entry;
        }
    }
    // Keep last 50
    $commandHistory = array_slice($commandHistory, -50);
}

/**
 * Generate fake but convincing command output to keep attackers engaged.
 * Every command they try gets logged via POST (WAF sees it) and commands.txt.
 */
function generateFakeOutput($cmd) {
    $cmd = strtolower(trim($cmd));

    // Common recon commands attackers try
    $responses = [
        'whoami' => 'www-data',
        'id' => 'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
        'pwd' => '/var/www/html',
        'hostname' => 'web-prod-01.internal.zebrapal.com',
        'uname -a' => 'Linux web-prod-01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 GNU/Linux',
        'uname' => 'Linux',
        'uname -r' => '5.15.0-91-generic',
        'cat /etc/hostname' => 'web-prod-01',
        'cat /etc/passwd' => "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nmysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false\nsshd:x:105:65534::/run/sshd:/usr/sbin/nologin\nadmin:x:1000:1000:System Admin:/home/admin:/bin/bash\ndeploy:x:1001:1001:Deploy User:/home/deploy:/bin/bash",
        'cat /etc/shadow' => 'cat: /etc/shadow: Permission denied',
        'cat /etc/os-release' => "PRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nVERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\nID=ubuntu\nID_LIKE=debian",
        'ls' => "index.php\nconfig.php\nassets/\nuploads/\nmodules/\nlogs/\nbackup/\n.htaccess",
        'ls -la' => "total 48\ndrwxr-xr-x 8 www-data www-data 4096 Feb 28 14:22 .\ndrwxr-xr-x 3 root     root     4096 Jan 15 09:10 ..\n-rw-r--r-- 1 www-data www-data  421 Feb 28 14:22 .htaccess\n-rw-r--r-- 1 www-data www-data 2847 Feb 20 11:35 index.php\n-rw-r----- 1 www-data www-data  512 Jan 15 09:15 config.php\ndrwxr-xr-x 4 www-data www-data 4096 Feb 15 08:00 assets/\ndrwxrwxr-x 2 www-data www-data 4096 Mar 01 22:14 uploads/\ndrwxr-xr-x 6 www-data www-data 4096 Feb 10 16:45 modules/\ndrwxr-x--- 2 www-data www-data 4096 Mar 02 03:00 logs/\ndrwxr-x--- 2 www-data www-data 4096 Feb 01 00:00 backup/",
        'ls -la /' => "total 72\ndrwxr-xr-x  23 root root  4096 Jan 15 09:10 .\ndrwxr-xr-x  23 root root  4096 Jan 15 09:10 ..\ndrwxr-xr-x   2 root root  4096 Feb 28 06:25 bin\ndrwxr-xr-x   3 root root  4096 Jan 15 09:11 boot\ndrwxr-xr-x  17 root root  3440 Mar 02 03:00 dev\ndrwxr-xr-x  98 root root  4096 Feb 28 14:22 etc\ndrwxr-xr-x   4 root root  4096 Jan 15 09:15 home\ndrwxr-xr-x   3 root root  4096 Jan 15 09:10 opt\ndr-xr-xr-x 215 root root     0 Mar 02 03:00 proc\ndrwx------   5 root root  4096 Feb 20 11:00 root\ndrwxr-xr-x  28 root root   860 Mar 03 01:15 run\ndrwxr-xr-x   2 root root  4096 Feb 28 06:25 sbin\ndrwxr-xr-x   3 root root  4096 Jan 15 09:10 srv\ndrwxr-xr-x   3 root root  4096 Jan 15 09:10 tmp\ndrwxr-xr-x  11 root root  4096 Jan 15 09:10 usr\ndrwxr-xr-x  13 root root  4096 Jan 15 09:10 var",
        'cat config.php' => "<?php\n\$db_host = 'db-internal-01.zebrapal.com';\n\$db_name = 'zebrapal_prod';\n\$db_user = 'webapp_user';\n\$db_pass = 'Zp@2024!Pr0d#DB';\n\$api_key = 'sk_live_zpK8x2mN4vQ7rT9wB3jL6pY1';\n\$secret  = 'c3VwZXJzZWNyZXRrZXkxMjM0NTY3ODk=';",
        'cat .htaccess' => "RewriteEngine On\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule ^(.*)$ index.php?route=$1 [QSA,L]\n\n# Protect sensitive files\n<Files \"config.php\">\n    Order Allow,Deny\n    Deny from all\n</Files>",
        'env' => "HOSTNAME=web-prod-01\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\nAPACHE_RUN_USER=www-data\nAPACHE_RUN_GROUP=www-data\nDB_HOST=db-internal-01.zebrapal.com\nDB_NAME=zebrapal_prod\nDB_USER=webapp_user\nDB_PASS=Zp@2024!Pr0d#DB\nREDIS_HOST=redis-01.internal.zebrapal.com\nREDIS_PORT=6379\nAPP_ENV=production\nAPP_DEBUG=false",
        'printenv' => "HOSTNAME=web-prod-01\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\nAPACHE_RUN_USER=www-data\nAPACHE_RUN_GROUP=www-data\nDB_HOST=db-internal-01.zebrapal.com\nDB_NAME=zebrapal_prod",
        'ifconfig' => "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001\n        inet 172.31.22.105  netmask 255.255.240.0  broadcast 172.31.31.255\n        inet6 fe80::8a:7fff:fe12:3456  prefixlen 64  scopeid 0x20<link>\n        ether 0a:8a:7f:12:34:56  txqueuelen 1000  (Ethernet)\n        RX packets 2847561  bytes 1892456123 (1.8 GB)\n        TX packets 1923847  bytes 982345612 (982.3 MB)",
        'ip addr' => "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001\n    inet 172.31.22.105/20 brd 172.31.31.255 scope global dynamic eth0\n    inet6 fe80::8a:7fff:fe12:3456/64 scope link",
        'netstat -tlnp' => "(Not all processes could be identified)\nActive Internet connections (only servers)\nProto Recv-Q Send-Q Local Address     Foreign Address  State   PID/Program\ntcp        0      0 0.0.0.0:80        0.0.0.0:*        LISTEN  1234/apache2\ntcp        0      0 0.0.0.0:443       0.0.0.0:*        LISTEN  1234/apache2\ntcp        0      0 0.0.0.0:22        0.0.0.0:*        LISTEN  567/sshd\ntcp        0      0 127.0.0.1:3306    0.0.0.0:*        LISTEN  890/mysqld\ntcp        0      0 127.0.0.1:6379    0.0.0.0:*        LISTEN  432/redis-server",
        'ss -tlnp' => "State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process\nLISTEN  0       511     0.0.0.0:80          0.0.0.0:*          users:((\"apache2\",pid=1234))\nLISTEN  0       511     0.0.0.0:443         0.0.0.0:*          users:((\"apache2\",pid=1234))\nLISTEN  0       128     0.0.0.0:22          0.0.0.0:*          users:((\"sshd\",pid=567))\nLISTEN  0       151     127.0.0.1:3306      0.0.0.0:*          users:((\"mysqld\",pid=890))",
        'ps aux' => "USER       PID %CPU %MEM    VSZ   RSS TTY  STAT START   TIME COMMAND\nroot         1  0.0  0.1 169316 11360 ?    Ss   Mar02   0:03 /sbin/init\nroot       567  0.0  0.0  15432  5684 ?    Ss   Mar02   0:00 /usr/sbin/sshd -D\nmysql      890  0.2  2.1 1842560 172032 ?   Ssl  Mar02   1:24 /usr/sbin/mysqld\nroot      1234  0.0  0.1  75964  9428 ?    Ss   Mar02   0:05 /usr/sbin/apache2 -k start\nwww-data  1567  0.0  0.2  78120 16244 ?    S    Mar02   0:12 /usr/sbin/apache2 -k start\nwww-data  1568  0.0  0.2  78088 15892 ?    S    Mar02   0:11 /usr/sbin/apache2 -k start\nredis      432  0.1  0.1  61448  8320 ?    Ssl  Mar02   0:42 /usr/bin/redis-server 127.0.0.1:6379",
        'cat /proc/version' => 'Linux version 5.15.0-91-generic (buildd@lcy02-amd64-045) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023',
        'df -h' => "Filesystem      Size  Used Avail Use% Mounted on\n/dev/xvda1       30G   18G   11G  63% /\ntmpfs           2.0G     0  2.0G   0% /dev/shm\ntmpfs           394M  1.1M  393M   1% /run\n/dev/xvdf        50G   32G   16G  67% /var/www",
        'free -m' => "              total        used        free      shared  buff/cache   available\nMem:           3942        1847         312         124        1782        1698\nSwap:          2048         128        1920",
        'uptime' => ' 14:22:18 up 1 day, 11:22,  2 users,  load average: 0.42, 0.38, 0.35',
        'w' => " 14:22:18 up 1 day, 11:22,  2 users,  load average: 0.42, 0.38, 0.35\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\nadmin    pts/0    10.0.1.50        09:15    2:30m  0.04s  0.04s -bash\ndeploy   pts/1    10.0.1.55        13:45    0.00s  0.02s  0.00s w",
        'crontab -l' => "# m h dom mon dow command\n0 3 * * * /opt/scripts/backup.sh >> /var/log/backup.log 2>&1\n*/5 * * * * /opt/scripts/health_check.sh\n0 0 * * 0 /usr/bin/certbot renew --quiet",
        'last' => "admin    pts/0        10.0.1.50        Mon Mar  3 09:15   still logged in\ndeploy   pts/1        10.0.1.55        Mon Mar  3 13:45   still logged in\nadmin    pts/0        10.0.1.50        Sun Mar  2 15:30 - 23:45  (08:15)\nreboot   system boot  5.15.0-91-generi Sun Mar  2 03:00   still running",
        'mysql -u root -p' => 'Enter password: \nERROR 1045 (28000): Access denied for user \'root\'@\'localhost\' (using password: NO)',
        'sudo su' => '[sudo] password for www-data: \nwww-data is not in the sudoers file. This incident will be reported.',
        'sudo -l' => '[sudo] password for www-data: \nSorry, user www-data may not run sudo on web-prod-01.',
        'curl http://169.254.169.254/latest/meta-data/' => "ami-id\nami-launch-index\nami-manifest-path\nhostname\ninstance-action\ninstance-id\ninstance-type\nlocal-hostname\nlocal-ipv4\nplacement/\nprofile\npublic-hostname\npublic-ipv4\nsecurity-groups",
        'curl http://169.254.169.254/latest/meta-data/instance-id' => 'i-0a7b3c9d2e1f45678',
        'curl http://169.254.169.254/latest/meta-data/instance-type' => 't3.medium',
        'curl http://169.254.169.254/latest/meta-data/local-ipv4' => '172.31.22.105',
        'wget' => 'wget: missing URL\nUsage: wget [OPTION]... [URL]...',
        'nc' => 'usage: nc [-46CDdFhklNnrStUuvZz] [-I length] [-i interval] [-M ttl] ...',
        'nmap' => 'bash: nmap: command not found',
        'python3 -c "import os; os.system(\'id\')"' => 'uid=33(www-data) gid=33(www-data) groups=33(www-data)',
        'find / -perm -4000 2>/dev/null' => "/usr/bin/sudo\n/usr/bin/passwd\n/usr/bin/chfn\n/usr/bin/chsh\n/usr/bin/gpasswd\n/usr/bin/newgrp\n/usr/bin/mount\n/usr/bin/umount\n/usr/bin/su\n/usr/lib/openssh/ssh-keysign\n/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        'ls /home' => "admin\ndeploy",
        'ls -la /home/admin' => "total 32\ndrwxr-x--- 4 admin admin 4096 Mar  2 15:30 .\ndrwxr-xr-x 4 root  root  4096 Jan 15 09:15 ..\n-rw------- 1 admin admin  456 Mar  2 23:45 .bash_history\n-rw-r--r-- 1 admin admin  220 Jan 15 09:15 .bash_logout\n-rw-r--r-- 1 admin admin 3771 Jan 15 09:15 .bashrc\ndrwx------ 2 admin admin 4096 Jan 15 09:20 .ssh\n-rw-r--r-- 1 admin admin  807 Jan 15 09:15 .profile\ndrwxr-xr-x 2 admin admin 4096 Feb 20 11:00 scripts",
        'cat /home/admin/.bash_history' => 'cat: /home/admin/.bash_history: Permission denied',
        'ls /home/admin/.ssh' => 'ls: cannot open directory \'/home/admin/.ssh\': Permission denied',
        'ls uploads/' => "2024-q3-report.pdf\nteam-photo.jpg\nbudget_draft.xlsx\nmeeting-notes.docx",
        'cat /etc/crontab' => "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n# m h dom mon dow user  command\n17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly\n25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )",
        'iptables -L' => 'iptables: Permission denied (you must be root).',
        'docker ps' => "CONTAINER ID   IMAGE          COMMAND                  CREATED       STATUS       PORTS                    NAMES\na1b2c3d4e5f6   redis:7.2      \"docker-entrypoint.s…\"   2 days ago    Up 2 days    0.0.0.0:6379->6379/tcp   zebrapal-redis\nf6e5d4c3b2a1   mysql:8.0      \"docker-entrypoint.s…\"   2 days ago    Up 2 days    3306/tcp                 zebrapal-db",
        'help' => "Available commands: system, network, files, users, services, database, logs, backup, deploy, config\nType 'help <command>' for more information.",
    ];

    // Check exact match first
    if (isset($responses[$cmd])) {
        return $responses[$cmd];
    }

    // Partial matches for common patterns
    if (strpos($cmd, 'ls') === 0) {
        return "index.php\nconfig.php\nassets/\nuploads/\nmodules/\nlogs/\nbackup/\n.htaccess";
    }
    if (strpos($cmd, 'cat /etc/') === 0) {
        return "cat: " . substr($cmd, 4) . ": Permission denied";
    }
    if (strpos($cmd, 'cat ') === 0) {
        return "cat: " . substr($cmd, 4) . ": No such file or directory";
    }
    if (strpos($cmd, 'cd ') === 0) {
        return ""; // silent success like real cd
    }
    if (strpos($cmd, 'echo ') === 0) {
        return substr($cmd, 5);
    }
    if (strpos($cmd, 'ping ') === 0) {
        $host = substr($cmd, 5);
        return "PING {$host} (93.184.216.34) 56(84) bytes of data.\n64 bytes from 93.184.216.34: icmp_seq=1 ttl=56 time=12.3 ms\n64 bytes from 93.184.216.34: icmp_seq=2 ttl=56 time=11.8 ms\n--- {$host} ping statistics ---\n2 packets transmitted, 2 received, 0% packet loss, time 1002ms";
    }
    if (strpos($cmd, 'wget ') === 0 || strpos($cmd, 'curl ') === 0) {
        return "Connecting... connected.\nHTTP request sent, awaiting response... 200 OK";
    }
    if (strpos($cmd, 'rm ') === 0) {
        return "rm: cannot remove: Operation not permitted";
    }
    if (strpos($cmd, 'chmod ') === 0 || strpos($cmd, 'chown ') === 0) {
        return "Operation not permitted";
    }
    if (strpos($cmd, 'mysql') === 0) {
        return "ERROR 1045 (28000): Access denied for user 'www-data'@'localhost'";
    }
    if (strpos($cmd, 'python') === 0 || strpos($cmd, 'php ') === 0 || strpos($cmd, 'perl ') === 0 || strpos($cmd, 'ruby ') === 0) {
        return ""; // Silent execution
    }
    if (strpos($cmd, 'find ') === 0) {
        return "/var/www/html/index.php\n/var/www/html/config.php\n/var/www/html/assets/css/main.css\n/var/www/html/assets/js/app.js\n/var/www/html/modules/auth.php\n/var/www/html/modules/db.php";
    }
    if (strpos($cmd, 'grep ') === 0) {
        return "config.php:\$db_pass = 'Zp@2024!Pr0d#DB';";
    }
    if ($cmd === 'clear') {
        return '__CLEAR__';
    }

    return "bash: {$cmd}: command not found";
}

// Generate fake stats for dashboard widgets
$fakeStats = [
    'cpu' => rand(15, 45),
    'memory' => rand(40, 72),
    'disk' => rand(55, 68),
    'requests' => rand(1200, 3500),
    'errors' => rand(2, 18),
    'uptime' => '1d 11h 22m',
    'activeUsers' => rand(12, 45),
    'dbConnections' => rand(8, 32),
];
?>

<!-- /user redirect (from existing index.php) -->
<script>
    if(document.location.href.indexOf('user') > -1) {
        document.location.href = '/home';
    }
</script>

<!-- Imprint debug output -->
<?php if (!empty($checkOutput)): ?>
<script>console.log('Alert Check Output:', <?php echo json_encode($checkOutput); ?>);</script>
<?php endif; ?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ZebraPal Admin · System Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0a0e17;
            --bg-secondary: #111827;
            --bg-card: #151d2e;
            --bg-card-hover: #1a2438;
            --bg-terminal: #0c1018;
            --border: #1e293b;
            --border-active: #334155;
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent: #3b82f6;
            --accent-glow: rgba(59, 130, 246, 0.15);
            --green: #22c55e;
            --green-dim: #166534;
            --yellow: #eab308;
            --red: #ef4444;
            --red-dim: #7f1d1d;
            --terminal-green: #4ade80;
            --terminal-prompt: #60a5fa;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'IBM Plex Sans', -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            overflow-x: hidden;
        }

        /* ===== TOP NAV ===== */
        .topnav {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 24px;
            height: 52px;
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border);
            position: sticky;
            top: 0;
            z-index: 100;
        }
        .topnav-brand {
            display: flex;
            align-items: center;
            gap: 10px;
            font-weight: 600;
            font-size: 14px;
            letter-spacing: 0.02em;
        }
        .topnav-brand svg { opacity: 0.9; }
        .topnav-brand span { color: var(--text-muted); font-weight: 400; margin-left: 4px; }
        .topnav-right {
            display: flex;
            align-items: center;
            gap: 16px;
            font-size: 13px;
            color: var(--text-secondary);
        }
        .topnav-right .badge {
            background: var(--green-dim);
            color: var(--green);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.04em;
            text-transform: uppercase;
        }
        .topnav-right .user-tag {
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .topnav-right .avatar {
            width: 28px;
            height: 28px;
            border-radius: 6px;
            background: linear-gradient(135deg, var(--accent), #6366f1);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
            font-weight: 600;
            color: #fff;
        }

        /* ===== LAYOUT ===== */
        .layout {
            display: grid;
            grid-template-columns: 200px 1fr;
            min-height: calc(100vh - 52px);
        }

        /* ===== SIDEBAR ===== */
        .sidebar {
            background: var(--bg-secondary);
            border-right: 1px solid var(--border);
            padding: 16px 0;
        }
        .sidebar-section {
            padding: 0 12px;
            margin-bottom: 20px;
        }
        .sidebar-label {
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--text-muted);
            padding: 0 8px;
            margin-bottom: 6px;
        }
        .sidebar-item {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 7px 8px;
            border-radius: 6px;
            font-size: 13px;
            color: var(--text-secondary);
            cursor: pointer;
            transition: all 0.15s;
            text-decoration: none;
        }
        .sidebar-item:hover { background: var(--bg-card); color: var(--text-primary); }
        .sidebar-item.active {
            background: var(--accent-glow);
            color: var(--accent);
        }
        .sidebar-item svg { width: 16px; height: 16px; opacity: 0.7; flex-shrink: 0; }
        .sidebar-item.active svg { opacity: 1; }
        .sidebar-item .count {
            margin-left: auto;
            font-size: 11px;
            background: var(--bg-primary);
            padding: 1px 6px;
            border-radius: 4px;
            color: var(--text-muted);
        }

        /* ===== MAIN CONTENT ===== */
        .main {
            padding: 24px;
            overflow-y: auto;
            max-height: calc(100vh - 52px);
        }
        .page-header {
            margin-bottom: 20px;
        }
        .page-header h1 {
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 4px;
        }
        .page-header p {
            font-size: 13px;
            color: var(--text-muted);
        }

        /* ===== STATS GRID ===== */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            transition: border-color 0.2s;
        }
        .stat-card:hover { border-color: var(--border-active); }
        .stat-label {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--text-muted);
            margin-bottom: 8px;
        }
        .stat-value {
            font-size: 28px;
            font-weight: 700;
            font-family: 'IBM Plex Mono', monospace;
            line-height: 1;
            margin-bottom: 6px;
        }
        .stat-sub {
            font-size: 12px;
            color: var(--text-muted);
        }
        .stat-sub .up { color: var(--green); }
        .stat-sub .down { color: var(--red); }

        /* ===== PANELS ===== */
        .panels {
            display: grid;
            grid-template-columns: 1fr 340px;
            gap: 16px;
        }

        .panel {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
        }
        .panel-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
        }
        .panel-title {
            font-size: 13px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .panel-title .dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: var(--green);
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.4; }
        }
        .panel-badge {
            font-size: 11px;
            padding: 2px 8px;
            border-radius: 4px;
            background: var(--bg-primary);
            color: var(--text-muted);
        }

        /* ===== TERMINAL ===== */
        .terminal {
            background: var(--bg-terminal);
            font-family: 'IBM Plex Mono', monospace;
            font-size: 13px;
            height: 420px;
            display: flex;
            flex-direction: column;
        }
        .terminal-body {
            flex: 1;
            overflow-y: auto;
            padding: 12px 16px;
            scroll-behavior: smooth;
        }
        .terminal-body::-webkit-scrollbar { width: 6px; }
        .terminal-body::-webkit-scrollbar-track { background: transparent; }
        .terminal-body::-webkit-scrollbar-thumb { background: var(--border-active); border-radius: 3px; }

        .term-line { margin-bottom: 2px; white-space: pre-wrap; word-break: break-all; line-height: 1.5; }
        .term-prompt { color: var(--terminal-prompt); }
        .term-cmd { color: var(--text-primary); }
        .term-output { color: var(--terminal-green); opacity: 0.85; }
        .term-error { color: var(--red); opacity: 0.85; }
        .term-info { color: var(--text-muted); font-style: italic; }

        .terminal-input {
            display: flex;
            align-items: center;
            padding: 10px 16px;
            border-top: 1px solid var(--border);
            background: rgba(0,0,0,0.3);
            gap: 8px;
        }
        .terminal-input .prompt-symbol {
            color: var(--terminal-prompt);
            font-family: 'IBM Plex Mono', monospace;
            font-size: 13px;
            user-select: none;
            white-space: nowrap;
        }
        .terminal-input input {
            flex: 1;
            background: none;
            border: none;
            color: var(--text-primary);
            font-family: 'IBM Plex Mono', monospace;
            font-size: 13px;
            outline: none;
            caret-color: var(--terminal-green);
        }
        .terminal-input input::placeholder { color: var(--text-muted); opacity: 0.5; }

        /* ===== RIGHT PANEL: ACTIVITY LOG ===== */
        .activity-list {
            padding: 0;
        }
        .activity-item {
            display: flex;
            gap: 10px;
            padding: 10px 16px;
            border-bottom: 1px solid var(--border);
            font-size: 12px;
            transition: background 0.15s;
        }
        .activity-item:hover { background: var(--bg-card-hover); }
        .activity-item:last-child { border-bottom: none; }
        .activity-icon {
            width: 28px;
            height: 28px;
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            font-size: 13px;
        }
        .activity-icon.login { background: rgba(34,197,94,0.12); color: var(--green); }
        .activity-icon.alert { background: rgba(239,68,68,0.12); color: var(--red); }
        .activity-icon.info { background: rgba(59,130,246,0.12); color: var(--accent); }
        .activity-icon.warn { background: rgba(234,179,8,0.12); color: var(--yellow); }
        .activity-content { flex: 1; }
        .activity-content strong { font-weight: 500; color: var(--text-primary); }
        .activity-content p { color: var(--text-muted); margin-top: 2px; }
        .activity-time {
            color: var(--text-muted);
            white-space: nowrap;
            font-size: 11px;
        }

        /* ===== SERVICES TABLE ===== */
        .services-panel { margin-top: 16px; }
        .services-table {
            width: 100%;
            border-collapse: collapse;
        }
        .services-table th {
            text-align: left;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: var(--text-muted);
            padding: 10px 16px;
            border-bottom: 1px solid var(--border);
        }
        .services-table td {
            padding: 10px 16px;
            font-size: 13px;
            border-bottom: 1px solid var(--border);
        }
        .services-table tr:last-child td { border-bottom: none; }
        .services-table tr:hover td { background: var(--bg-card-hover); }
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 6px;
        }
        .status-dot.running { background: var(--green); box-shadow: 0 0 6px rgba(34,197,94,0.4); }
        .status-dot.stopped { background: var(--red); }
        .status-dot.idle { background: var(--yellow); }

        .mono { font-family: 'IBM Plex Mono', monospace; font-size: 12px; }

        /* ===== LOGOUT ===== */
        .btn-logout {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 5px 10px;
            border-radius: 6px;
            border: 1px solid var(--border);
            background: transparent;
            color: var(--text-muted);
            font-size: 12px;
            cursor: pointer;
            transition: all 0.15s;
        }
        .btn-logout:hover { border-color: var(--red); color: var(--red); }

        /* ===== RESPONSIVE ===== */
        @media (max-width: 1024px) {
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .panels { grid-template-columns: 1fr; }
            .layout { grid-template-columns: 1fr; }
            .sidebar { display: none; }
        }
    </style>
</head>
<body>

<!-- TOP NAV -->
<nav class="topnav">
    <div class="topnav-brand">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>
        ZebraPal <span>· Admin Console</span>
    </div>
    <div class="topnav-right">
        <span class="badge">● Production</span>
        <span>web-prod-01</span>
        <div class="user-tag">
            <div class="avatar"><?php echo strtoupper(substr($username, 0, 1)); ?></div>
            <span><?php echo htmlspecialchars($username); ?></span>
        </div>
        <a href="/logout.php" class="btn-logout">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
            Logout (<?php echo htmlspecialchars($username); ?>)
        </a>
    </div>
</nav>

<div class="layout">
    <!-- SIDEBAR -->
    <aside class="sidebar">
        <div class="sidebar-section">
            <div class="sidebar-label">Main</div>
            <a class="sidebar-item active" href="#">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></svg>
                Dashboard
            </a>
            <a class="sidebar-item" href="#">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                Terminal
            </a>
            <a class="sidebar-item" href="#">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.5 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V7.5L14.5 2z"/></svg>
                File Manager
            </a>
            <a class="sidebar-item" href="#">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>
                Users
                <span class="count"><?php echo $fakeStats['activeUsers']; ?></span>
            </a>
        </div>

        <div class="sidebar-section">
            <div class="sidebar-label">System</div>
            <a class="sidebar-item" href="#">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>
                Services
            </a>
            <a class="sidebar-item" href="#">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                Monitoring
            </a>
            <a class="sidebar-item" href="#">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/></svg>
                Logs
                <span class="count">24</span>
            </a>
            <a class="sidebar-item" href="#">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="1" y="4" width="22" height="16" rx="2"/><line x1="1" y1="10" x2="23" y2="10"/></svg>
                Database
            </a>
        </div>

        <div class="sidebar-section">
            <div class="sidebar-label">Deploy</div>
            <a class="sidebar-item" href="#">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>
                Environments
            </a>
            <a class="sidebar-item" href="#">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 013 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
                Config
            </a>
        </div>
    </aside>

    <!-- MAIN CONTENT -->
    <main class="main">
        <div class="page-header">
            <h1>System Dashboard</h1>
            <p>Last synced: <?php echo date('M d, Y · H:i:s'); ?> UTC — web-prod-01.internal.zebrapal.com</p>
        </div>

        <!-- STATS ROW -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">CPU Usage</div>
                <div class="stat-value"><?php echo $fakeStats['cpu']; ?>%</div>
                <div class="stat-sub"><span class="up">↑ 3.2%</span> from avg</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Memory</div>
                <div class="stat-value"><?php echo $fakeStats['memory']; ?>%</div>
                <div class="stat-sub">1.8 GB / 3.9 GB</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Requests / hr</div>
                <div class="stat-value"><?php echo number_format($fakeStats['requests']); ?></div>
                <div class="stat-sub"><span class="up">↑ 12%</span> last hour</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Errors (24h)</div>
                <div class="stat-value" style="color: <?php echo $fakeStats['errors'] > 10 ? 'var(--yellow)' : 'var(--green)'; ?>;"><?php echo $fakeStats['errors']; ?></div>
                <div class="stat-sub"><span class="down">↓ 5</span> from yesterday</div>
            </div>
        </div>

        <!-- TERMINAL + ACTIVITY -->
        <div class="panels">
            <!-- COMMAND TERMINAL -->
            <div class="panel">
                <div class="panel-header">
                    <div class="panel-title">
                        <div class="dot"></div>
                        System Console
                    </div>
                    <span class="panel-badge">www-data@web-prod-01</span>
                </div>
                <div class="terminal">
                    <div class="terminal-body" id="terminalBody">
                        <div class="term-line term-info">ZebraPal System Console v2.4.1 — Type 'help' for available commands</div>
                        <div class="term-line term-info">Connected as: www-data | Server: web-prod-01.internal.zebrapal.com</div>
                        <div class="term-line">&nbsp;</div>
                        <?php foreach ($commandHistory as $entry): ?>
                            <div class="term-line"><span class="term-prompt">www-data@web-prod-01:~$ </span><span class="term-cmd"><?php echo htmlspecialchars($entry['command']); ?></span></div>
                            <?php
                            $output = generateFakeOutput($entry['command']);
                            if ($output && $output !== '__CLEAR__'):
                                $isError = (strpos($output, 'Permission denied') !== false || strpos($output, 'command not found') !== false || strpos($output, 'Access denied') !== false || strpos($output, 'not in the sudoers') !== false);
                            ?>
                                <div class="term-line <?php echo $isError ? 'term-error' : 'term-output'; ?>"><?php echo htmlspecialchars($output); ?></div>
                            <?php endif; ?>
                        <?php endforeach; ?>
                    </div>
                    <form method="post" action="" id="cmdForm" class="terminal-input" autocomplete="off">
                        <span class="prompt-symbol">www-data@web-prod-01:~$</span>
                        <input type="text" name="cmd" id="cmdInput" placeholder="Enter command..." autofocus spellcheck="false" autocomplete="off">
                    </form>
                </div>
            </div>

            <!-- ACTIVITY FEED -->
            <div class="panel">
                <div class="panel-header">
                    <div class="panel-title">Recent Activity</div>
                    <span class="panel-badge">Live</span>
                </div>
                <div class="activity-list" style="max-height: 420px; overflow-y: auto;">
                    <div class="activity-item">
                        <div class="activity-icon login">✓</div>
                        <div class="activity-content">
                            <strong><?php echo htmlspecialchars($username); ?></strong> logged in
                            <p>Session started from <?php echo $_SERVER['REMOTE_ADDR'] ?? '10.0.1.50'; ?></p>
                        </div>
                        <div class="activity-time">Just now</div>
                    </div>
                    <div class="activity-item">
                        <div class="activity-icon info">↻</div>
                        <div class="activity-content">
                            <strong>deploy</strong> ran deployment
                            <p>Branch: main → production</p>
                        </div>
                        <div class="activity-time">42m ago</div>
                    </div>
                    <div class="activity-item">
                        <div class="activity-icon warn">⚠</div>
                        <div class="activity-content">
                            <strong>System</strong> high memory alert
                            <p>Memory usage peaked at 89%</p>
                        </div>
                        <div class="activity-time">1h ago</div>
                    </div>
                    <div class="activity-item">
                        <div class="activity-icon info">◆</div>
                        <div class="activity-content">
                            <strong>cron</strong> backup completed
                            <p>/opt/scripts/backup.sh exited 0</p>
                        </div>
                        <div class="activity-time">3h ago</div>
                    </div>
                    <div class="activity-item">
                        <div class="activity-icon alert">✕</div>
                        <div class="activity-content">
                            <strong>ModSecurity</strong> blocked request
                            <p>SQL injection attempt from 45.33.xx.xx</p>
                        </div>
                        <div class="activity-time">4h ago</div>
                    </div>
                    <div class="activity-item">
                        <div class="activity-icon login">✓</div>
                        <div class="activity-content">
                            <strong>admin</strong> SSH session
                            <p>Connected from 10.0.1.50</p>
                        </div>
                        <div class="activity-time">5h ago</div>
                    </div>
                    <div class="activity-item">
                        <div class="activity-icon info">↻</div>
                        <div class="activity-content">
                            <strong>certbot</strong> SSL renewal
                            <p>Certificate renewed for *.zebrapal.com</p>
                        </div>
                        <div class="activity-time">12h ago</div>
                    </div>
                    <div class="activity-item">
                        <div class="activity-icon warn">⚠</div>
                        <div class="activity-content">
                            <strong>MySQL</strong> slow query logged
                            <p>Query took 4.2s on users table</p>
                        </div>
                        <div class="activity-time">14h ago</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- SERVICES TABLE -->
        <div class="panel services-panel">
            <div class="panel-header">
                <div class="panel-title">Running Services</div>
                <span class="panel-badge"><?php echo rand(5,7); ?> active</span>
            </div>
            <table class="services-table">
                <thead>
                    <tr>
                        <th>Service</th>
                        <th>Status</th>
                        <th>PID</th>
                        <th>Port</th>
                        <th>Uptime</th>
                        <th>Memory</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><strong>Apache2</strong></td>
                        <td><span class="status-dot running"></span>Running</td>
                        <td class="mono">1234</td>
                        <td class="mono">80, 443</td>
                        <td>1d 11h</td>
                        <td class="mono">142 MB</td>
                    </tr>
                    <tr>
                        <td><strong>MySQL 8.0</strong></td>
                        <td><span class="status-dot running"></span>Running</td>
                        <td class="mono">890</td>
                        <td class="mono">3306</td>
                        <td>1d 11h</td>
                        <td class="mono">512 MB</td>
                    </tr>
                    <tr>
                        <td><strong>Redis 7.2</strong></td>
                        <td><span class="status-dot running"></span>Running</td>
                        <td class="mono">432</td>
                        <td class="mono">6379</td>
                        <td>1d 11h</td>
                        <td class="mono">84 MB</td>
                    </tr>
                    <tr>
                        <td><strong>OpenSSH</strong></td>
                        <td><span class="status-dot running"></span>Running</td>
                        <td class="mono">567</td>
                        <td class="mono">22</td>
                        <td>1d 11h</td>
                        <td class="mono">8 MB</td>
                    </tr>
                    <tr>
                        <td><strong>Cron</strong></td>
                        <td><span class="status-dot idle"></span>Idle</td>
                        <td class="mono">289</td>
                        <td class="mono">—</td>
                        <td>1d 11h</td>
                        <td class="mono">4 MB</td>
                    </tr>
                    <tr>
                        <td><strong>Fail2Ban</strong></td>
                        <td><span class="status-dot running"></span>Running</td>
                        <td class="mono">345</td>
                        <td class="mono">—</td>
                        <td>1d 11h</td>
                        <td class="mono">22 MB</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </main>
</div>

<script>
// Auto-scroll terminal to bottom
const termBody = document.getElementById('terminalBody');
termBody.scrollTop = termBody.scrollHeight;

// Focus input on click anywhere in terminal
document.querySelector('.terminal').addEventListener('click', function() {
    document.getElementById('cmdInput').focus();
});

// Command history navigation (arrow up/down)
const cmdHistory = <?php echo json_encode(array_column($commandHistory, 'command')); ?>;
let historyIndex = cmdHistory.length;

document.getElementById('cmdInput').addEventListener('keydown', function(e) {
    if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (historyIndex > 0) {
            historyIndex--;
            this.value = cmdHistory[historyIndex] || '';
        }
    } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (historyIndex < cmdHistory.length - 1) {
            historyIndex++;
            this.value = cmdHistory[historyIndex] || '';
        } else {
            historyIndex = cmdHistory.length;
            this.value = '';
        }
    }
});
</script>

</body>
</html>
