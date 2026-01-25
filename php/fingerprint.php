<?php
// $username = $_SESSION['username'];
$content = "
<?php
\$data = file_get_contents('php://input');
\$t=time();
\$data = '[' . date('d:M:Y:H:i:s',\$t) . ' +0000] " . $randStr . " ' . \$data . \"\\n\";
\$fh = fopen('/var/log/scythe/fingerprint.txt', 'a');
fwrite(\$fh, \$data);
fclose(\$fh);
unlink(__FILE__);
?>";

$myfile = fopen("/var/www/html/" . $randStr . ".php", "w");
fwrite($myfile, $content);
fclose($myfile);

//passthru("python3 /var/www/time_remove.py \"/var/www/html/" . $randStr . ".php\"");
exec("nohup /opt/scripts/time_remove.py /var/www/html/" . $randStr . ".php > /dev/null 2>/dev/null &");

?>

<script>

(function browserdata(window) {
    {
        var unknown = '-';

        // screen
        var screenSize = '';
        if (screen.width) {
            width = (screen.width) ? screen.width : '';
            height = (screen.height) ? screen.height : '';
            screenSize += '' + width + " x " + height;
        }

        // browser
        var nVer = navigator.appVersion;
        var nAgt = navigator.userAgent;
        var browser = navigator.appName;
        var version = '' + parseFloat(navigator.appVersion);
        var majorVersion = parseInt(navigator.appVersion, 10);
        var nameOffset, verOffset, ix;

        // Opera
        if ((verOffset = nAgt.indexOf('Opera')) != -1) {
            browser = 'Opera';
            version = nAgt.substring(verOffset + 6);
            if ((verOffset = nAgt.indexOf('Version')) != -1) {
                version = nAgt.substring(verOffset + 8);
            }
        }
        // Opera Next
        if ((verOffset = nAgt.indexOf('OPR')) != -1) {
            browser = 'Opera';
            version = nAgt.substring(verOffset + 4);
        }
        // Legacy Edge
        else if ((verOffset = nAgt.indexOf('Edge')) != -1) {
            browser = 'Microsoft Legacy Edge';
            version = nAgt.substring(verOffset + 5);
        }
        // Edge (Chromium)
        else if ((verOffset = nAgt.indexOf('Edg')) != -1) {
            browser = 'Microsoft Edge';
            version = nAgt.substring(verOffset + 4);
        }
        // MSIE
        else if ((verOffset = nAgt.indexOf('MSIE')) != -1) {
            browser = 'Microsoft Internet Explorer';
            version = nAgt.substring(verOffset + 5);
        }
        // Chrome
        else if ((verOffset = nAgt.indexOf('Chrome')) != -1) {
            browser = 'Chrome';
            version = nAgt.substring(verOffset + 7);
        }
        // Safari
        else if ((verOffset = nAgt.indexOf('Safari')) != -1) {
            browser = 'Safari';
            version = nAgt.substring(verOffset + 7);
            if ((verOffset = nAgt.indexOf('Version')) != -1) {
                version = nAgt.substring(verOffset + 8);
            }
        }
        // Firefox
        else if ((verOffset = nAgt.indexOf('Firefox')) != -1) {
            browser = 'Firefox';
            version = nAgt.substring(verOffset + 8);
        }
        // MSIE 11+
        else if (nAgt.indexOf('Trident/') != -1) {
            browser = 'Microsoft Internet Explorer';
            version = nAgt.substring(nAgt.indexOf('rv:') + 3);
        }
        // Other browsers
        else if ((nameOffset = nAgt.lastIndexOf(' ') + 1) < (verOffset = nAgt.lastIndexOf('/'))) {
            browser = nAgt.substring(nameOffset, verOffset);
            version = nAgt.substring(verOffset + 1);
            if (browser.toLowerCase() == browser.toUpperCase()) {
                browser = navigator.appName;
            }
        }
        // trim the version string
        if ((ix = version.indexOf(';')) != -1) version = version.substring(0, ix);
        if ((ix = version.indexOf(' ')) != -1) version = version.substring(0, ix);
        if ((ix = version.indexOf(')')) != -1) version = version.substring(0, ix);

        majorVersion = parseInt('' + version, 10);
        if (isNaN(majorVersion)) {
            version = '' + parseFloat(navigator.appVersion);
            majorVersion = parseInt(navigator.appVersion, 10);
        }

        // mobile version
        var mobile = /Mobile|mini|Fennec|Android|iP(ad|od|hone)/.test(nVer);

        // cookie
        var cookieEnabled = (navigator.cookieEnabled) ? true : false;

        if (typeof navigator.cookieEnabled == 'undefined' && !cookieEnabled) {
            document.cookie = 'testcookie';
            cookieEnabled = (document.cookie.indexOf('testcookie') != -1) ? true : false;
        }

        // system
        var os = unknown;
        var clientStrings = [{
                s: 'Windows 10',
                r: /(Windows 10.0|Windows NT 10.0)/
            },
            {
                s: 'Windows 8.1',
                r: /(Windows 8.1|Windows NT 6.3)/
            },
            {
                s: 'Windows 8',
                r: /(Windows 8|Windows NT 6.2)/
            },
            {
                s: 'Windows 7',
                r: /(Windows 7|Windows NT 6.1)/
            },
            {
                s: 'Windows Vista',
                r: /Windows NT 6.0/
            },
            {
                s: 'Windows Server 2003',
                r: /Windows NT 5.2/
            },
            {
                s: 'Windows XP',
                r: /(Windows NT 5.1|Windows XP)/
            },
            {
                s: 'Windows 2000',
                r: /(Windows NT 5.0|Windows 2000)/
            },
            {
                s: 'Windows ME',
                r: /(Win 9x 4.90|Windows ME)/
            },
            {
                s: 'Windows 98',
                r: /(Windows 98|Win98)/
            },
            {
                s: 'Windows 95',
                r: /(Windows 95|Win95|Windows_95)/
            },
            {
                s: 'Windows NT 4.0',
                r: /(Windows NT 4.0|WinNT4.0|WinNT|Windows NT)/
            },
            {
                s: 'Windows CE',
                r: /Windows CE/
            },
            {
                s: 'Windows 3.11',
                r: /Win16/
            },
            {
                s: 'Android',
                r: /Android/
            },
            {
                s: 'Open BSD',
                r: /OpenBSD/
            },
            {
                s: 'Sun OS',
                r: /SunOS/
            },
            {
                s: 'Chrome OS',
                r: /CrOS/
            },
            {
                s: 'Linux',
                r: /(Linux|X11(?!.*CrOS))/
            },
            {
                s: 'iOS',
                r: /(iPhone|iPad|iPod)/
            },
            {
                s: 'Mac OS X',
                r: /Mac OS X/
            },
            {
                s: 'Mac OS',
                r: /(Mac OS|MacPPC|MacIntel|Mac_PowerPC|Macintosh)/
            },
            {
                s: 'QNX',
                r: /QNX/
            },
            {
                s: 'UNIX',
                r: /UNIX/
            },
            {
                s: 'BeOS',
                r: /BeOS/
            },
            {
                s: 'OS/2',
                r: /OS\/2/
            },
            {
                s: 'Search Bot',
                r: /(nuhk|Googlebot|Yammybot|Openbot|Slurp|MSNBot|Ask Jeeves\/Teoma|ia_archiver)/
            }
        ];
        for (var id in clientStrings) {
            var cs = clientStrings[id];
            if (cs.r.test(nAgt)) {
                os = cs.s;
                break;
            }
        }

        var osVersion = unknown;

        if (/Windows/.test(os)) {
            osVersion = /Windows (.*)/.exec(os)[1];
            os = 'Windows';
        }

        switch (os) {
            case 'Mac OS':
            case 'Mac OS X':
            case 'Android':
                osVersion = /(?:Android|Mac OS|Mac OS X|MacPPC|MacIntel|Mac_PowerPC|Macintosh) ([\.\_\d]+)/.exec(nAgt)[1];
                break;

            case 'iOS':
                osVersion = /OS (\d+)_(\d+)_?(\d+)?/.exec(nVer);
                osVersion = osVersion[1] + '.' + osVersion[2] + '.' + (osVersion[3] | 0);
                break;
        }

        // flash (you'll need to include swfobject)
        /* script src="//ajax.googleapis.com/ajax/libs/swfobject/2.2/swfobject.js" */
        var flashVersion = 'no check';
        if (typeof swfobject != 'undefined') {
            var fv = swfobject.getFlashPlayerVersion();
            if (fv.major > 0) {
                flashVersion = fv.major + '.' + fv.minor + ' r' + fv.release;
            } else {
                flashVersion = unknown;
            }
        }
    }

    window.jscd = {
        screen: screenSize,
        browser: browser,
        browserVersion: version,
        browserMajorVersion: majorVersion,
        mobile: mobile,
        os: os,
        osVersion: osVersion,
        cookies: cookieEnabled,
        flashVersion: flashVersion,
        agent: nAgt
    };

}(this));



(function fingerprint_hardware(window) {
    var canvas = document.createElement("canvas");
    var webgl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
    var debugInfo = webgl.getExtension("webgl_debug_renderer_info");
    var gpu = webgl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);

    window.hardware = {
        memory: navigator.deviceMemory,
        cpuCores: navigator.hardwareConcurrency,
        gpu: gpu
    }

}(this));



(function fingerprint_network(window) {
    var request = new XMLHttpRequest();
    request.open('GET', 'http://ip-api.com/json?fields=21233405', false); // false makes the request synchronous
    request.send(null);

    if (request.status === 200) {
        window.network = JSON.parse(request.responseText);
    }
}(this));



(function canvas(window) {

    var canvas = document.body.appendChild(document.createElement('canvas'));
    var ctx = canvas.getContext('2d');
    canvas.height = 200;
    canvas.width = 500;

    // Text with lowercase/uppercase/punctuation symbols
    var txt = "❁ I Want me a Tasty Fruit Salad!\n\r <🍏🍎🍐🍊🍋🍌🍉🍇🍓🍈🍒🍑🍍🥝>";
    ctx.textBaseline = "top";
    // The most common type
    ctx.font = "14px 'Arial'";
    ctx.textBaseline = "alphabetic";
    ctx.fillStyle = "#f60";
    ctx.fillRect(125, 1, 62, 20);
    // Some tricks for color mixing to increase the difference in rendering
    ctx.fillStyle = "#069";
    ctx.fillText(txt, 2, 15);
    ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
    ctx.fillText(txt, 4, 17);

    // canvas blending
    // http://blogs.adobe.com/webplatform/2013/01/28/blending-features-in-canvas/
    // http://jsfiddle.net/NDYV8/16/
    ctx.globalCompositeOperation = "multiply";
    ctx.fillStyle = "rgb(255,0,255)";
    ctx.beginPath();
    ctx.arc(50, 50, 50, 0, Math.PI * 2, true);
    ctx.closePath();
    ctx.fill();
    ctx.fillStyle = "rgb(0,255,255)";
    ctx.beginPath();
    ctx.arc(100, 50, 50, 0, Math.PI * 2, true);
    ctx.closePath();
    ctx.fill();
    ctx.fillStyle = "rgb(255,255,0)";
    ctx.beginPath();
    ctx.arc(75, 100, 50, 0, Math.PI * 2, true);
    ctx.closePath();
    ctx.fill();
    ctx.fillStyle = "rgb(255,0,255)";
    // canvas winding
    // http://blogs.adobe.com/webplatform/2013/01/30/winding-rules-in-canvas/
    // http://jsfiddle.net/NDYV8/19/
    ctx.arc(75, 75, 75, 0, Math.PI * 2, true);
    ctx.arc(75, 75, 25, 0, Math.PI * 2, true);
    ctx.fill("evenodd");


    var fingerprint_canvas = (function() {

        // Eratosthenes seive to find primes up to 311 for magic constants. This is why SHA256 is better than SHA1
        var i = 1,
            j,
            K = [],
            H = [];

        while (++i < 18) {
            for (j = i * i; j < 312; j += i) {
                K[j] = 1;
            }
        }

        function x(num, root) {
            return (Math.pow(num, 1 / root) % 1) * 4294967296 | 0;
        }

        for (i = 1, j = 0; i < 313;) {
            if (!K[++i]) {
                H[j] = x(i, 2);
                K[j++] = x(i, 3);
            }
        }

        function S(X, n) {
            return (X >>> n) | (X << (32 - n));
        }

        function SHA256(b) {
            var HASH = H.slice(i = 0),
                s = unescape(encodeURI(b)),
                /* encode as utf8 */
                W = [],
                l = s.length,
                m = [],
                a, y, z;
            for (; i < l;) m[i >> 2] |= (s.charCodeAt(i) & 0xff) << 8 * (3 - i++ % 4);

            l *= 8;

            m[l >> 5] |= 0x80 << (24 - l % 32);
            m[z = (l + 64 >> 5) | 15] = l;

            for (i = 0; i < z; i += 16) {
                a = HASH.slice(j = 0, 8);

                for (; j < 64; a[4] += y) {
                    if (j < 16) {
                        W[j] = m[j + i];
                    } else {
                        W[j] =
                            (S(y = W[j - 2], 17) ^ S(y, 19) ^ (y >>> 10)) +
                            (W[j - 7] | 0) +
                            (S(y = W[j - 15], 7) ^ S(y, 18) ^ (y >>> 3)) +
                            (W[j - 16] | 0);
                    }

                    a.unshift(
                        (
                            y = (
                                a.pop() +
                                (S(b = a[4], 6) ^ S(b, 11) ^ S(b, 25)) +
                                (((b & a[5]) ^ ((~b) & a[6])) + K[j]) | 0
                            ) +
                            (W[j++] | 0)
                        ) +
                        (S(l = a[0], 2) ^ S(l, 13) ^ S(l, 22)) +
                        ((l & a[1]) ^ (a[1] & a[2]) ^ (a[2] & l))
                    );
                }

                for (j = 8; j--;) HASH[j] = a[j] + HASH[j];
            }

            for (s = ''; j < 63;) s += ((HASH[++j >> 3] >> 4 * (7 - j % 8)) & 15).toString(16);

            return s;
        }

        return SHA256;
    })();

    window.canvas = fingerprint_canvas(canvas.toDataURL());

}(this));


// https://codepen.io/run-time/pen/XJNXWV

(function fingerprint_fonts(window) {
    "use strict";
    var strOnError, style, fonts, count, template, fragment, divs, i, font, div, body, result, e;

    strOnError = "Error";
    style = null;
    fonts = null;
    font = null;
    count = 0;
    template = null;
    divs = null;
    e = null;
    div = null;
    body = null;
    i = 0;

    try {
        style = "position: absolute; visibility: hidden; display: block !important";
        fonts = ['.Aqua Kana', '.Helvetica LT MM', '.Times LT MM', '18thCentury', '8514oem', 'AR BERKLEY', 'AR JULIAN', 'AR PL UKai CN', 'AR PL UMing CN', 'AR PL UMing HK', 'AR PL UMing TW', 'AR PL UMing TW MBE', 'Aakar', 'Abadi MT Condensed Extra Bold', 'Abadi MT Condensed Light', 'Abyssinica SIL', 'AcmeFont', 'Adobe Arabic', 'Agency FB', 'Aharoni', 'Aharoni Bold', 'Al Bayan', 'Al Bayan Bold', 'Al Bayan Plain', 'Al Nile', 'Al Tarikh', 'Aldhabi', 'Alfredo', 'Algerian', 'Alien Encounters', 'Almonte Snow', 'American Typewriter', 'American Typewriter Bold', 'American Typewriter Condensed', 'American Typewriter Light', 'Amethyst', 'Andale Mono', 'Andale Mono Version', 'Andalus', 'Angsana New', 'AngsanaUPC', 'Ani', 'AnjaliOldLipi', 'Aparajita', 'Apple Braille', 'Apple Braille Outline 6 Dot', 'Apple Braille Outline 8 Dot', 'Apple Braille Pinpoint 6 Dot', 'Apple Braille Pinpoint 8 Dot', 'Apple Chancery', 'Apple Color Emoji', 'Apple LiGothic Medium', 'Apple LiSung Light', 'Apple SD Gothic Neo', 'Apple SD Gothic Neo Regular', 'Apple SD GothicNeo ExtraBold', 'Apple Symbols', 'AppleGothic', 'AppleGothic Regular', 'AppleMyungjo', 'AppleMyungjo Regular', 'AquaKana', 'Arabic Transparent', 'Arabic Typesetting', 'Arial', 'Arial Baltic', 'Arial Black', 'Arial Bold', 'Arial Bold Italic', 'Arial CE', 'Arial CYR', 'Arial Greek', 'Arial Hebrew', 'Arial Hebrew Bold', 'Arial Italic', 'Arial Narrow', 'Arial Narrow Bold', 'Arial Narrow Bold Italic', 'Arial Narrow Italic', 'Arial Rounded Bold', 'Arial Rounded MT Bold', 'Arial TUR', 'Arial Unicode MS', 'ArialHB', 'Arimo', 'Asimov', 'Autumn', 'Avenir', 'Avenir Black', 'Avenir Book', 'Avenir Next', 'Avenir Next Bold', 'Avenir Next Condensed', 'Avenir Next Condensed Bold', 'Avenir Next Demi Bold', 'Avenir Next Heavy', 'Avenir Next Regular', 'Avenir Roman', 'Ayuthaya', 'BN Jinx', 'BN Machine', 'BOUTON International Symbols', 'Baby Kruffy', 'Baghdad', 'Bahnschrift', 'Balthazar', 'Bangla MN', 'Bangla MN Bold', 'Bangla Sangam MN', 'Bangla Sangam MN Bold', 'Baskerville', 'Baskerville Bold', 'Baskerville Bold Italic', 'Baskerville Old Face', 'Baskerville SemiBold', 'Baskerville SemiBold Italic', 'Bastion', 'Batang', 'BatangChe', 'Bauhaus 93', 'Beirut', 'Bell MT', 'Bell MT Bold', 'Bell MT Italic', 'Bellerose', 'Berlin Sans FB', 'Berlin Sans FB Demi', 'Bernard MT Condensed', 'BiauKai', 'Big Caslon', 'Big Caslon Medium', 'Birch Std', 'Bitstream Charter', 'Bitstream Vera Sans', 'Blackadder ITC', 'Blackoak Std', 'Bobcat', 'Bodoni 72', 'Bodoni MT', 'Bodoni MT Black', 'Bodoni MT Poster Compressed', 'Bodoni Ornaments', 'BolsterBold', 'Book Antiqua', 'Book Antiqua Bold', 'Bookman Old Style', 'Bookman Old Style Bold', 'Bookshelf Symbol 7', 'Borealis', 'Bradley Hand', 'Bradley Hand ITC', 'Braggadocio', 'Brandish', 'Britannic Bold', 'Broadway', 'Browallia New', 'BrowalliaUPC', 'Brush Script', 'Brush Script MT', 'Brush Script MT Italic', 'Brush Script Std', 'Brussels', 'Calibri', 'Calibri Bold', 'Calibri Light', 'Californian FB', 'Calisto MT', 'Calisto MT Bold', 'Calligraphic', 'Calvin', 'Cambria', 'Cambria Bold', 'Cambria Math', 'Candara', 'Candara Bold', 'Candles', 'Carrois Gothic SC', 'Castellar', 'Centaur', 'Century', 'Century Gothic', 'Century Gothic Bold', 'Century Schoolbook', 'Century Schoolbook Bold', 'Century Schoolbook L', 'Chalkboard', 'Chalkboard Bold', 'Chalkboard SE', 'Chalkboard SE Bold', 'ChalkboardBold', 'Chalkduster', 'Chandas', 'Chaparral Pro', 'Chaparral Pro Light', 'Charlemagne Std', 'Charter', 'Chilanka', 'Chiller', 'Chinyen', 'Clarendon', 'Cochin', 'Cochin Bold', 'Colbert', 'Colonna MT', 'Comic Sans MS', 'Comic Sans MS Bold', 'Commons', 'Consolas', 'Consolas Bold', 'Constantia', 'Constantia Bold', 'Coolsville', 'Cooper Black', 'Cooper Std Black', 'Copperplate', 'Copperplate Bold', 'Copperplate Gothic Bold', 'Copperplate Light', 'Corbel', 'Corbel Bold', 'Cordia New', 'CordiaUPC', 'Corporate', 'Corsiva', 'Corsiva Hebrew', 'Corsiva Hebrew Bold', 'Courier', 'Courier 10 Pitch', 'Courier Bold', 'Courier New', 'Courier New Baltic', 'Courier New Bold', 'Courier New CE', 'Courier New Italic', 'Courier Oblique', 'Cracked Johnnie', 'Creepygirl', 'Curlz MT', 'Cursor', 'Cutive Mono', 'DFKai-SB', 'DIN Alternate', 'DIN Condensed', 'Damascus', 'Damascus Bold', 'Dancing Script', 'DaunPenh', 'David', 'Dayton', 'DecoType Naskh', 'Deja Vu', 'DejaVu LGC Sans', 'DejaVu Sans', 'DejaVu Sans Mono', 'DejaVu Serif', 'Deneane', 'Desdemona', 'Detente', 'Devanagari MT', 'Devanagari MT Bold', 'Devanagari Sangam MN', 'Didot', 'Didot Bold', 'Digifit', 'DilleniaUPC', 'Dingbats', 'Distant Galaxy', 'Diwan Kufi', 'Diwan Kufi Regular', 'Diwan Thuluth', 'Diwan Thuluth Regular', 'DokChampa', 'Dominican', 'Dotum', 'DotumChe', 'Droid Sans', 'Droid Sans Fallback', 'Droid Sans Mono', 'Dyuthi', 'Ebrima', 'Edwardian Script ITC', 'Elephant', 'Emmett', 'Engravers MT', 'Engravers MT Bold', 'Enliven', 'Eras Bold ITC', 'Estrangelo Edessa', 'Ethnocentric', 'EucrosiaUPC', 'Euphemia', 'Euphemia UCAS', 'Euphemia UCAS Bold', 'Eurostile', 'Eurostile Bold', 'Expressway Rg', 'FangSong', 'Farah', 'Farisi', 'Felix Titling', 'Fingerpop', 'Fixedsys', 'Flubber', 'Footlight MT Light', 'Forte', 'FrankRuehl', 'Frankfurter Venetian TT', 'Franklin Gothic Book', 'Franklin Gothic Book Italic', 'Franklin Gothic Medium', 'Franklin Gothic Medium Cond', 'Franklin Gothic Medium Italic', 'FreeMono', 'FreeSans', 'FreeSerif', 'FreesiaUPC', 'Freestyle Script', 'French Script MT', 'Futura', 'Futura Condensed ExtraBold', 'Futura Medium', 'GB18030 Bitmap', 'Gabriola', 'Gadugi', 'Garamond', 'Garamond Bold', 'Gargi', 'Garuda', 'Gautami', 'Gazzarelli', 'Geeza Pro', 'Geeza Pro Bold', 'Geneva', 'GenevaCY', 'Gentium', 'Gentium Basic', 'Gentium Book Basic', 'GentiumAlt', 'Georgia', 'Georgia Bold', 'Geotype TT', 'Giddyup Std', 'Gigi', 'Gill', 'Gill Sans', 'Gill Sans Bold', 'Gill Sans MT', 'Gill Sans MT Bold', 'Gill Sans MT Condensed', 'Gill Sans MT Ext Condensed Bold', 'Gill Sans MT Italic', 'Gill Sans Ultra Bold', 'Gill Sans Ultra Bold Condensed', 'Gisha', 'Glockenspiel', 'Gloucester MT Extra Condensed', 'Good Times', 'Goudy', 'Goudy Old Style', 'Goudy Old Style Bold', 'Goudy Stout', 'Greek Diner Inline TT', 'Gubbi', 'Gujarati MT', 'Gujarati MT Bold', 'Gujarati Sangam MN', 'Gujarati Sangam MN Bold', 'Gulim', 'GulimChe', 'GungSeo Regular', 'Gungseouche', 'Gungsuh', 'GungsuhChe', 'Gurmukhi', 'Gurmukhi MN', 'Gurmukhi MN Bold', 'Gurmukhi MT', 'Gurmukhi Sangam MN', 'Gurmukhi Sangam MN Bold', 'Haettenschweiler', 'Hand Me Down S (BRK)', 'Hansen', 'Harlow Solid Italic', 'Harrington', 'Harvest', 'HarvestItal', 'Haxton Logos TT', 'HeadLineA Regular', 'HeadlineA', 'Heavy Heap', 'Hei', 'Hei Regular', 'Heiti SC', 'Heiti SC Light', 'Heiti SC Medium', 'Heiti TC', 'Heiti TC Light', 'Heiti TC Medium', 'Helvetica', 'Helvetica Bold', 'Helvetica CY Bold', 'Helvetica CY Plain', 'Helvetica LT Std', 'Helvetica Light', 'Helvetica Neue', 'Helvetica Neue Bold', 'Helvetica Neue Medium', 'Helvetica Oblique', 'HelveticaCY', 'HelveticaNeueLT Com 107 XBlkCn', 'Herculanum', 'High Tower Text', 'Highboot', 'Hiragino Kaku Gothic Pro W3', 'Hiragino Kaku Gothic Pro W6', 'Hiragino Kaku Gothic ProN W3', 'Hiragino Kaku Gothic ProN W6', 'Hiragino Kaku Gothic Std W8', 'Hiragino Kaku Gothic StdN W8', 'Hiragino Maru Gothic Pro W4', 'Hiragino Maru Gothic ProN W4', 'Hiragino Mincho Pro W3', 'Hiragino Mincho Pro W6', 'Hiragino Mincho ProN W3', 'Hiragino Mincho ProN W6', 'Hiragino Sans GB W3', 'Hiragino Sans GB W6', 'Hiragino Sans W0', 'Hiragino Sans W1', 'Hiragino Sans W2', 'Hiragino Sans W3', 'Hiragino Sans W4', 'Hiragino Sans W5', 'Hiragino Sans W6', 'Hiragino Sans W7', 'Hiragino Sans W8', 'Hiragino Sans W9', 'Hobo Std', 'Hoefler Text', 'Hoefler Text Black', 'Hoefler Text Ornaments', 'Hollywood Hills', 'Hombre', 'Huxley Titling', 'ITC Stone Serif', 'ITF Devanagari', 'ITF Devanagari Marathi', 'ITF Devanagari Medium', 'Impact', 'Imprint MT Shadow', 'InaiMathi', 'Induction', 'Informal Roman', 'Ink Free', 'IrisUPC', 'Iskoola Pota', 'Italianate', 'Jamrul', 'JasmineUPC', 'Javanese Text', 'Jokerman', 'Juice ITC', 'KacstArt', 'KacstBook', 'KacstDecorative', 'KacstDigital', 'KacstFarsi', 'KacstLetter', 'KacstNaskh', 'KacstOffice', 'KacstOne', 'KacstPen', 'KacstPoster', 'KacstQurn', 'KacstScreen', 'KacstTitle', 'KacstTitleL', 'Kai', 'Kai Regular', 'KaiTi', 'Kailasa', 'Kailasa Regular', 'Kaiti SC', 'Kaiti SC Black', 'Kalapi', 'Kalimati', 'Kalinga', 'Kannada MN', 'Kannada MN Bold', 'Kannada Sangam MN', 'Kannada Sangam MN Bold', 'Kartika', 'Karumbi', 'Kedage', 'Kefa', 'Kefa Bold', 'Keraleeyam', 'Keyboard', 'Khmer MN', 'Khmer MN Bold', 'Khmer OS', 'Khmer OS System', 'Khmer Sangam MN', 'Khmer UI', 'Kinnari', 'Kino MT', 'KodchiangUPC', 'Kohinoor Bangla', 'Kohinoor Devanagari', 'Kohinoor Telugu', 'Kokila', 'Kokonor', 'Kokonor Regular', 'Kozuka Gothic Pr6N B', 'Kristen ITC', 'Krungthep', 'KufiStandardGK', 'KufiStandardGK Regular', 'Kunstler Script', 'Laksaman', 'Lao MN', 'Lao Sangam MN', 'Lao UI', 'LastResort', 'Latha', 'Leelawadee', 'Letter Gothic Std', 'LetterOMatic!', 'Levenim MT', 'LiHei Pro', 'LiSong Pro', 'Liberation Mono', 'Liberation Sans', 'Liberation Sans Narrow', 'Liberation Serif', 'Likhan', 'LilyUPC', 'Limousine', 'Lithos Pro Regular', 'LittleLordFontleroy', 'Lohit Assamese', 'Lohit Bengali', 'Lohit Devanagari', 'Lohit Gujarati', 'Lohit Gurmukhi', 'Lohit Hindi', 'Lohit Kannada', 'Lohit Malayalam', 'Lohit Odia', 'Lohit Punjabi', 'Lohit Tamil', 'Lohit Tamil Classical', 'Lohit Telugu', 'Loma', 'Lucida Blackletter', 'Lucida Bright', 'Lucida Bright Demibold', 'Lucida Bright Demibold Italic', 'Lucida Bright Italic', 'Lucida Calligraphy', 'Lucida Calligraphy Italic', 'Lucida Console', 'Lucida Fax', 'Lucida Fax Demibold', 'Lucida Fax Regular', 'Lucida Grande', 'Lucida Grande Bold', 'Lucida Handwriting', 'Lucida Handwriting Italic', 'Lucida Sans', 'Lucida Sans Demibold Italic', 'Lucida Sans Typewriter', 'Lucida Sans Typewriter Bold', 'Lucida Sans Unicode', 'Luminari', 'Luxi Mono', 'MS Gothic', 'MS Mincho', 'MS Outlook', 'MS PGothic', 'MS PMincho', 'MS Reference Sans Serif', 'MS Reference Specialty', 'MS Sans Serif', 'MS Serif', 'MS UI Gothic', 'MT Extra', 'MV Boli', 'Mael', 'Magneto', 'Maiandra GD', 'Malayalam MN', 'Malayalam MN Bold', 'Malayalam Sangam MN', 'Malayalam Sangam MN Bold', 'Malgun Gothic', 'Mallige', 'Mangal', 'Manorly', 'Marion', 'Marion Bold', 'Marker Felt', 'Marker Felt Thin', 'Marlett', 'Martina', 'Matura MT Script Capitals', 'Meera', 'Meiryo', 'Meiryo Bold', 'Meiryo UI', 'MelodBold', 'Menlo', 'Menlo Bold', 'Mesquite Std', 'Microsoft', 'Microsoft Himalaya', 'Microsoft JhengHei', 'Microsoft JhengHei UI', 'Microsoft New Tai Lue', 'Microsoft PhagsPa', 'Microsoft Sans Serif', 'Microsoft Tai Le', 'Microsoft Tai Le Bold', 'Microsoft Uighur', 'Microsoft YaHei', 'Microsoft YaHei UI', 'Microsoft Yi Baiti', 'Minerva', 'MingLiU', 'MingLiU-ExtB', 'MingLiU_HKSCS', 'Minion Pro', 'Miriam', 'Mishafi', 'Mishafi Gold', 'Mistral', 'Modern', 'Modern No. 20', 'Monaco', 'Mongolian Baiti', 'Monospace', 'Monotype Corsiva', 'Monotype Sorts', 'MoolBoran', 'Moonbeam', 'MotoyaLMaru', 'Mshtakan', 'Mshtakan Bold', 'Mukti Narrow', 'Muna', 'Myanmar MN', 'Myanmar MN Bold', 'Myanmar Sangam MN', 'Myanmar Text', 'Mycalc', 'Myriad Arabic', 'Myriad Hebrew', 'Myriad Pro', 'NISC18030', 'NSimSun', 'Nadeem', 'Nadeem Regular', 'Nakula', 'Nanum Barun Gothic', 'Nanum Gothic', 'Nanum Myeongjo', 'NanumBarunGothic', 'NanumGothic', 'NanumGothic Bold', 'NanumGothicCoding', 'NanumMyeongjo', 'NanumMyeongjo Bold', 'Narkisim', 'Nasalization', 'Navilu', 'Neon Lights', 'New Peninim MT', 'New Peninim MT Bold', 'News Gothic MT', 'News Gothic MT Bold', 'Niagara Engraved', 'Niagara Solid', 'Nimbus Mono L', 'Nimbus Roman No9 L', 'Nimbus Sans L', 'Nimbus Sans L Condensed', 'Nina', 'Nirmala UI', 'Nirmala.ttf', 'Norasi', 'Noteworthy', 'Noteworthy Bold', 'Noto Color Emoji', 'Noto Emoji', 'Noto Mono', 'Noto Naskh Arabic', 'Noto Nastaliq Urdu', 'Noto Sans', 'Noto Sans Armenian', 'Noto Sans Bengali', 'Noto Sans CJK', 'Noto Sans Canadian Aboriginal', 'Noto Sans Cherokee', 'Noto Sans Devanagari', 'Noto Sans Ethiopic', 'Noto Sans Georgian', 'Noto Sans Gujarati', 'Noto Sans Gurmukhi', 'Noto Sans Hebrew', 'Noto Sans JP', 'Noto Sans KR', 'Noto Sans Kannada', 'Noto Sans Khmer', 'Noto Sans Lao', 'Noto Sans Malayalam', 'Noto Sans Myanmar', 'Noto Sans Oriya', 'Noto Sans SC', 'Noto Sans Sinhala', 'Noto Sans Symbols', 'Noto Sans TC', 'Noto Sans Tamil', 'Noto Sans Telugu', 'Noto Sans Thai', 'Noto Sans Yi', 'Noto Serif', 'Notram', 'November', 'Nueva Std', 'Nueva Std Cond', 'Nyala', 'OCR A Extended', 'OCR A Std', 'Old English Text MT', 'OldeEnglish', 'Onyx', 'OpenSymbol', 'OpineHeavy', 'Optima', 'Optima Bold', 'Optima Regular', 'Orator Std', 'Oriya MN', 'Oriya MN Bold', 'Oriya Sangam MN', 'Oriya Sangam MN Bold', 'Osaka', 'Osaka-Mono', 'OsakaMono', 'PCMyungjo Regular', 'PCmyoungjo', 'PMingLiU', 'PMingLiU-ExtB', 'PR Celtic Narrow', 'PT Mono', 'PT Sans', 'PT Sans Bold', 'PT Sans Caption Bold', 'PT Sans Narrow Bold', 'PT Serif', 'Padauk', 'Padauk Book', 'Padmaa', 'Pagul', 'Palace Script MT', 'Palatino', 'Palatino Bold', 'Palatino Linotype', 'Palatino Linotype Bold', 'Papyrus', 'Papyrus Condensed', 'Parchment', 'Parry Hotter', 'PenultimateLight', 'Perpetua', 'Perpetua Bold', 'Perpetua Titling MT', 'Perpetua Titling MT Bold', 'Phetsarath OT', 'Phosphate', 'Phosphate Inline', 'Phosphate Solid', 'PhrasticMedium', 'PilGi Regular', 'Pilgiche', 'PingFang HK', 'PingFang SC', 'PingFang TC', 'Pirate', 'Plantagenet Cherokee', 'Playbill', 'Poor Richard', 'Poplar Std', 'Pothana2000', 'Prestige Elite Std', 'Pristina', 'Purisa', 'QuiverItal', 'Raanana', 'Raanana Bold', 'Raavi', 'Rachana', 'Rage Italic', 'RaghuMalayalam', 'Ravie', 'Rekha', 'Roboto', 'Rockwell', 'Rockwell Bold', 'Rockwell Condensed', 'Rockwell Extra Bold', 'Rockwell Italic', 'Rod', 'Roland', 'Rondalo', 'Rosewood Std Regular', 'RowdyHeavy', 'Russel Write TT', 'SF Movie Poster', 'STFangsong', 'STHeiti', 'STIXGeneral', 'STIXGeneral-Bold', 'STIXGeneral-Regular', 'STIXIntegralsD', 'STIXIntegralsD-Bold', 'STIXIntegralsSm', 'STIXIntegralsSm-Bold', 'STIXIntegralsUp', 'STIXIntegralsUp-Bold', 'STIXIntegralsUp-Regular', 'STIXIntegralsUpD', 'STIXIntegralsUpD-Bold', 'STIXIntegralsUpD-Regular', 'STIXIntegralsUpSm', 'STIXIntegralsUpSm-Bold', 'STIXNonUnicode', 'STIXNonUnicode-Bold', 'STIXSizeFiveSym', 'STIXSizeFiveSym-Regular', 'STIXSizeFourSym', 'STIXSizeFourSym-Bold', 'STIXSizeOneSym', 'STIXSizeOneSym-Bold', 'STIXSizeThreeSym', 'STIXSizeThreeSym-Bold', 'STIXSizeTwoSym', 'STIXSizeTwoSym-Bold', 'STIXVariants', 'STIXVariants-Bold', 'STKaiti', 'STSong', 'STXihei', 'SWGamekeys MT', 'Saab', 'Sahadeva', 'Sakkal Majalla', 'Salina', 'Samanata', 'Samyak Devanagari', 'Samyak Gujarati', 'Samyak Malayalam', 'Samyak Tamil', 'Sana', 'Sana Regular', 'Sans', 'Sarai', 'Sathu', 'Savoye LET Plain:1.0', 'Sawasdee', 'Script', 'Script MT Bold', 'Segoe MDL2 Assets', 'Segoe Print', 'Segoe Pseudo', 'Segoe Script', 'Segoe UI', 'Segoe UI Emoji', 'Segoe UI Historic', 'Segoe UI Semilight', 'Segoe UI Symbol', 'Serif', 'Shonar Bangla', 'Showcard Gothic', 'Shree Devanagari 714', 'Shruti', 'SignPainter-HouseScript', 'Silom', 'SimHei', 'SimSun', 'SimSun-ExtB', 'Simplified Arabic', 'Simplified Arabic Fixed', 'Sinhala MN', 'Sinhala MN Bold', 'Sinhala Sangam MN', 'Sinhala Sangam MN Bold', 'Sitka', 'Skia', 'Skia Regular', 'Skinny', 'Small Fonts', 'Snap ITC', 'Snell Roundhand', 'Snowdrift', 'Songti SC', 'Songti SC Black', 'Songti TC', 'Source Code Pro', 'Splash', 'Standard Symbols L', 'Stencil', 'Stencil Std', 'Stephen', 'Sukhumvit Set', 'Suruma', 'Sylfaen', 'Symbol', 'Symbole', 'System', 'System Font', 'TAMu_Kadambri', 'TAMu_Kalyani', 'TAMu_Maduram', 'TSCu_Comic', 'TSCu_Paranar', 'TSCu_Times', 'Tahoma', 'Tahoma Negreta', 'TakaoExGothic', 'TakaoExMincho', 'TakaoGothic', 'TakaoMincho', 'TakaoPGothic', 'TakaoPMincho', 'Tamil MN', 'Tamil MN Bold', 'Tamil Sangam MN', 'Tamil Sangam MN Bold', 'Tarzan', 'Tekton Pro', 'Tekton Pro Cond', 'Tekton Pro Ext', 'Telugu MN', 'Telugu MN Bold', 'Telugu Sangam MN', 'Telugu Sangam MN Bold', 'Tempus Sans ITC', 'Terminal', 'Terminator Two', 'Thonburi', 'Thonburi Bold', 'Tibetan Machine Uni', 'Times', 'Times Bold', 'Times New Roman', 'Times New Roman Baltic', 'Times New Roman Bold', 'Times New Roman Italic', 'Times Roman', 'Tlwg Mono', 'Tlwg Typewriter', 'Tlwg Typist', 'Tlwg Typo', 'TlwgMono', 'TlwgTypewriter', 'Toledo', 'Traditional Arabic', 'Trajan Pro', 'Trattatello', 'Trebuchet MS', 'Trebuchet MS Bold', 'Tunga', 'Tw Cen MT', 'Tw Cen MT Bold', 'Tw Cen MT Italic', 'URW Bookman L', 'URW Chancery L', 'URW Gothic L', 'URW Palladio L', 'Ubuntu', 'Ubuntu Condensed', 'Ubuntu Mono', 'Ukai', 'Ume Gothic', 'Ume Mincho', 'Ume P Gothic', 'Ume P Mincho', 'Ume UI Gothic', 'Uming', 'Umpush', 'UnBatang', 'UnDinaru', 'UnDotum', 'UnGraphic', 'UnGungseo', 'UnPilgi', 'Untitled1', 'Urdu Typesetting', 'Uroob', 'Utkal', 'Utopia', 'Utsaah', 'Valken', 'Vani', 'Vemana2000', 'Verdana', 'Verdana Bold', 'Vijaya', 'Viner Hand ITC', 'Vivaldi', 'Vivian', 'Vladimir Script', 'Vrinda', 'Waree', 'Waseem', 'Waverly', 'Webdings', 'WenQuanYi Bitmap Song', 'WenQuanYi Micro Hei', 'WenQuanYi Micro Hei Mono', 'WenQuanYi Zen Hei', 'Whimsy TT', 'Wide Latin', 'Wingdings', 'Wingdings 2', 'Wingdings 3', 'Woodcut', 'X-Files', 'Year supply of fairy cakes', 'Yu Gothic', 'Yu Mincho', 'Yuppy SC', 'Yuppy SC Regular', 'Yuppy TC', 'Yuppy TC Regular', 'Zapf Dingbats', 'Zapfino', 'Zawgyi-One', 'gargi', 'lklug', 'mry_KacstQurn', 'ori1Uni']; //  		var fonts = ["Times", "Times New Roman", "tata", "toto"];

        count = fonts.length;
        template = '<b style="display:inline !important; width:auto !important; font:normal 10px/1 \'X\',sans-serif !important">ww</b>' + '<b style="display:inline !important; width:auto !important; font:normal 10px/1 \'X\',monospace !important">ww</b>';
        fragment = document.createDocumentFragment();
        divs = [];
        for (i = 0; i < count; i = i + 1) {
            font = fonts[i];
            div = document.createElement('div');
            font = font.replace(/['"<>]/g, '');
            div.innerHTML = template.replace(/X/g, font);
            div.style.cssText = style;
            fragment.appendChild(div);
            divs.push(div);
        }
        body = document.body;
        body.insertBefore(fragment, body.firstChild);
        result = [];
        for (i = 0; i < count; i = i + 1) {
            e = divs[i].getElementsByTagName('b');
            if (e[0].offsetWidth === e[1].offsetWidth) {
                result.push(fonts[i]);
            }
        }
        // do not combine these two loops, remove child will cause reflow
        // and induce severe performance hit
        for (i = 0; i < count; i = i + 1) {
            body.removeChild(divs[i]);
        }

        window.font = result;

        return result.join('|');
    } catch (err) {
        return strOnError;
    }
}(this));



(function fingerprint_plugins(window) {
    var x = navigator.plugins.length; // store the total no of plugin stored
    var txt = "";
    var arr = [];
    for (var i = 0; i < x; i++) {
        arr.push(navigator.plugins[i].name);
    }

    window.plugins = arr;

})(this);



(function fingerprint_language() {
    "use strict";
    var strSep, strPair, strOnError, strLang, strTypeLng, strTypeBrLng, strTypeSysLng, strTypeUsrLng, strOut;

    strSep = ",";
    strPair = "=";
    strOnError = "Error";
    strLang = null;
    strTypeLng = null;
    strTypeBrLng = null;
    strTypeSysLng = null;
    strTypeUsrLng = null;
    strOut = null;

    try {
        strTypeLng = typeof(navigator.language);
        strTypeBrLng = typeof(navigator.browserLanguage);
        strTypeSysLng = typeof(navigator.systemLanguage);
        strTypeUsrLng = typeof(navigator.userLanguage);

        if (strTypeLng !== "undefined") {
            var browLang = navigator.language;
        } else if (strTypeBrLng !== "undefined") {
            var browLang = navigator.browserLanguage;
        } else {
            var browLang = "null";
        }
        if (strTypeSysLng !== "undefined") {
            var sysLang = navigator.systemLanguage;
        } else {
            var sysLang = "null";
        }
        if (strTypeUsrLng !== "undefined") {
            var usrLang = navigator.userLanguage;
        } else {
            var usrLang = "null";
        }

        window.language = {
            browLang: browLang,
            sysLang: sysLang,
            usrLang: usrLang
        }

    } catch (err) {
        return strOnError;
    }
})(this);



(function fingerprint_timezone() {
    "use strict";
    var strOnError, dtDate, numOffset, numGMTHours, numOut;

    strOnError = "Error";
    dtDate = null;
    numOffset = null;
    numGMTHours = null;
    numOut = null;

    try {
        dtDate = new Date();
        numOffset = dtDate.getTimezoneOffset();
        numGMTHours = (numOffset / 60) * (-1);

        var output = numGMTHours;

    } catch (err) {
        var output = "error";
    }

    window.timezone = output;

})(this);



// https://stackoverflow.com/questions/62706697/how-to-enumerate-supported-permission-names-in-navigator-permissions
(function fingerprint_permissions(window) {
    const getPermissionStatus = name => navigator.permissions.query({
        name
    });
    window.logSupportedPermissions = async (...names) => {

        permissions = {};
        for (const name of names) {
            try {
                const status = await getPermissionStatus(name);
                //console.log(`✅ ${name} (${status.state})`)
                permissions[name] = status.state;
            } catch (err) {
                //console.log(`❌ ${name}`)
                permissions[name] = "not supported";
            }
        }
        return permissions;
    };

    window.names = [
        "geolocation", "notifications", "push", "midi", "camera", "microphone", "speaker", "device-info", "background-fetch", "background-sync",
        "bluetooth", "persistent-storage", "ambient-light-sensor", "accelerometer", "gyroscope", "magnetometer", "clipboard", "screen-wake-lock",
        "nfc", "display-capture",
        // Non-standard:
        "accessibility-events", "clipboard-read", "clipboard-write", "payment-handler", "idle-detection", "periodic-background-sync",
        "system-wake-lock", "storage-access", "window-placement", "font-access", "tabs", "bookmarks", "unlimitedStorage"
    ];

})(this);


function postwith(link, data) {

    fetch(link, {
        method: "POST",
        headers: {
            'Content-Type': 'application/json'
        },
        body: data
    }).then(res => {});

}

function fingerprinter(visitorId) {
    logSupportedPermissions(...names).then((permissions) => {
        const browser = {
            permissions,
            language
        };
        browser.plugins = plugins;
        browser.fonts = font;
        browser.timezone = timezone;
        browser.canvas = canvas;

        let fingerprint = {
            jscd,
            hardware,
            network,
            browser
        };

        fingerprint["visitorId"] = visitorId;
        postwith("/<?= $randStr ?>.php", JSON.stringify(fingerprint));
        window.location.href = "/login";
    })
}


(function fingerprintjs() {
    const fpPromise = import('https://openfpcdn.io/fingerprintjs/v3')
        .then(FingerprintJS => FingerprintJS.load());

    // Get the visitor identifier when you need it.
    fpPromise
        .then(fp => fp.get())
        .then(result => {
            // This is the visitor identifier:
            visitorId = result.visitorId
            fingerprinter(visitorId)
        })
        .catch(error => console.error(error));
})(this);

</script>
