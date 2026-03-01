<?php
function uuidv7(): string {
    $ms = (int) floor(microtime(true) * 1000);

    $bytes = random_bytes(16);

    // timestamp 48-bit big-endian into bytes 0..5
    $bytes[0] = chr(($ms >> 40) & 0xFF);
    $bytes[1] = chr(($ms >> 32) & 0xFF);
    $bytes[2] = chr(($ms >> 24) & 0xFF);
    $bytes[3] = chr(($ms >> 16) & 0xFF);
    $bytes[4] = chr(($ms >> 8) & 0xFF);
    $bytes[5] = chr($ms & 0xFF);

    // version 7
    $bytes[6] = chr((ord($bytes[6]) & 0x0F) | 0x70);

    // RFC4122 variant
    $bytes[8] = chr((ord($bytes[8]) & 0x3F) | 0x80);

    $hex = bin2hex($bytes);
    return sprintf(
        '%s-%s-%s-%s-%s',
        substr($hex, 0, 8),
        substr($hex, 8, 4),
        substr($hex, 12, 4),
        substr($hex, 16, 4),
        substr($hex, 20, 12)
    );
}
