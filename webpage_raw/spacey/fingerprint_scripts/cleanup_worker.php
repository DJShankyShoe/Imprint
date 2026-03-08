#!/usr/bin/env php
<?php
/**
 * Background Cleanup Worker - FIXED VERSION
 * 
 * This script is spawned in the background to delete endpoint files after delay.
 * Usage: php cleanup_worker.php /path/to/file.php 10
 */

// Get arguments
$filepath = $argv[1] ?? '';
$delaySeconds = intval($argv[2] ?? 10);

// Validate filepath exists
if (empty($filepath)) {
    error_log("cleanup_worker: No filepath provided");
    exit(1);
}

// IMPORTANT: File might not exist yet when worker starts
// So we DON'T check if file exists here, only validate the filename

// Validate it's a safe filename (security check)
$basename = basename($filepath);

// Allow both fp_*.php AND test files (for diagnostics)
if (!preg_match('/^(fp_[a-f0-9]{32}\.php|fp_test_\d+\.php|manual_test_\d+\.txt)$/', $basename)) {
    error_log("cleanup_worker: Invalid filename: {$basename}");
    exit(1);
}

// Wait for specified delay
sleep($delaySeconds);

// Delete the file (if it exists)
if (file_exists($filepath)) {
    $deleted = @unlink($filepath);
    if ($deleted) {
        error_log("cleanup_worker: Deleted {$filepath}");
        exit(0);
    } else {
        error_log("cleanup_worker: Failed to delete {$filepath}");
        exit(1);
    }
} else {
    // File already deleted (maybe by endpoint self-delete)
    error_log("cleanup_worker: File already deleted: {$filepath}");
    exit(0);
}
