<?php
// ============================================================
// config_sample.php — CloudSim configuration template
// ============================================================
// HOW TO USE:
//   1. Copy this file and rename it to config.php
//   2. Fill in your database credentials below
//   3. Never commit config.php (it is in .gitignore)
// ============================================================

// 1. SECURE SESSION CONFIGURATION
// Must run before session_start()
ini_set('session.cookie_httponly', 1);   // JS cannot access the session cookie
ini_set('session.use_only_cookies', 1);  // Session ID only via cookie, never via URL
ini_set('session.cookie_secure', 1);     // Only transmit cookie over HTTPS
ini_set('session.cookie_samesite', 'Lax'); // Block cross-site POST forgery at cookie level

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// 2. DATABASE CONNECTION
// Replace the placeholders with your local database credentials
define('DB_HOST', 'localhost');
define('DB_USER', 'YOUR_DATABASE_USERNAME');   // e.g., 'root'
define('DB_PASS', 'YOUR_DATABASE_PASSWORD');   // e.g., '' for XAMPP default
define('DB_NAME', 'cloud_simulation');

$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if ($conn->connect_error) {
    write_security_log("SYSTEM", "CRITICAL", "Database connection failed.");
    die("Database failure.");
}

// 3. CENTRALIZED AUDIT LOGGING
// Writes structured log entries to secure_logs/security_audit.log
// That folder must exist two levels above this file (outside the web root)
// Format: [Timestamp] [IP] [User] [Action] -> Details
function write_security_log($username, $action, $details) {
    $log_directory = dirname(__DIR__, 2) . '/secure_logs/';
    $log_file      = $log_directory . 'security_audit.log';

    $timestamp  = date('Y-m-d H:i:s');
    $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';

    $log_entry = sprintf(
        "[%s] [%s] [%s] [%s] -> %s\n",
        $timestamp, $ip_address, $username, $action, $details
    );

    file_put_contents($log_file, $log_entry, FILE_APPEND | LOCK_EX);
}

// 4. CSRF TOKEN HELPERS
// csrf_token()        — generates (or returns existing) session CSRF token
// verify_csrf_token() — call at the top of every POST handler; dies on mismatch
function csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf_token(): void {
    $submitted = $_POST['csrf_token'] ?? '';
    if (!hash_equals(csrf_token(), $submitted)) {
        http_response_code(403);
        die('❌ Invalid or missing security token. Request blocked.');
    }
}

// 5. RATE LIMITING
// Limits each IP to 5 requests per 10-second window
// Timestamps are stored as JSON files in secure_logs/rate_limits/
// Adjust $time_window and $max_requests below if needed
function enforce_rate_limit() {
    $ip      = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    $safe_ip = preg_replace('/[^a-zA-Z0-9_]/', '_', $ip); // Sanitize for use as filename

    $limit_directory = dirname(__DIR__, 2) . '/secure_logs/rate_limits/';

    if (!file_exists($limit_directory)) {
        mkdir($limit_directory, 0755, true);
    }

    $ip_file     = $limit_directory . $safe_ip . '.json';
    $now         = time();
    $time_window = 10;  // seconds
    $max_requests = 15;  // allowed requests within the window

    $requests = [];
    if (file_exists($ip_file)) {
        $data = json_decode(file_get_contents($ip_file), true);
        if (is_array($data)) {
            $requests = $data;
        }
    }

    // Drop timestamps outside the current window
    $requests = array_filter($requests, function($timestamp) use ($now, $time_window) {
        return ($now - $timestamp) < $time_window;
    });

    if (count($requests) >= $max_requests) {
        write_security_log("IP_" . $ip, "RATE_LIMIT_TRIPPED", "Excessive request volume detected. Request throttled.");
        header("HTTP/1.1 429 Too Many Requests");
        header("Retry-After: " . $time_window);
        die("❌ Too Many Requests: Access locked for {$time_window} seconds.");
    }

    $requests[] = $now;
    file_put_contents($ip_file, json_encode(array_values($requests)), LOCK_EX);
}

// Enforce rate limiting on every request automatically
enforce_rate_limit();
?>