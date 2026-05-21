<?php
// 1. Secure Session Configuration (Must run before session_start)
ini_set('session.cookie_httponly', 1);
ini_set('session.use_only_cookies', 1);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// 2. Database Connection Template
// Replace placeholders below with your local database environment settings
define('DB_HOST', 'localhost');
define('DB_USER', 'YOUR_DATABASE_USERNAME');     // e.g., 'root'
define('DB_PASS', 'YOUR_DATABASE_PASSWORD');     // e.g., ''
define('DB_NAME', 'cloud_simulation');

$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if ($conn->connect_error) {
    write_security_log("SYSTEM", "CRITICAL", "Database connection failed.");
    die("Database failure.");
}

// 3. Centralized Audit Logging Function
function write_security_log($username, $action, $details) {
    $log_directory = dirname(__DIR__, 2) . '/secure_logs/';
    $log_file = $log_directory . 'security_audit.log';
    
    $timestamp = date('Y-m-d H:i:s');
    $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
    
    $log_entry = sprintf("[%s] [%s] [%s] [%s] -> %s\n", $timestamp, $ip_address, $username, $action, $details);
    file_put_contents($log_file, $log_entry, FILE_APPEND | LOCK_EX);
}

// 4. RATE LIMITING CONTROLLER
function enforce_rate_limit() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    $safe_ip = preg_replace('/[^a-zA-Z0-9_]/', '_', $ip);
    $limit_directory = dirname(__DIR__, 2) . '/secure_logs/rate_limits/';
    
    if (!file_exists($limit_directory)) {
        mkdir($limit_directory, 0755, true);
    }
    
    $ip_file = $limit_directory . $safe_ip . '.json';
    $now = time();
    $time_window = 10;
    $max_requests = 5;
    
    $requests = [];
    if (file_exists($ip_file)) {
        $data = json_decode(file_get_contents($ip_file), true);
        if (is_array($data)) { $requests = $data; }
    }
    
    $requests = array_filter($requests, function($timestamp) use ($now, $time_window) {
        return ($now - $timestamp) < $time_window;
    });
    
    if (count($requests) >= $max_requests) {
        write_security_log("IP_" . $ip, "RATE_LIMIT_TRIPPED", "Excessive request volume detected.");
        header("HTTP/1.1 429 Too Many Requests");
        die("❌ Too Many Requests.");
    }
    
    $requests[] = $now;
    file_put_contents($ip_file, json_encode(array_values($requests)), LOCK_EX);
}

enforce_rate_limit();
?>