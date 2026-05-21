<?php
require_once 'config.php';

if (isset($_SESSION['username'])) {
    write_security_log($_SESSION['username'], "LOGOUT", "User securely disconnected session.");
}

// 1. Unset all session variables in memory
$_SESSION = array();

// 2. Clear the session cookie from the browser
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    
    // Set the cookie expiration date to one hour ago to force deletion
    setcookie(
        session_name(), 
        '', 
        time() - 3600,
        $params["path"], 
        $params["domain"],
        $params["secure"], 
        $params["httponly"]
    );
}

// 3. Destroy the server-side session data block
session_destroy();

// 4. Redirect cleanly back to the gateway login page
header("Location: login.php");
exit;
?>