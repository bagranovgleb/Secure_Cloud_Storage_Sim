<?php

require_once 'config.php';




// Redirect to upload dashboard if session is already verified
if (isset($_SESSION['user_id'])) {
    header("Location: upload.php");
    exit;
}

$message = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    // CONTROL A: BOUNDARY INTERCEPTION VALVE
    // Drop execution immediately if string bounds exceed expected structural standards
    if (strlen($username) > 30 || strlen($password) > 128) {
        write_security_log("NETWORK_ANOMALY", "DOS_ATTEMPT", "Input parameters exceeded length constraints. Packet dropped.");
        header("HTTP/1.1 400 Bad Request");
        die("❌ Bad Request: Malformed input bounds.");
    }

    if (!empty($username) && !empty($password)) {
        // Query the entry registry matching the unique username
        $stmt = $conn->prepare("SELECT id, password_hash, role FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        
        $result = $stmt->get_result();
        $user = $result->fetch_assoc(); // 1. Pull data out into memory first
        $stmt->close();                 // 2. Safely close statement right after fetch

        if ($user) {
            // --- SECURE HASH VERIFICATION ---
            if (password_verify($password, $user['password_hash'])) {
                // Destroy old session identifier and issue a brand new one
                session_regenerate_id(true);
                
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $username;
                $_SESSION['role'] = $user['role']; 
                
                // --- CRYPTOGRAPHIC DATA-AT-REST ENCRYPTION KEY ---
                $_SESSION['encryption_key'] = bin2hex(random_bytes(32));
                
                write_security_log($username, "LOGIN_SUCCESS", "Authenticated as role: " . $user['role']);
                
                // Redirect based on privilege level
                if ($_SESSION['role'] === 'admin') {
                    header("Location: admin_dashboard.php");
                } else {
                    header("Location: upload.php");
                }
                exit; // End execution safely after successful redirect
            } else {
                write_security_log($username, "LOGIN_FAILED", "Invalid password for existing user account.");
                $message = "❌ Invalid username or password.";
            }
        } else {
            write_security_log($username, "LOGIN_FAILED", "Authentication attempted for non-existent username.");
            $message = "❌ Invalid username or password.";
        }
    } else {
        $message = "⚠️ Please provide both your credentials.";
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Cloud Sim - Login</title>
</head>
<body>
    <h2>Cloud Simulation Gateway</h2>
    <?php 
    if(!empty($message)) {
        echo "<p>$message</p>"; 
    }

    if (isset($_GET['status']) && $_GET['status'] === 'account_deleted') {
        echo "<p style='color: #155724; background: #d4edda; padding: 10px; border-radius: 4px; border: 1px solid #c3e6cb; max-width: 400px; margin: 15px auto;'>✅ Your profile and all corresponding file data volumes have been completely purged from our cloud servers.</p>";
    }
    ?>
    <form action="login.php" method="POST">
        <label>Username:</label><br>
        <input type="text" name="username" required><br><br>
        
        <label>Password:</label><br>
        <input type="password" name="password" required><br><br>
        
        <button type="submit">Log In</button>
    </form>
    <br>
    <a href="register.php">Need an account? Register here.</a>
</body>
</html>