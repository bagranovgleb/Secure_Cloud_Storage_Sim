<?php

require_once 'config.php';




// Redirect to upload dashboard if session is already verified
if (isset($_SESSION['user_id'])) {
    header("Location: upload.php");
    exit;
}

$message = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf_token();
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
        $stmt = $conn->prepare("SELECT id, password_hash, role, enc_salt FROM users WHERE username = ?");
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

                // --- STABLE ENCRYPTION KEY DERIVATION (PBKDF2) ---
                // Derived deterministically from the user's password + their stored per-user salt.
                // Identical inputs always produce the same key, so encrypted files remain
                // readable across session expiry, server restarts, and re-logins.
                // The plaintext password is available only here at login — the ideal derivation point.
                $derived_key = hash_pbkdf2('sha256', $password, $user['enc_salt'], 200000, 32, true);
                $_SESSION['encryption_key'] = bin2hex($derived_key);
                
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
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in — CloudSim</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Google+Sans:wght@400;500;600&family=Roboto+Mono:wght@400&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="styles/main.css">
    <link rel="stylesheet" href="styles/auth.css">
</head>
<body>

<!-- Background layers -->
<div class="orb orb-1"></div>
<div class="orb orb-2"></div>
<div class="orb orb-3"></div>
<div class="orb orb-4"></div>
<div class="grid-overlay"></div>

<!-- Login card -->
<div class="card-wrap" id="cardWrap">

    <a href="login.php" class="logo">
        <div class="logo-icon">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M3 15a4 4 0 004 4h10a4 4 0 001-7.9A5 5 0 1015.9 6L15 6a5 5 0 00-5 5l-1 .1A4 4 0 003 15z"/>
            </svg>
        </div>
        <span class="logo-name">Cloud<span>Sim</span></span>
    </a>

    <div class="card">
        <h1 class="card-title">Welcome back</h1>
        <p class="card-sub">Sign in to access your encrypted drive</p>

        <?php if (!empty($message)):
            $is_warn = str_starts_with($message, '⚠');
            $alert_class = $is_warn ? 'alert-warn' : 'alert-danger';
            $icon = $is_warn
                ? '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
                : '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
        ?>
        <div class="alert <?= $alert_class ?>">
            <?= $icon ?>
            <?= htmlspecialchars($message) ?>
        </div>
        <?php endif; ?>

        <?php if (isset($_GET['status']) && $_GET['status'] === 'account_deleted'): ?>
        <div class="alert alert-success">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
            Your account and all encrypted data have been permanently deleted.
        </div>
        <?php endif; ?>

        <form action="login.php" method="POST" id="loginForm" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">

            <div class="form-group">
                <label class="form-label" for="username">Username</label>
                <div class="form-input-wrap">
                    <span class="form-input-icon">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                    </span>
                    <input
                        type="text" class="form-input" name="username" id="username"
                        placeholder="Enter your username"
                        maxlength="30" required autofocus
                        value="<?= htmlspecialchars($_POST['username'] ?? '') ?>">
                </div>
            </div>

            <div class="form-group">
                <label class="form-label" for="password">Password</label>
                <div class="form-input-wrap">
                    <span class="form-input-icon">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
                    </span>
                    <input
                        type="password" class="form-input" name="password" id="password"
                        placeholder="Enter your password"
                        maxlength="128" required id="passwordInput">
                    <button type="button" class="pw-toggle" id="pwToggle" title="Show/hide password" tabindex="-1">
                        <svg id="eyeIcon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
                        </svg>
                    </button>
                </div>
            </div>

            <button type="submit" class="btn-submit" id="submitBtn">
                <span class="btn-text">Sign In</span>
                <span class="spinner"><span class="spinner-ring"></span></span>
            </button>
        </form>

        <div class="divider">
            <div class="divider-line"></div>
            <span class="divider-text">or</span>
            <div class="divider-line"></div>
        </div>

        <div class="register-row">
            Don't have an account? <a href="register.php">Create one</a>
        </div>
    </div>

    <div class="page-footer">
        <div class="footer">This website is made by Bagranov Gleb for the project of Messina University</div>
    </div>
</div>

<script src="js/auth.js"></script>

</body>
</html>