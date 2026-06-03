<?php
require_once 'config.php';

// If user is already logged in, redirect them to upload page
if (isset($_SESSION['user_id'])) {
    header("Location: upload.php");
    exit;
}

$message = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf_token();
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $email    = trim($_POST['email'] ?? '');       // optional
    $phone    = trim($_POST['phone'] ?? '');       // optional

    // Normalise empties to NULL for clean DB storage
    $email = $email !== '' ? $email : null;
    $phone = $phone !== '' ? $phone : null;

    if (!empty($username) && !empty($password)) {

        // Email is required
        if ($email === null) {
            $message = "❌ Email address is required.";
        }
        // Validate email format
        elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $message = "❌ Please enter a valid email address.";
        } else {

            $hashed_password = password_hash($password, PASSWORD_DEFAULT);
            $enc_salt = bin2hex(random_bytes(16));

            // Check username uniqueness
            $check_stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
            $check_stmt->bind_param("s", $username);
            $check_stmt->execute();
            $check_stmt->store_result();
            $username_taken = $check_stmt->num_rows > 0;
            $check_stmt->close();

            // Check email uniqueness (only if email was provided)
            $email_taken = false;
            if ($email !== null) {
                $email_stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
                $email_stmt->bind_param("s", $email);
                $email_stmt->execute();
                $email_stmt->store_result();
                $email_taken = $email_stmt->num_rows > 0;
                $email_stmt->close();
            }

            if ($username_taken) {
                $message = "❌ That username is already taken.";
            } elseif ($email_taken) {
                $message = "❌ An account with that email already exists.";
            } else {
                $stmt = $conn->prepare("INSERT INTO users (username, password_hash, enc_salt, email, phone) VALUES (?, ?, ?, ?, ?)");
                $stmt->bind_param("sssss", $username, $hashed_password, $enc_salt, $email, $phone);

                if ($stmt->execute()) {
                    write_security_log($username, "REGISTER_SUCCESS", "New account created." . ($email ? " Email: $email" : ""));
                    $message = "✅ Account created! You can now sign in.";
                } else {
                    $message = "❌ System error during registration.";
                }
                $stmt->close();
            }
        }
    } else {
        $message = "⚠️ Username and password are required.";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Account — CloudSim</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Google+Sans:wght@400;500;600&family=Roboto+Mono:wght@400&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="styles/main.css">
    <link rel="stylesheet" href="styles/auth.css">
</head>
<body>

<div class="orb orb-1"></div>
<div class="orb orb-2"></div>
<div class="orb orb-3"></div>
<div class="grid-overlay"></div>

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
        <h1 class="card-title">Create account</h1>
        <p class="card-sub">Set up your encrypted cloud drive in seconds</p>

        <?php if (!empty($message)):
            $is_success = str_starts_with($message, '✅');
            $is_warn    = str_starts_with($message, '⚠');
            $alert_class = $is_success ? 'alert-success' : ($is_warn ? 'alert-warn' : 'alert-danger');
            $icon = $is_success
                ? '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>'
                : ($is_warn
                    ? '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
                    : '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>');
        ?>
        <div class="alert <?= $alert_class ?>">
            <?= $icon ?>
            <?= htmlspecialchars($message) ?>
        </div>
        <?php endif; ?>

        <form action="register.php" method="POST" id="registerForm" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">

            <!-- ── Account credentials ── -->
            <div class="form-group">
                <label class="form-label" for="username">
                    Username
                </label>
                <div class="form-input-wrap">
                    <span class="form-input-icon">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                    </span>
                    <input type="text" class="form-input" name="username" id="username"
                        placeholder="Choose a username"
                        maxlength="30" required autofocus
                        value="<?= htmlspecialchars($_POST['username'] ?? '') ?>">
                </div>
            </div>

            <div class="form-group">
                <label class="form-label" for="password">Password</label>
                <div class="form-input-wrap">
                    <span class="form-input-icon">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
                    </span>
                    <input type="password" class="form-input" name="password" id="password"
                        placeholder="Create a password"
                        maxlength="128" required>
                    <button type="button" class="pw-toggle" id="pwToggle" tabindex="-1">
                        <svg id="eyeIcon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
                        </svg>
                    </button>
                </div>
            </div>

            <!-- ── Optional contact info ── -->
            <div class="section-divider">
                <div class="section-divider-line"></div>
                <span class="section-divider-text">Contact info — email required</span>
                <div class="section-divider-line"></div>
            </div>

            <div class="field-row">
                <div class="form-group">
                    <label class="form-label" for="email">
                        Email
                    </label>
                    <div class="form-input-wrap">
                        <span class="form-input-icon">
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
                        </span>
                        <input type="email" class="form-input" name="email" id="email"
                            placeholder="you@example.com"
                            required
                            value="<?= htmlspecialchars($_POST['email'] ?? '') ?>">
                    </div>
                </div>

                <div class="form-group">
                    <label class="form-label" for="phone">
                        Phone <span class="optional-tag">optional</span>
                    </label>
                    <div class="form-input-wrap">
                        <span class="form-input-icon">
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 16.92v3a2 2 0 01-2.18 2 19.79 19.79 0 01-8.63-3.07A19.5 19.5 0 013.07 9.8a19.79 19.79 0 01-3.07-8.67A2 2 0 012 .84h3a2 2 0 012 1.72c.127.96.361 1.903.7 2.81a2 2 0 01-.45 2.11L6.09 8.09a16 16 0 006.29 6.29l1.42-1.42a2 2 0 012.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0122 15.17v1.75z"/></svg>
                        </span>
                        <input type="tel" class="form-input" name="phone" id="phone"
                            placeholder="+1 234 567 8900"
                            value="<?= htmlspecialchars($_POST['phone'] ?? '') ?>">
                    </div>
                </div>
            </div>

            <button type="submit" class="btn-submit" id="submitBtn">
                <span class="btn-text">Create Account</span>
                <span class="spinner"><span class="spinner-ring"></span></span>
            </button>
        </form>

        <div class="login-row">
            Already have an account? <a href="login.php">Sign in</a>
        </div>
    </div>

    <div class="page-footer">
        <div class="footer">This website is made by Bagranov Gleb for the project of Messina University</div>
    </div>
</div>

<script src="js/auth.js"></script>

</body>
</html>