<?php
require_once 'config.php';

// If user is already logged in, redirect them to upload page
if (isset($_SESSION['user_id'])) {
    header("Location: upload.php");
    exit;
}

$message = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if (!empty($username) && !empty($password)) {
        // --- SECURE PASSWORD HASHING ---
        // PASSWORD_DEFAULT relies on strong algorithms (currently bcrypt) and salts automatically.
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        // --- ENCRYPTION SALT GENERATION ---
        // A unique random salt per user, stored permanently.
        // Combined with the user's password at login via PBKDF2 to derive a
        // stable, deterministic encryption key — files survive session expiry and re-logins.
        $enc_salt = bin2hex(random_bytes(16)); // 32-char hex string, stored in DB

        // Check if username already exists to prevent duplicate entries
        $check_stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $check_stmt->bind_param("s", $username);
        $check_stmt->execute();
        $check_stmt->store_result();

        if ($check_stmt->num_rows > 0) {
            $message = "❌ Error: Username is already taken.";
        } else {
            // Insert the secure user profile into the database (with enc_salt)
            $stmt = $conn->prepare("INSERT INTO users (username, password_hash, enc_salt) VALUES (?, ?, ?)");
            $stmt->bind_param("sss", $username, $hashed_password, $enc_salt);

            if ($stmt->execute()) {
                $message = "✅ Registration successful! You can now log in.";
            } else {
                $message = "❌ System error during database write.";
            }
            $stmt->close();
        }
        $check_stmt->close();
    } else {
        $message = "⚠️ Please fill in all fields.";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Cloud Sim - Register</title>
</head>
<body>
    <h2>Create Simulated Cloud Account</h2>
    <?php if(!empty($message)) echo "<p>$message</p>"; ?>
    
    <form action="register.php" method="POST">
        <label>Username:</label><br>
        <input type="text" name="username" required><br><br>
        
        <label>Password:</label><br>
        <input type="password" name="password" required><br><br>
        
        <button type="submit">Register</button>
    </form>
    <br>
    <a href="login.php">Already have an account? Log in here.</a>
</body>
</html>