<?php
require_once 'config.php';

// Ensure the user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

$user_id = $_SESSION['user_id'];
$username = $_SESSION['username'];
$message = "";
$error_message = "";

// --- HANDLE FORM SUBMISSIONS ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // 1. HANDLE PASSWORD UPDATE
    if (isset($_POST['update_password'])) {
        $new_password = $_POST['new_password'];
        $confirm_password = $_POST['confirm_password'];

        if (empty($new_password)) {
            $error_message = "❌ Password cannot be empty.";
        } elseif ($new_password !== $confirm_password) {
            $error_message = "❌ Passwords do not match.";
        } else {
            $new_hash = password_hash($new_password, PASSWORD_BCRYPT);
            
            $stmt = $conn->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
            $stmt->bind_param("si", $new_hash, $user_id);
            
            if ($stmt->execute()) {
                write_security_log($username, "PASSWORD_CHANGED", "User updated account password.");
                $message = "✅ Password updated successfully.";
            } else {
                $error_message = "❌ Database error updating password.";
            }
            $stmt->close();
        }
    }

    // 2. HANDLE ENCRYPTED BLOB AVATAR UPDATE
    if (isset($_POST['update_avatar']) && isset($_FILES['avatar_img'])) {
        $file = $_FILES['avatar_img'];
        
        if ($file['error'] === UPLOAD_ERR_OK) {
            // Validate file extension
            $file_ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
            $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif'];
            
            if (!in_array($file_ext, $allowed_extensions)) {
                write_security_log($username, "AVATAR_REJECTED", "Banned extension: $file_ext");
                $error_message = "❌ Unsafe file type. Only JPG, PNG, and GIF are allowed.";
            } 
            // Validate file size limit (2MB)
            elseif ($file['size'] > 2 * 1024 * 1024) {
                $error_message = "❌ Avatar file size must be under 2 MB.";
            } 
            else {
                // Secure validation of actual file structure using finfo
                $finfo = new finfo(FILEINFO_MIME_TYPE);
                $mime_type = $finfo->file($file['tmp_name']);
                $allowed_mimes = ['image/jpeg', 'image/png', 'image/gif'];
                
                if (!in_array($mime_type, $allowed_mimes)) {
                    write_security_log($username, "AVATAR_SPOOF_DETECTED", "MIME type mismatch.");
                    $error_message = "❌ Invalid image architecture structure detected.";
                } else {
                    // Fetch raw data bytes from the temporary upload stream
                    $plaintext_avatar = file_get_contents($file['tmp_name']);
                    
                    // Setup AES-256-CTR Layer
                    $cipher_method = "aes-256-ctr";
                    $iv_length = openssl_cipher_iv_length($cipher_method);
                    $iv = random_bytes($iv_length);
                    
                    // Use your application session encryption key
                    $encryption_key = hex2bin($_SESSION['encryption_key']);
                    
                    // Encrypt raw image payload binary data
                    $encrypted_avatar = openssl_encrypt($plaintext_avatar, $cipher_method, $encryption_key, OPENSSL_RAW_DATA, $iv);
                    
                    // Prepend the IV to the encrypted content package
                    $final_blob_payload = $iv . $encrypted_avatar;
                    
                    // Bind and execute structural database modification
                    $stmt = $conn->prepare("UPDATE users SET avatar_blob = ?, avatar_mime = ? WHERE id = ?");
                    $stmt->bind_param("ssi", $final_blob_payload, $mime_type, $user_id);
                    
                    if ($stmt->execute()) {
                        write_security_log($username, "AVATAR_ENCRYPTED_SUCCESS", "Stored profile picture inside data BLOB.");
                        $message = "✅ Encrypted avatar updated successfully.";
                    } else {
                        $error_message = "❌ Failed to save encrypted profile content to database storage.";
                    }
                    $stmt->close();
                }
            }
        } else {
            $error_message = "❌ Error uploading image asset file.";
        }
    }
}

// --- DECRYPT AND DISPLAY ACTIVE AVATAR FROM BLOB ---
$stmt = $conn->prepare("SELECT avatar_blob, avatar_mime FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result()->fetch_assoc();
$stmt->close();

$avatar_src = "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='100' height='100' viewBox='0 0 100 100'><circle cx='50' cy='50' r='50' fill='%23ccc'/><text x='50%' y='55%' font-size='40' text-anchor='middle' dominant-baseline='middle'>👤</text></svg>"; // Secure vector default fallback

if (!empty($result['avatar_blob']) && !empty($result['avatar_mime'])) {
    $database_payload = $result['avatar_blob'];
    $mime_type = $result['avatar_mime'];
    
    $cipher_method = "aes-256-ctr";
    $iv_length = openssl_cipher_iv_length($cipher_method);
    
    // Parse the payload blocks cleanly
    $extracted_iv = substr($database_payload, 0, $iv_length);
    $encrypted_data = substr($database_payload, $iv_length);
    $encryption_key = hex2bin($_SESSION['encryption_key']);
    
    // Decrypt the raw binary asset structure string
    $decrypted_binary = openssl_decrypt($encrypted_data, $cipher_method, $encryption_key, OPENSSL_RAW_DATA, $extracted_iv);
    
    if ($decrypted_binary !== false) {
        // Formulate inline Data URI presentation path string
        $avatar_src = "data:" . htmlspecialchars($mime_type) . ";base64," . base64_encode($decrypted_binary);
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Personal Space - Secure Profile Settings</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f8f9fa; color: #333; }
        .container { max-width: 500px; background: white; padding: 25px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin: 0 auto; }
        .form-group { margin-bottom: 20px; }
        label { font-weight: bold; display: block; margin-bottom: 5px; }
        input[type="password"], input[type="file"] { width: 100%; padding: 8px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }
        button { background: #28a745; color: white; border: none; padding: 10px 15px; border-radius: 4px; cursor: pointer; font-weight: bold; }
        button:hover { background: #218838; }
        .alert { padding: 10px; margin-bottom: 15px; border-radius: 4px; font-size: 14px; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-danger { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .avatar-preview { width: 120px; height: 120px; border-radius: 50%; object-fit: cover; border: 3px solid #007bff; margin-bottom: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.15); }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        hr { border: 0; height: 1px; background: #eee; margin: 25px 0; }
    </style>
</head>
<body>

<div class="container">
    <h2>🛡️ Personal Space: <?= htmlspecialchars($username) ?></h2>
    <p><a href="upload.php">◀ Return to Main Dashboard</a></p>
    <hr>

    <?php if (!empty($message)): ?>
        <div class="alert alert-success"><?= $message ?></div>
    <?php endif; ?>
    <?php if (!empty($error_message)): ?>
        <div class="alert alert-danger"><?= $error_message ?></div>
    <?php endif; ?>

    <form action="profile.php" method="POST" enctype="multipart/form-data">
        <h3>Encrypted Profile Image</h3>
        <div class="form-group" style="text-align: center;">
            <img src="<?= $avatar_src ?>" alt="Active Profile Image Snapshot" class="avatar-preview"><br>
            <label style="text-align: left;">Upload New Asset Cover (Max 2MB - JPG/PNG/GIF):</label>
            <input type="file" name="avatar_img" required>
        </div>
        <button type="submit" name="update_avatar">Save Secure Image</button>
    </form>

    <hr>

    <form action="profile.php" method="POST">
        <h3>Modify Account Credentials</h3>
        <div class="form-group">
            <label>New Passphrase String:</label>
            <input type="password" name="new_password" required autocomplete="new-password">
        </div>
        <div class="form-group">
            <label>Confirm Passphrase Verification:</label>
            <input type="password" name="confirm_password" required autocomplete="new-password">
        </div>
        <button type="submit" name="update_password" style="background-color: #007bff;">Commit Password Change</button>
    </form>
</div>

</body>
</html>