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

            // --- KEY ROTATION ON PASSWORD CHANGE ---
            // The encryption key is derived from password + enc_salt (PBKDF2).
            // Changing the password means a new key at next login — so we must:
            //   1. Generate a fresh enc_salt
            //   2. Derive the new key now (plaintext password is available only here)
            //   3. Re-encrypt every stored file and the avatar blob under the new key
            //   4. Update password_hash + enc_salt in the DB atomically
            //   5. Refresh $_SESSION['encryption_key'] so the current session stays valid

            $old_key = hex2bin($_SESSION['encryption_key']);
            $new_salt = bin2hex(random_bytes(16));
            $new_key  = hash_pbkdf2('sha256', $new_password, $new_salt, 200000, 32, true);

            $cipher_method = "aes-256-ctr";
            $iv_length     = openssl_cipher_iv_length($cipher_method);

            // Re-encrypt all files on disk
            $file_stmt = $conn->prepare("SELECT id, stored_name, original_name FROM file_registry WHERE owner_id = ?");
            $file_stmt->bind_param("i", $user_id);
            $file_stmt->execute();
            $file_res = $file_stmt->get_result();

            $reencrypt_failed = false;
            while ($file_row = $file_res->fetch_assoc()) {
                $path = __DIR__ . '/storage/' . $file_row['stored_name'];
                if (!file_exists($path)) continue;

                $raw        = file_get_contents($path);
                $old_iv     = substr($raw, 0, $iv_length);
                $old_cipher = substr($raw, $iv_length);

                // Decrypt with old key
                $plain = openssl_decrypt($old_cipher, $cipher_method, $old_key, OPENSSL_RAW_DATA, $old_iv);
                if ($plain === false) { $reencrypt_failed = true; break; }

                // Re-encrypt with new key under a fresh IV
                $new_iv         = random_bytes($iv_length);
                $new_cipher     = openssl_encrypt($plain, $cipher_method, $new_key, OPENSSL_RAW_DATA, $new_iv);
                $new_payload    = $new_iv . $new_cipher;
                file_put_contents($path, $new_payload, LOCK_EX);

                // Re-encrypt the stored filename with its own new IV
                $name_iv_hex_len   = $iv_length * 2;
                $old_name_iv       = hex2bin(substr($file_row['original_name'], 0, $name_iv_hex_len));
                $old_enc_name_b64  = hex2bin(substr($file_row['original_name'], $name_iv_hex_len));
                $plain_name        = openssl_decrypt($old_enc_name_b64, $cipher_method, $old_key, 0, $old_name_iv);
                if ($plain_name === false) $plain_name = 'unknown_file';

                $new_name_iv   = random_bytes($iv_length);
                $new_enc_name  = bin2hex($new_name_iv) . bin2hex(openssl_encrypt($plain_name, $cipher_method, $new_key, 0, $new_name_iv));

                $upd_stmt = $conn->prepare("UPDATE file_registry SET original_name = ? WHERE id = ?");
                $upd_stmt->bind_param("si", $new_enc_name, $file_row['id']);
                $upd_stmt->execute();
                $upd_stmt->close();
            }
            $file_stmt->close();

            // Re-encrypt avatar blob if present
            if (!$reencrypt_failed) {
                $av_stmt = $conn->prepare("SELECT avatar_blob, avatar_mime FROM users WHERE id = ?");
                $av_stmt->bind_param("i", $user_id);
                $av_stmt->execute();
                $av_row = $av_stmt->get_result()->fetch_assoc();
                $av_stmt->close();

                if (!empty($av_row['avatar_blob'])) {
                    $av_raw     = $av_row['avatar_blob'];
                    $av_old_iv  = substr($av_raw, 0, $iv_length);
                    $av_old_enc = substr($av_raw, $iv_length);
                    $av_plain   = openssl_decrypt($av_old_enc, $cipher_method, $old_key, OPENSSL_RAW_DATA, $av_old_iv);

                    if ($av_plain !== false) {
                        $av_new_iv      = random_bytes($iv_length);
                        $av_new_enc     = openssl_encrypt($av_plain, $cipher_method, $new_key, OPENSSL_RAW_DATA, $av_new_iv);
                        $av_new_payload = $av_new_iv . $av_new_enc;

                        $av_upd = $conn->prepare("UPDATE users SET avatar_blob = ? WHERE id = ?");
                        $av_upd->bind_param("si", $av_new_payload, $user_id);
                        $av_upd->execute();
                        $av_upd->close();
                    }
                }
            }

            if ($reencrypt_failed) {
                $error_message = "❌ Re-encryption failed on one or more files. Password was not changed.";
            } else {
                // Commit the new password hash and salt atomically
                $upd_auth = $conn->prepare("UPDATE users SET password_hash = ?, enc_salt = ? WHERE id = ?");
                $upd_auth->bind_param("ssi", $new_hash, $new_salt, $user_id);

                if ($upd_auth->execute()) {
                    // Refresh session key so the current session stays valid immediately
                    $_SESSION['encryption_key'] = bin2hex($new_key);
                    write_security_log($username, "PASSWORD_CHANGED", "Password changed and all stored data re-encrypted under new key.");
                    $message = "✅ Password updated and all files re-encrypted successfully.";
                } else {
                    $error_message = "❌ Database error saving new credentials.";
                }
                $upd_auth->close();
            }
        }
    }

    // 2. HANDLE ENCRYPTED BLOB AVATAR UPDATE
    if (isset($_POST['update_avatar']) && isset($_FILES['avatar_img'])) {
        $file = $_FILES['avatar_img'];
        
        if ($file['error'] === UPLOAD_ERR_OK) {
            // Validate file extension
            $file_ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
            $allowed_extensions = ['jpg', 'jpeg', 'png'];
            
            if (!in_array($file_ext, $allowed_extensions)) {
                write_security_log($username, "AVATAR_REJECTED", "Banned extension: $file_ext");
                $error_message = "❌ Unsafe file type. Only JPG and PNG are allowed.";
            } 
            // Validate file size limit (5MB)
            elseif ($file['size'] > 5 * 1024 * 1024) {
                $error_message = "❌ Avatar file size must be under 5 MB.";
            } 
            else {
                // Secure validation of actual file structure using finfo
                $finfo = new finfo(FILEINFO_MIME_TYPE);
                $mime_type = $finfo->file($file['tmp_name']);
                $allowed_mimes = ['image/jpeg', 'image/png'];
                
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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profile — CloudSim</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Google+Sans:wght@400;500;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="styles/main.css">
    <link rel="stylesheet" href="styles/dashboard.css">
    <link rel="stylesheet" href="styles/profile.css">
</head>
<body>

<!-- ── TOPBAR ── -->
<header class="topbar">
    <a href="upload.php" class="topbar-brand">
        <div class="topbar-brand-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M3 15a4 4 0 004 4h10a4 4 0 001-7.9A5 5 0 1015.9 6L15 6a5 5 0 00-5 5l-1 .1A4 4 0 003 15z"/>
            </svg>
        </div>
        <span class="topbar-brand-name">Cloud<span>Sim</span></span>
    </a>

    <div class="topbar-spacer"></div>

    <div class="topbar-actions">
        <?php if (isset($_SESSION['role']) && $_SESSION['role'] === 'admin'): ?>
        <a href="admin_dashboard.php" class="topbar-icon-btn" title="Admin Panel">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
        </a>
        <?php endif; ?>
        <div class="topbar-user-chip">
            <img src="<?= $avatar_src ?>" alt="Avatar">
            <?= htmlspecialchars($username) ?>
        </div>
        <a href="logout.php" class="topbar-icon-btn" title="Sign out">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9"/>
            </svg>
        </a>
    </div>
</header>

<!-- ── LAYOUT ── -->
<div class="layout">

    <!-- ── SIDEBAR ── -->
    <aside class="sidebar">
        <a href="upload.php" class="sidebar-item">
            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M3 15a4 4 0 004 4h10a4 4 0 001-7.9A5 5 0 1015.9 6L15 6a5 5 0 00-5 5l-1 .1A4 4 0 003 15z"/>
            </svg>
            My Drive
        </a>
        <a href="profile.php" class="sidebar-item active">
            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/>
            </svg>
            Profile
        </a>
        <?php if (isset($_SESSION['role']) && $_SESSION['role'] === 'admin'): ?>
        <a href="admin_dashboard.php" class="sidebar-item">
            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            Admin Panel
        </a>
        <?php endif; ?>
        <div class="sidebar-divider"></div>
        
    </aside>

    <!-- ── MAIN ── -->
    <main class="main">

        <div class="page-header">
            <h1 class="page-title">Profile &amp; Settings</h1>
            <p class="page-sub">Manage your account details, avatar, and security credentials.</p>
        </div>

        <?php if (!empty($message)): ?>
        <div class="alert alert-success">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
            <?= htmlspecialchars($message) ?>
        </div>
        <?php endif; ?>

        <?php if (!empty($error_message)): ?>
        <div class="alert alert-danger">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            <?= htmlspecialchars($error_message) ?>
        </div>
        <?php endif; ?>

        <!-- ── PROFILE OVERVIEW ── -->
        <div class="section-card">
            <div class="section-card-header">
                <div class="section-card-title">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                    Profile Photo
                </div>
            </div>
            <div class="section-card-body">
                <div class="avatar-row">
                    <div class="avatar-wrap">
                        <img src="<?= $avatar_src ?>" alt="Profile avatar" class="avatar-img" id="avatarPreview">
                        <label for="avatar_input" class="avatar-edit-badge" title="Change photo">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 013 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
                        </label>
                    </div>
                    <div class="avatar-meta">
                        <h3><?= htmlspecialchars($username) ?></h3>
                        <p>Secure cloud account</p>
                        <span class="role-badge <?= isset($_SESSION['role']) && $_SESSION['role'] === 'admin' ? 'role-badge-admin' : 'role-badge-user' ?>">
                            <?= htmlspecialchars($_SESSION['role'] ?? 'user') ?>
                        </span>
                    </div>
                </div>

                <form action="profile.php" method="POST" enctype="multipart/form-data" id="avatarForm">
                    <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                    <label for="avatar_input" class="file-input-wrap" id="avatarDropLabel">
                        <input type="file" name="avatar_img" id="avatar_input" accept=".jpg,.jpeg,.png">
                        <span class="file-input-icon">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>
                        </span>
                        <div class="file-input-text">
                            <strong>Choose a photo</strong> or drag it here &nbsp;·&nbsp; JPG, PNG up to 5 MB
                        </div>
                    </label>
                    <div class="file-selected-chip" id="avatarChip">
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>
                        <span id="avatarChipName"></span>
                    </div>
                    <div class="form-actions" style="margin-top: 16px;">
                        <button type="submit" name="update_avatar" class="btn btn-primary" id="avatarSaveBtn" disabled>
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
                            Save Photo
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <!-- ── CHANGE PASSWORD ── -->
        <div class="section-card">
            <div class="section-card-header">
                <div class="section-card-title">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
                    Change Password
                </div>
            </div>
            <div class="section-card-body">
                <div class="enc-note">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                    All your files will be automatically re-encrypted with a new key derived from your new password. This may take a moment.
                </div>
                <form action="profile.php" method="POST" id="passwordForm">
                    <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                    <div class="form-group">
                        <label class="form-label" for="new_password">New Password</label>
                        <input type="password" class="form-input" name="new_password" id="new_password" required autocomplete="new-password" placeholder="Enter new password">
                    </div>
                    <div class="form-group">
                        <label class="form-label" for="confirm_password">Confirm Password</label>
                        <input type="password" class="form-input" name="confirm_password" id="confirm_password" required autocomplete="new-password" placeholder="Re-enter new password">
                        <div class="form-hint" id="matchHint"></div>
                    </div>
                    <div class="form-actions">
                        <button type="reset" class="btn btn-ghost">Cancel</button>
                        <button type="submit" name="update_password" class="btn btn-primary" id="passwordSaveBtn">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                            Update Password
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <!-- ── DANGER ZONE ── -->
        <div class="danger-card">
            <div class="danger-card-header">
                <div class="danger-card-title">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                    Danger Zone
                </div>
                <div class="danger-card-sub">Irreversible and destructive actions</div>
            </div>
            <div class="danger-card-body">
                <div class="danger-card-desc">
                    <strong>Delete this account</strong><br>
                    Permanently removes your account, all stored files, and encrypted data. This cannot be undone.
                </div>
                <a href="delete_profile.php" class="btn btn-danger-outline" style="flex-shrink:0;">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6M14 11v6"/></svg>
                    Delete Account
                </a>
            </div>
        </div>

        <div class="page-footer">
            <div class="footer">This website is made by Bagranov Gleb for the project of Messina University</div>
        </div>

    </main>
</div>

<script src="js/profile.js"></script>

</body>
</html>