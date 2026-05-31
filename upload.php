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

// --- DYNAMICALLY DECRYPT ACTIVE AVATAR FROM BLOB STORAGE ---
$avatar_src = "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='40' height='40' viewBox='0 0 100 100'><circle cx='50' cy='50' r='50' fill='%23ccc'/><text x='50%' y='55%' font-size='40' text-anchor='middle' dominant-baseline='middle'>👤</text></svg>"; // Vector fallback icon

$stmt = $conn->prepare("SELECT avatar_blob, avatar_mime FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$avatar_result = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!empty($avatar_result['avatar_blob']) && !empty($avatar_result['avatar_mime'])) {
    $db_payload = $avatar_result['avatar_blob'];
    $mime_type = $avatar_result['avatar_mime'];
    
    $cipher_method = "aes-256-ctr";
    $iv_length = openssl_cipher_iv_length($cipher_method);
    
    $extracted_iv = substr($db_payload, 0, $iv_length);
    $encrypted_data = substr($db_payload, $iv_length);
    $encryption_key = hex2bin($_SESSION['encryption_key']);
    
    $decrypted_binary = openssl_decrypt($encrypted_data, $cipher_method, $encryption_key, OPENSSL_RAW_DATA, $extracted_iv);
    
    if ($decrypted_binary !== false) {
        $avatar_src = "data:" . htmlspecialchars($mime_type) . ";base64," . base64_encode($decrypted_binary);
    }
}

// --- FILE UPLOAD PROCESSING ENGINE ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['cloud_file'])) {
    verify_csrf_token();
    $file = $_FILES['cloud_file'];
    
    if ($file['error'] === UPLOAD_ERR_OK) {
        $original_name = basename($file['name']);
        $file_size = $file['size'];
        $file_ext = strtolower(pathinfo($original_name, PATHINFO_EXTENSION));

        // 1. BANNED EXTENSION GATE — block server-executable file types
        $banned_extensions = ['php', 'phtml', 'phar', 'exe', 'bat', 'sh', 'cmd', 'py', 'rb', 'pl'];
        if (in_array($file_ext, $banned_extensions) || empty($file_ext)) {
            write_security_log($username, "UPLOAD_REJECTED", "Banned extension blocked: '.$file_ext'.");
            $error_message = "❌ File type not permitted.";
        }
        // 2. REAL MIME TYPE CHECK via finfo — never trust browser-supplied $file['type']
        else {
            $finfo = new finfo(FILEINFO_MIME_TYPE);
            $real_mime = $finfo->file($file['tmp_name']);

            // 3. 5GB CUMULATIVE QUOTA ENFORCEMENT
            $max_total_quota = 5 * 1024 * 1024 * 1024;
            $quota_stmt = $conn->prepare("SELECT SUM(file_size) AS total_used FROM file_registry WHERE owner_id = ?");
            $quota_stmt->bind_param("i", $user_id);
            $quota_stmt->execute();
            $quota_row = $quota_stmt->get_result()->fetch_assoc();
            $quota_stmt->close();
            $current_used = $quota_row['total_used'] ?? 0;

            if (($current_used + $file_size) > $max_total_quota) {
                $available_mb = round(($max_total_quota - $current_used) / (1024 * 1024), 2);
                write_security_log($username, "QUOTA_EXCEEDED", "Upload blocked — would exceed 5GB quota.");
                $error_message = "❌ Storage quota exceeded. Only {$available_mb} MB remaining.";
            }
            // 4. PER-FILE 20MB CAP
            elseif ($file_size > 20 * 1024 * 1024) {
                $error_message = "❌ File size exceeds the 20MB per-file limit.";
            }
            else {
                // Read raw binary contents for symmetric encryption
                $plaintext_content = file_get_contents($file['tmp_name']);

                $cipher_method = "aes-256-ctr";
                $iv_length = openssl_cipher_iv_length($cipher_method);
                $iv = random_bytes($iv_length);
                $encryption_key = hex2bin($_SESSION['encryption_key']);

                $encrypted_content = openssl_encrypt($plaintext_content, $cipher_method, $encryption_key, OPENSSL_RAW_DATA, $iv);
                $final_payload = $iv . $encrypted_content;

                $stored_name = bin2hex(random_bytes(16)) . ".dat";
                $target_path = __DIR__ . "/storage/" . $stored_name;

                if (!is_dir(__DIR__ . "/storage/")) {
                    mkdir(__DIR__ . "/storage/", 0755, true);
                }

                if (file_put_contents($target_path, $final_payload)) {
                    // Filename gets its own IV — never reuse the file-content IV
                    $name_iv = random_bytes($iv_length);
                    $encrypted_name = bin2hex($name_iv) . bin2hex(openssl_encrypt($original_name, $cipher_method, $encryption_key, 0, $name_iv));

                    // Store $real_mime (from finfo) — never the browser-supplied $file['type']
                    $stmt = $conn->prepare("INSERT INTO file_registry (owner_id, original_name, stored_name, file_type, file_size) VALUES (?, ?, ?, ?, ?)");
                    $stmt->bind_param("issss", $user_id, $encrypted_name, $stored_name, $real_mime, $file_size);

                    if ($stmt->execute()) {
                        write_security_log($username, "FILE_UPLOAD_SUCCESS", "Encrypted file registered: $stored_name");
                        $message = "✅ File encrypted and uploaded successfully.";
                    } else {
                        $error_message = "❌ Failed to log entry inside database registry.";
                        unlink($target_path);
                    }
                    $stmt->close();
                } else {
                    $error_message = "❌ Write error saving file asset to disk storage block.";
                }
            }
        }
    } else {
        $error_message = "❌ Standard upload handling error detected.";
    }
}

// Fetch active user files from registry
$files_list = [];
$stmt = $conn->prepare("SELECT id, original_name, file_size, uploaded_at FROM file_registry WHERE owner_id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$res = $stmt->get_result();
while ($row = $res->fetch_assoc()) {
    $files_list[] = $row;
}
$stmt->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Core Cloud Simulation Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f8f9fa; color: #333; }
        .container { max-width: 700px; margin: 0 auto; }
        .card { background: white; padding: 25px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .form-group { margin-bottom: 15px; }
        button { background: #007bff; color: white; border: none; padding: 10px 15px; border-radius: 4px; cursor: pointer; font-weight: bold; }
        button:hover { background: #0056b3; }
        .alert { padding: 10px; margin-bottom: 15px; border-radius: 4px; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-danger { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background-color: #f1f1f1; }
        .nav-links { display: flex; justify-content: space-between; align-items: center; margin-top: 20px; }
        .nav-links a { text-decoration: none; font-weight: bold; color: #007bff; }
        .nav-links a:hover { text-decoration: underline; }
    </style>
</head>
<body>

<div class="container">

    <div style="display: flex; align-items: center; justify-content: space-between; background: #fff; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); margin-bottom: 20px;">
        <div style="display: flex; align-items: center; gap: 15px;">
            <img src="<?= $avatar_src ?>" alt="User Profile Image" style="width: 45px; height: 45px; border-radius: 50%; object-fit: cover; border: 2px solid #007bff;">
            <div>
                <h3 style="margin: 0; font-size: 18px;">Welcome back, <?= htmlspecialchars($username) ?>!</h3>
                <span style="font-size: 12px; color: #666;">Secure Storage Environment Active</span>
            </div>
        </div>
        <div>
            <a href="profile.php" style="background: #007bff; color: white; text-decoration: none; padding: 8px 12px; border-radius: 4px; font-size: 14px; font-weight: bold;">⚙️ Manage Profile</a>
        </div>
    </div>

    <?php if (!empty($message)): ?>
        <div class="alert alert-success"><?= $message ?></div>
    <?php endif; ?>
    <?php if (!empty($error_message)): ?>
        <div class="alert alert-danger"><?= $error_message ?></div>
    <?php endif; ?>

    <div class="card">
        <h3>Upload File Asset to Encrypted Partition</h3>
        <form action="upload.php" method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
            <div class="form-group">
                <input type="file" name="cloud_file" required>
            </div>
            <button type="submit">Encrypt & Upload</button>
        </form>
    </div>

    <div class="card">
        <h3>Your Encrypted Cloud Files Storage Registry</h3>
        <?php if (empty($files_list)): ?>
            <p style="color: #666;">No secure file records found in your directory footprint.</p>
        <?php else: ?>
            <table>
                <thead>
                    <tr>
                        <th>File ID</th>
                        <th>Encrypted System Tag</th>
                        <th>Size</th>
                        <th>Timestamp</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($files_list as $f): ?>
                        <tr>
                            <td><?= intval($f['id']) ?></td>
                            <td style="font-family: monospace; font-size: 11px; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                                <?= htmlspecialchars($f['original_name']) ?>
                            </td>
                            <td><?= number_format($f['file_size']) ?></td>
                            <td><?= htmlspecialchars($f['uploaded_at']) ?></td>
                            <td style="white-space: nowrap;">
                                <a href="download.php?file_id=<?= intval($f['id']) ?>" style="color: #007bff; margin-right: 10px;">Download</a>
                                <form action="delete.php" method="POST" style="display:inline;" onsubmit="return confirm('Delete this file? This cannot be undone.');">
                                    <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                                    <input type="hidden" name="file_id" value="<?= intval($f['id']) ?>">
                                    <button type="submit" style="background:none; border:none; color:#dc3545; cursor:pointer; padding:0; font-size:14px;">Delete</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

    <div class="nav-links">
        <a href="profile.php">⚙️ Personal Space Settings</a>
        <a href="delete_profile.php" style="color: #dc3545;">⚠️ Delete Account</a>
        <a href="logout.php" style="color: #6c757d;">Disconnect Session</a>
    </div>

</div>

</body>
</html>