<?php
require_once 'config.php';

if (!isset($_SESSION['user_id']) || !isset($_SESSION['encryption_key'])) {
    if (isset($_SESSION['username'])) {
        write_security_log($_SESSION['username'], "SESSION_EXPIRED", "Cryptographic session key was missing. Forcing logout.");
    }
    $_SESSION = array();
    session_destroy();
    header("Location: login.php");
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['cloud_file'])) {
    $file = $_FILES['cloud_file'];
    $username = $_SESSION['username'];
    $owner_id = $_SESSION['user_id'];
    
    $original_name = basename($file['name']);
    $file_type = $file['type'];
    $file_size = $file['size']; // Size of the file currently being uploaded
    $file_ext = strtolower(pathinfo($original_name, PATHINFO_EXTENSION));

    // 1. CHOOSE PRIVILEGED QUOTA CAPS (5 GB Total Limit in Bytes)
    $max_total_quota = 5 * 1024 * 1024 * 1024; 
    $banned_extensions = ['php', 'phtml', 'exe', 'bat', 'sh', 'cmd'];

    if (in_array($file_ext, $banned_extensions) || empty($file_ext)) {
        write_security_log($username, "UPLOAD_REJECTED", "Banned extension attack detected: '.$file_ext'.");
        die("❌ Error: Unsupported or unsafe file extension.");
    }

    // 2. CALCULATE EXISTING ACCUMULATED STORAGE CONSUMPTION
    $quota_stmt = $conn->prepare("SELECT SUM(file_size) as total_used FROM file_registry WHERE owner_id = ?");
    $quota_stmt->bind_param("i", $owner_id);
    $quota_stmt->execute();
    $quota_result = $quota_stmt->get_result()->fetch_assoc();
    $quota_stmt->close();

    $current_total_used = $quota_result['total_used'] ?? 0;
    
    // Check if adding this file exceeds the 5 GB cumulative limit
    if (($current_total_used + $file_size) > $max_total_quota) {
        $available_space = $max_total_quota - $current_total_used;
        $available_mb = round($available_space / (1024 * 1024), 2);
        
        write_security_log($username, "QUOTA_EXCEEDED", "Upload blocked. Total usage would exceed 5GB quota limit.");
        die("❌ Error: Storage quota exceeded. You only have " . $available_mb . " MB of space remaining.");
    }

    // 3. CRYPTOGRAPHIC ENCRYPTION LAYER (AES-256-CTR)
    $plaintext_content = file_get_contents($file['tmp_name']);
    $cipher_method = "aes-256-ctr";
    
    $iv_length = openssl_cipher_iv_length($cipher_method);
    $file_iv = random_bytes($iv_length);
    $encryption_key = hex2bin($_SESSION['encryption_key']);
    
    $encrypted_content = openssl_encrypt($plaintext_content, $cipher_method, $encryption_key, OPENSSL_RAW_DATA, $file_iv);
    $final_disk_payload = $file_iv . $encrypted_content;

    $stored_name = bin2hex(random_bytes(16)) . '.dat';
    $target_path = __DIR__ . '/storage/' . $stored_name;

    if (file_put_contents($target_path, $final_disk_payload, LOCK_EX) !== false) {
        // SAVING CLOUD ATTRIBUTES: Note that we are now logging the $file_size integer directly into the database row
        $stmt = $conn->prepare("INSERT INTO file_registry (owner_id, original_name, stored_name, file_type, file_size) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("isssi", $owner_id, $original_name, $stored_name, $file_type, $file_size);
        
        if ($stmt->execute()) {
            write_security_log($username, "UPLOAD_SUCCESS", "Stored encrypted file '$original_name'. Current total allocation usage: " . ($current_total_used + $file_size) . " bytes.");
            echo "✅ File securely uploaded and encrypted.";
        } else {
            echo "Database error mapping file size metrics.";
        }
        $stmt->close();
    } else {
        echo "Failed to save data directly onto storage disc partitions.";
    }
}
?>

<!-- Interface UI -->
<form action="upload.php" method="POST" enctype="multipart/form-data">
    <h3>Simulate Secure Cloud Storage</h3>
    <?php
    if (isset($_SESSION['role']) && $_SESSION['role'] === 'admin') {
        echo "<p style='background: #fff3cd; padding: 10px; border: 1px solid #ffeeba; color: #856404; border-radius: 4px;'>🛡️ <strong>Admin Notice:</strong> You have access to the <a href='admin_dashboard.php'>Administrative Space</a>.</p>";
    }
    ?>
    <label>Select File (Your collective limit is 5 GB total storage):</label><br><br>
    <input type="file" name="cloud_file" required><br><br>
    <button type="submit">Upload File</button>
</form>

<?php
// Render Dashboard View
if (isset($_SESSION['user_id'])) {
    echo "<h3>Your Secure Cloud Files:</h3>";
    
    $user_id = $_SESSION['user_id'];
    $list_stmt = $conn->prepare("SELECT id, original_name, file_size FROM file_registry WHERE owner_id = ?");
    $list_stmt->bind_param("i", $user_id);
    $list_stmt->execute();
    $result = $list_stmt->get_result();

    if ($result->num_rows > 0) {
        echo "<table border='1' cellpadding='8' style='border-collapse: collapse; width: 500px;'><tr><th>File Name</th><th>Size</th><th>Action</th></tr>";
        while ($file = $result->fetch_assoc()) {
            $display_size = round($file['file_size'] / 1024, 2) . " KB";
            if ($file['file_size'] > 1024 * 1024) {
                $display_size = round($file['file_size'] / (1024 * 1024), 2) . " MB";
            }
            echo "<tr>";
            echo "<td><a href='download.php?file_id=" . $file['id'] . "'>" . htmlspecialchars($file['original_name']) . "</a></td>";
            echo "<td>" . $display_size . "</td>";
            echo "<td><a href='delete.php?file_id=" . $file['id'] . "' style='color:red;'>Delete</a></td>";
            echo "</tr>";
        }
        echo "</table>";
    } else {
        echo "<p>No files uploaded yet.</p>";
    }
    $list_stmt->close();
    echo "<br><hr>";
    echo "<div style='display: flex; justify-content: space-between; align-items: center; max-width: 500px;'>";
    echo "  <a href='logout.php'>Disconnect Session</a>";
    echo "  <a href='delete_profile.php' style='color: #dc3545; text-decoration: none; font-size: 14px;'>⚠️ Close/Purge My Account</a>";
    echo "</div>";
}
?>