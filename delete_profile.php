<?php
require_once 'config.php';

// 1. IDENTITY ENFORCEMENT CHECKPOINT
if (!isset($_SESSION['user_id']) || !isset($_SESSION['username'])) {
    header("Location: login.php");
    exit;
}

// Extract variables strictly from the server-side session (Defeats IDOR/Parameter Tampering)
$user_id = intval($_SESSION['user_id']);
$username = $_SESSION['username'];

// Prevent administrative accidents via this specific frontend endpoint
if (isset($_SESSION['role']) && $_SESSION['role'] === 'admin') {
    die("❌ Safety Block: System Administrators must use the main Infrastructure Panel to delete administrative accounts.");
}

// Process the deletion request only if the form was formally submitted via POST
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['confirm_purge']) && $_POST['confirm_purge'] === 'YES') {
    
    if (isset($conn) && $conn instanceof mysqli) {
        
        // PHASE A: Locate and physically delete all files from the storage folder
        $file_stmt = $conn->prepare("SELECT stored_name FROM file_registry WHERE owner_id = ?");
        $file_stmt->bind_param("i", $user_id);
        $file_stmt->execute();
        $file_res = $file_stmt->get_result();
        
        $deleted_file_count = 0;
        while ($file_row = $file_res->fetch_assoc()) {
            $physical_path = __DIR__ . '/storage/' . $file_row['stored_name'];
            if (file_exists($physical_path)) {
                if (unlink($physical_path)) {
                    $deleted_file_count++;
                }
            }
        }
        $file_stmt->close();

        // PHASE B: Purge file records from the database
        $del_files_stmt = $conn->prepare("DELETE FROM file_registry WHERE owner_id = ?");
        $del_files_stmt->bind_param("i", $user_id);
        $del_files_stmt->execute();
        $del_files_stmt->close();

        // PHASE C: Purge the actual user identity row
        $del_user_stmt = $conn->prepare("DELETE FROM users WHERE id = ?");
        $del_user_stmt->bind_param("i", $user_id);
        $del_user_stmt->execute();
        $del_user_stmt->close();

        // 2. SECURE AUDIT TRAIL RECORDING
        write_security_log($username, "USER_SELF_PURGE", "User requested account closure. Erased identity database profile and completely unlinked $deleted_file_count files from the host disk filesystem.");

        // 3. SECURE SESSION TEARDOWN (Shreds server-side memory & expires client tracking cookie)
        $_SESSION = array();
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }
        session_destroy();

        // Send the user away with a status tracking parameter
        header("Location: login.php?status=account_deleted");
        exit;
    } else {
        die("❌ Core Database Engine Link is currently offline.");
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Cloud Sim - Close Account</title>
    <style>
        body { font-family: sans-serif; background-color: #f8f9fa; color: #333; margin: 50px; text-align: center; }
        .danger-zone { max-width: 500px; margin: 0 auto; background: white; padding: 30px; border: 1px solid #dc3545; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        h2 { color: #dc3545; margin-top: 0; }
        p { line-height: 1.5; color: #666; }
        .btn-cancel { background: #6c757d; color: white; text-decoration: none; padding: 10px 20px; border-radius: 4px; display: inline-block; margin-right: 10px; }
        .btn-danger { background: #dc3545; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-size: 16px; }
        .btn-danger:hover { background: #bd2130; }
    </style>
</head>
<body>

<div class="danger-zone">
    <h2>🚨 Danger Zone: Account Closure</h2>
    <p>Hello <strong><?php echo htmlspecialchars($username); ?></strong>. You are about to permanently delete your cloud account.</p>
    <p><strong>This action is absolute and irreversible.</strong> Proceeding will instantly drop your access token and completely erase all encrypted files currently stored inside your allocation quota space.</p>
    <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">
    
    <!-- Double-Layer Confirmation: JavaScript popup gate + server POST validation -->
    <form action="delete_profile.php" method="POST" onsubmit="return confirm('Final verification check: Are you absolutely certain you want to purge your cloud file environment? This action cannot be reverted.');">
        <input type="hidden" name="confirm_purge" value="YES">
        <a href="upload.php" class="btn-cancel">Cancel and Go Back</a>
        <button type="submit" class="btn-danger">Permanently Delete My Account</button>
    </form>
</div>

</body>
</html>