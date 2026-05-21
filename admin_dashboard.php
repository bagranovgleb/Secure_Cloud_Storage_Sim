<?php
require_once 'config.php';




// 2. STEALTH PROTECTION GATEWAY
if (!isset($_SESSION['user_id']) || !isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
    $offending_user = $_SESSION['username'] ?? 'UNAUTHENTICATED';
    write_security_log($offending_user, "STEALTH_INTERCEPTION", "Admin panel requested. Server responded with a fake 404 Not Found.");
    header("HTTP/1.1 404 Not Found");
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8"><title>404 Not Found</title>
        <style>body { font-family: Arial, sans-serif; background-color: #f8f9fa; color: #343a40; text-align: center; padding: 50px; } h1 { font-size: 50px; } p { font-size: 18px; color: #6c757d; }</style>
    </head>
    <body><h1>404 Not Found</h1><p>The requested URL was not found on this server.</p></body>
    </html>
    <?php
    exit;
}

$username = $_SESSION['username'];
$current_admin_id = $_SESSION['user_id'];

// 3. CASCADING DELETION ENGINE (Processes User + Disk Files)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete_user') {
    $target_user_id = intval($_POST['target_user_id'] ?? 0);

    // Prevent Self-Deletion Disaster
    if ($target_user_id === $current_admin_id) {
        header("Location: admin_dashboard.php?status=self_deletion_blocked");
        exit;
    }

    if ($target_user_id > 0 && isset($conn) && $conn instanceof mysqli) {
        // Fetch the target user's username for accurate audit trail logging
        $user_stmt = $conn->prepare("SELECT username FROM users WHERE id = ?");
        $user_stmt->bind_param("i", $target_user_id);
        $user_stmt->execute();
        $user_res = $user_stmt->get_result()->fetch_assoc();
        $target_username = $user_res['username'] ?? 'UNKNOWN_USER';
        $user_stmt->close();

        // Phase A: Locate and unlink physical encrypted files from target storage
        $file_stmt = $conn->prepare("SELECT stored_name FROM file_registry WHERE owner_id = ?");
        $file_stmt->bind_param("i", $target_user_id);
        $file_stmt->execute();
        
        // FIXED: Call get_result exactly once and store it inside the active array context variable
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

        // Phase B: Delete file database records mapping to this owner
        $del_files_stmt = $conn->prepare("DELETE FROM file_registry WHERE owner_id = ?");
        $del_files_stmt->bind_param("i", $target_user_id);
        $del_files_stmt->execute();
        $del_files_stmt->close();

        // Phase C: Delete the actual user identity profile row
        $del_user_stmt = $conn->prepare("DELETE FROM users WHERE id = ?");
        $del_user_stmt->bind_param("i", $target_user_id);
        $del_user_stmt->execute();
        $del_user_stmt->close();

        // Log the complete cleanup operation in the secure audit trailing infrastructure
        write_security_log($username, "USER_PURGED", "Permanently deleted user '$target_username' (ID: $target_user_id) and unlinked $deleted_file_count associated files from disk storage.");
        
        header("Location: admin_dashboard.php?status=purge_success");
        exit;
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Cloud Sim - Admin Panel</title>
    <style>
        body { font-family: sans-serif; margin: 30px; }
        .log-box { background: #222; color: #00ff00; padding: 15px; font-family: monospace; height: 150px; overflow-y: scroll; border-radius: 5px; white-space: pre-wrap; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background-color: #f2f2f2; }
        .btn-danger { background-color: #dc3545; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer; }
        .btn-danger:hover { background-color: #bd2130; }
        .alert { padding: 10px; border-radius: 4px; margin-bottom: 15px; }
        .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
    </style>
</head>
<body>
    <h2>🛡️ Secure Cloud-Edge Administrative Space</h2>
    <p>Logged in as administrator: <strong><?php echo htmlspecialchars($username); ?></strong></p>
    <hr>

    <?php
    // User Action Status Banners
    if (isset($_GET['status'])) {
        if ($_GET['status'] === 'purge_success') {
            echo "<div class='alert success'>✅ User and all of their encrypted cloud storage contents were purged successfully.</div>";
        } elseif ($_GET['status'] === 'self_deletion_blocked') {
            echo "<div class='alert error'>⚠️ Security Violation: You cannot delete your own active administrative account.</div>";
        }
    }
    ?>

    <h3>📊 Live Security Audit Logs</h3>
    <div class="log-box"><?php
        $log_directory = dirname(__DIR__, 2) . '/secure_logs/';
        $log_file = $log_directory . 'security_audit.log';
        
        if (file_exists($log_file) && is_readable($log_file)) {
            $log_lines = file($log_file);
            if (!empty($log_lines)) {
                $recent_logs = array_slice($log_lines, -30);
                foreach (array_reverse($recent_logs) as $line) {
                    echo htmlspecialchars($line);
                }
            } else { echo "The log file is currently empty."; }
        } else { echo "⚠️ Log connection offline."; }
    ?></div>

    <h3>👥 System Infrastructure Inventory (Users & Nodes)</h3>
    <table>
        <tr>
            <th>ID</th>
            <th>Identity/Node Name</th>
            <th>Assigned Security Role</th>
            <th>Registration Date</th>
            <th>Actions</th>
        </tr>
        <?php
        if (isset($conn) && $conn instanceof mysqli) {
            $result = $conn->query("SELECT id, username, role, created_at FROM users");
            if ($result) {
                while ($row = $result->fetch_assoc()) {
                    echo "<tr>";
                    echo "<td>" . intval($row['id']) . "</td>";
                    echo "<td>" . htmlspecialchars($row['username']) . "</td>";
                    echo "<td><strong>" . htmlspecialchars($row['role']) . "</strong></td>";
                    echo "<td>" . htmlspecialchars($row['created_at']) . "</td>";
                    echo "<td>";
                    if ($row['id'] !== $current_admin_id) {
                        ?>
                        <form action="admin_dashboard.php" method="POST" onsubmit="return confirm('🚨 CRITICAL WARNING: This will permanently delete this user and all of their encrypted data files from disk storage. This cannot be undone. Proceed?');" style="margin:0;">
                            <input type="hidden" name="action" value="delete_user">
                            <input type="hidden" name="target_user_id" value="<?php echo $row['id']; ?>">
                            <button type="submit" class="btn-danger">Purge Account</button>
                        </form>
                        <?php
                    } else {
                        echo "<span style='color: #6c757d; font-style: italic;'>Active Session Admin</span>";
                    }
                    echo "</td>";
                    echo "</tr>";
                }
                $result->free();
            } else { echo "<tr><td colspan='5'>⚠️ Error querying user data tables.</td></tr>"; }
        } else { echo "<tr><td colspan='5'>⚠️ Database driver context missing.</td></tr>"; }
        ?>
    </table>

    <br><hr>
    <p><a href="upload.php">Go to regular File Storage Dashboard</a> | <a href="logout.php">Securely Log Out</a></p>
</body>
</html>