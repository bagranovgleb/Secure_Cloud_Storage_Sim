<?php
require_once 'config.php';

// 1. Authentication check
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

// 2. Must be a POST request — GET cannot trigger destructive actions
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header("Location: upload.php");
    exit;
}

// 3. CSRF verification
verify_csrf_token();

$user_id = $_SESSION['user_id'];
$file_id = intval($_POST['file_id'] ?? 0);

if ($file_id > 0) {
    // 4. Authorization check: only fetch the file if it belongs to this user
    $stmt = $conn->prepare("SELECT stored_name FROM file_registry WHERE id = ? AND owner_id = ?");
    $stmt->bind_param("ii", $file_id, $user_id);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($file_info = $result->fetch_assoc()) {
        $stored_name = $file_info['stored_name'];
        $physical_file_path = __DIR__ . '/storage/' . $stored_name;

        // 5. Remove DB record first, then clean up disk
        $delete_stmt = $conn->prepare("DELETE FROM file_registry WHERE id = ? AND owner_id = ?");
        $delete_stmt->bind_param("ii", $file_id, $user_id);

        if ($delete_stmt->execute()) {
            if (file_exists($physical_file_path)) {
                unlink($physical_file_path);
                header("Location: upload.php?msg=deleted");
                exit;
            } else {
                header("Location: upload.php?msg=db_only_deleted");
                exit;
            }
        }
        $delete_stmt->close();
    } else {
        header("HTTP/1.0 403 Forbidden");
        die("Access Denied: Unauthorized deletion request.");
    }
    $stmt->close();
} else {
    header("Location: upload.php");
    exit;
}
$conn->close();
?>