<?php
require_once 'config.php';

// 1. Enforce Authentication Check
if (!isset($_SESSION['user_id'])) {
    die("Access Denied: Unauthenticated.");
}

$user_id = $_SESSION['user_id'];
$file_id = $_GET['file_id'] ?? 0;

if ($file_id > 0) {
    // 2. Authorization Check: Find the file details ONLY if it belongs to the logged-in user
    $stmt = $conn->prepare("SELECT stored_name FROM file_registry WHERE id = ? AND owner_id = ?");
    $stmt->bind_param("ii", $file_id, $user_id);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($file_info = $result->fetch_assoc()) {
        $stored_name = $file_info['stored_name'];
        $physical_file_path = __DIR__ . '/storage/' . $stored_name;

        // 3. Database Deletion: Remove the registry row first
        $delete_stmt = $conn->prepare("DELETE FROM file_registry WHERE id = ? AND owner_id = ?");
        $delete_stmt->bind_param("ii", $file_id, $user_id);
        
        if ($delete_stmt->execute()) {
            // 4. Physical Storage Cleanup: Remove the file from disk if it exists
            if (file_exists($physical_file_path)) {
                unlink($physical_file_path); // unlink() deletes files in PHP
                header("Location: upload.php?msg=deleted");
                exit;
            } else {
                header("Location: upload.php?msg=db_only_deleted");
                exit;
            }
        }
        $delete_stmt->close();
    } else {
        // If the file does not belong to the user, throw an access error
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