<?php
require_once 'config.php';

if (!isset($_SESSION['user_id'])) {
    die("Access Denied.");
}

$user_id = $_SESSION['user_id'];
$username = $_SESSION['username'];
$file_id = $_GET['file_id'] ?? 0;

$stmt = $conn->prepare("SELECT original_name, stored_name, file_type FROM file_registry WHERE id = ? AND owner_id = ?");
$stmt->bind_param("ii", $file_id, $user_id);
$stmt->execute();
$result = $stmt->get_result();

if ($file_info = $result->fetch_assoc()) {
    $real_file_path = __DIR__ . '/storage/' . $file_info['stored_name'];

    if (file_exists($real_file_path)) {
        // 1. READ ENCRYPTED CONTAINER DATA
        $raw_encrypted_payload = file_get_contents($real_file_path);
        
        $cipher_method = "aes-256-ctr";
        $iv_length = openssl_cipher_iv_length($cipher_method);
        
        // 2. CHOP CRYPTO STRUCT: Extract the first X bytes for IV, remaining data is cipher text
        $file_iv = substr($raw_encrypted_payload, 0, $iv_length);
        $encrypted_content = substr($raw_encrypted_payload, $iv_length);
        
        // 3. ON-THE-FLY DECRYPTION
        $encryption_key = hex2bin($_SESSION['encryption_key']);
        $decrypted_plaintext = openssl_decrypt($encrypted_content, $cipher_method, $encryption_key, OPENSSL_RAW_DATA, $file_iv);

        write_security_log($username, "DOWNLOAD_SUCCESS", "Decrypted and transferred file '$file_info[original_name]'.");

        // 4. STREAM CLEAN STREAM TO CLIENT
        header('Content-Type: ' . $file_info['file_type']);
        header('Content-Disposition: attachment; filename="' . $file_info['original_name'] . '"');
        echo $decrypted_plaintext;
        exit;
    }
} else {
    write_security_log($username, "ILLEGAL_ACCESS_ATTEMPT", "User tried querying file ID '$file_id' without permissions.");
    header("HTTP/1.0 403 Forbidden");
    echo "Access Denied.";
}
$stmt->close();
?>