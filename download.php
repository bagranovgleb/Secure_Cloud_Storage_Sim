<?php
require_once 'config.php';

// Ensure the user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

// Check for file identification target
if (!isset($_GET['file_id'])) {
    die("❌ Missing file target parameters.");
}

$file_id = intval($_GET['file_id']);
$user_id = $_SESSION['user_id'];
$username = $_SESSION['username'];

// Fetch file metadata and confirm strict ownership boundary
$stmt = $conn->prepare("SELECT original_name, stored_name, file_type FROM file_registry WHERE id = ? AND owner_id = ?");
$stmt->bind_param("ii", $file_id, $user_id);
$stmt->execute();
$result = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$result) {
    write_security_log($username, "UNAUTHORIZED_DOWNLOAD_ATTEMPT", "User tried accessing File ID: $file_id");
    die("❌ Access Denied: File not found or you do not have permission to view this resource.");
}

$stored_name = $result['stored_name'];
$file_type = $result['file_type'];
$target_file_path = __DIR__ . "/storage/" . $stored_name;

if (!file_exists($target_file_path)) {
    die("❌ Error: The physical data block asset is missing from storage disk arrays.");
}

// --- DECRYPTION TIMELINE LAYER ---
$cipher_method = "aes-256-ctr";
$iv_length = openssl_cipher_iv_length($cipher_method);
$encryption_key = hex2bin($_SESSION['encryption_key']);

// 1. Read encrypted raw contents from disk
$raw_payload = file_get_contents($target_file_path);

// 2. Separate initialization vector (IV) from encrypted text payload
$iv = substr($raw_payload, 0, $iv_length);
$encrypted_contents = substr($raw_payload, $iv_length);

// 3. Decrypt file payload back to native state in memory buffer
$decrypted_binary = openssl_decrypt($encrypted_contents, $cipher_method, $encryption_key, OPENSSL_RAW_DATA, $iv);

if ($decrypted_binary === false) {
    die("❌ Cryptographic Error: Decryption processing failed.");
}

// 4. Decrypt the obfuscated filename.
// The stored value is: bin2hex(name_iv) . bin2hex(openssl_encrypt(name, ..., 0, name_iv))
// name_iv is $iv_length bytes → $iv_length*2 hex chars at the front.
$name_iv_hex_len = $iv_length * 2;
$name_iv = hex2bin(substr($result['original_name'], 0, $name_iv_hex_len));
$encrypted_name_b64 = hex2bin(substr($result['original_name'], $name_iv_hex_len));
$original_filename = openssl_decrypt($encrypted_name_b64, $cipher_method, $encryption_key, 0, $name_iv);

if (!$original_filename) {
    $original_filename = "downloaded_file_restored.dat"; // Fallback safety name
}

// --- STREAM BINARY PAYLOAD SAFELY TO BROWSER ---
// Clear output buffering structures to prevent file streaming corruption
if (ob_get_level()) {
    ob_end_clean();
}

// Setup HTTP response headers to force download handling mechanism
header('Content-Description: File Transfer');
header('Content-Type: ' . $file_type);
header('Content-Disposition: attachment; filename="' . basename($original_filename) . '"');
header('Expires: 0');
header('Cache-Control: must-revalidate');
header('Pragma: public');
header('Content-Length: ' . strlen($decrypted_binary));

// Flush plaintext contents directly to client connection socket
echo $decrypted_binary;
exit;