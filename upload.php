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
            // 4. PER-FILE 40MB CAP
            elseif ($file_size > 40 * 1024 * 1024) {
                $error_message = "❌ File size exceeds the 40MB per-file limit.";
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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Drive — CloudSim</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Google+Sans:wght@400;500;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="styles/main.css">
    <link rel="stylesheet" href="styles/dashboard.css">
    <link rel="stylesheet" href="styles/upload.css">
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
        
        <a href="profile.php" class="topbar-avatar-btn">
            <img src="<?= $avatar_src ?>" alt="Profile">
            <span><?= htmlspecialchars($username) ?></span>
        </a>

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
        

        <a href="upload.php" class="sidebar-item active">
            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M3 15a4 4 0 004 4h10a4 4 0 001-7.9A5 5 0 1015.9 6L15 6a5 5 0 00-5 5l-1 .1A4 4 0 003 15z"/>
            </svg>
            My Drive
        </a>

        <a href="profile.php" class="sidebar-item">
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

        <label class="sidebar-new-btn" for="cloud_file_trigger" title="Upload a file">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" color="var(--blue)">
                <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
            </svg>
            New Upload
        </label>

        <!-- Storage usage bar -->
        <div class="storage-section">
            <?php
                $total_quota = 5 * 1024 * 1024 * 1024;
                $used_stmt = $conn->prepare("SELECT SUM(file_size) AS used FROM file_registry WHERE owner_id = ?");
                $used_stmt->bind_param("i", $user_id);
                $used_stmt->execute();
                $used_row = $used_stmt->get_result()->fetch_assoc();
                $used_stmt->close();
                $bytes_used = $used_row['used'] ?? 0;
                $pct = min(100, round(($bytes_used / $total_quota) * 100, 1));
                $used_gb = round($bytes_used / (1024**3), 2);
            ?>
            <div class="storage-label">Storage</div>
            <div class="storage-bar-wrap">
                <div class="storage-bar" style="width: <?= $pct ?>%"></div>
            </div>
            <div class="storage-sub"><?= $used_gb ?> GB of 5 GB used</div>
        </div>
    </aside>

    <!-- ── MAIN ── -->
    <main class="main">


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

        <!-- ── UPLOAD ZONE ── -->
        <form action="upload.php" method="POST" enctype="multipart/form-data" id="uploadForm">
            <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">

            <div class="upload-zone" id="uploadZone">
                <input type="file" name="cloud_file" id="cloud_file_trigger" required>
                <div class="upload-icon">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--blue)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/>
                        <path d="M20.39 18.39A5 5 0 0018 9h-1.26A8 8 0 103 16.3"/>
                    </svg>
                </div>
                <h3>Drag files here, or <span class="browse-link">browse</span></h3>
                <p>Files are encrypted with AES-256 before storage &nbsp;·&nbsp; Max 40 MB per file</p>

                <div class="file-chip" id="fileChip">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                    <span id="fileChipName"></span>
                    <button type="button" class="file-chip-clear" id="clearFile">×</button>
                </div>
            </div>

            <div class="upload-submit-row">
                <button type="submit" class="btn btn-primary" id="uploadBtn" disabled>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/>
                        <path d="M20.39 18.39A5 5 0 0018 9h-1.26A8 8 0 103 16.3"/>
                    </svg>
                    Encrypt &amp; Upload
                </button>
            </div>
        </form>

        <!-- ── FILES TABLE ── -->
        <div class="files-card">
            <div class="files-card-header">
                <span class="files-card-title">My Files</span>
                <span class="files-count"><?= count($files_list) ?> file<?= count($files_list) !== 1 ? 's' : '' ?></span>
            </div>

            <?php if (empty($files_list)): ?>
            <div class="empty-state">
                <div class="empty-state-icon">
                    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--text-3)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M13 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V9z"/><polyline points="13 2 13 9 20 9"/>
                    </svg>
                </div>
                <h3>No files yet</h3>
                <p>Upload your first file to get started. It will be encrypted automatically.</p>
            </div>
            <?php else: ?>
            <table class="file-table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Size</th>
                        <th>Uploaded</th>
                        <th></th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    $type_icons = [
                        'image'       => ['bg'=>'#e8f0fe','icon'=>'🖼️'],
                        'video'       => ['bg'=>'#fce8e6','icon'=>'🎬'],
                        'audio'       => ['bg'=>'#e6f4ea','icon'=>'🎵'],
                        'pdf'         => ['bg'=>'#fce8e6','icon'=>'📄'],
                        'zip'         => ['bg'=>'#fff3e0','icon'=>'📦'],
                        'text'        => ['bg'=>'#f1f3f4','icon'=>'📝'],
                        'default'     => ['bg'=>'#e8f0fe','icon'=>'📁'],
                    ];
                    foreach ($files_list as $f):
                        // Decrypt the stored filename — stored as bin2hex(name_iv) . bin2hex(encrypted_name)
                        $display_name = 'Unknown file';
                        if (!empty($f['original_name']) && isset($_SESSION['encryption_key'])) {
                            $cipher_method   = 'aes-256-ctr';
                            $iv_length       = openssl_cipher_iv_length($cipher_method);
                            $name_iv_hex_len = $iv_length * 2;
                            $name_iv         = hex2bin(substr($f['original_name'], 0, $name_iv_hex_len));
                            $enc_name_b64    = hex2bin(substr($f['original_name'], $name_iv_hex_len));
                            $enc_key         = hex2bin($_SESSION['encryption_key']);
                            $decrypted       = openssl_decrypt($enc_name_b64, $cipher_method, $enc_key, 0, $name_iv);
                            if ($decrypted !== false && $decrypted !== '') {
                                $display_name = $decrypted;
                            }
                        }

                        // Pick icon by file extension
                        $ext = strtolower(pathinfo($display_name, PATHINFO_EXTENSION));
                        $ext_map = [
                            'jpg'=>'image','jpeg'=>'image','png'=>'image','gif'=>'image','webp'=>'image','svg'=>'image',
                            'mp4'=>'video','mov'=>'video','avi'=>'video','mkv'=>'video',
                            'mp3'=>'audio','wav'=>'audio','flac'=>'audio','ogg'=>'audio',
                            'pdf'=>'pdf',
                            'zip'=>'zip','rar'=>'zip','7z'=>'zip','tar'=>'zip','gz'=>'zip',
                            'txt'=>'text','md'=>'text','csv'=>'text','log'=>'text',
                        ];
                        $icon_set = $type_icons[$ext_map[$ext] ?? 'default'];

                        $size_bytes = intval($f['file_size']);
                        if ($size_bytes < 1024) {
                            $size_fmt = $size_bytes . ' B';
                        } elseif ($size_bytes < 1024*1024) {
                            $size_fmt = round($size_bytes/1024, 1) . ' KB';
                        } else {
                            $size_fmt = round($size_bytes/(1024*1024), 2) . ' MB';
                        }
                        $ts = htmlspecialchars($f['uploaded_at'] ?? '—');
                    ?>
                    <tr>
                        <td>
                            <div class="file-name-cell">
                                <div class="file-type-icon" style="background:<?= $icon_set['bg'] ?>">
                                    <?= $icon_set['icon'] ?>
                                </div>
                                <div>
                                    <div class="file-name-text"><?= htmlspecialchars($display_name) ?></div>
                                    <div class="file-id-badge">#<?= intval($f['id']) ?></div>
                                </div>
                            </div>
                        </td>
                        <td class="file-size"><?= $size_fmt ?></td>
                        <td class="file-date"><?= $ts ?></td>
                        <td>
                            <div class="file-actions">
                                <a href="download.php?file_id=<?= intval($f['id']) ?>" class="action-btn action-btn-download">
                                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                                    Download
                                </a>
                                <form action="delete.php" method="POST" style="display:inline;" onsubmit="return confirm('Permanently delete this file? This cannot be undone.');">
                                    <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                                    <input type="hidden" name="file_id" value="<?= intval($f['id']) ?>">
                                    <button type="submit" class="action-btn action-btn-delete">
                                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 011-1h4a1 1 0 011 1v2"/></svg>
                                        Delete
                                    </button>
                                </form>
                            </div>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>
        </div>

        <!-- ── FOOTER ── -->
        <div class="page-footer">
                <div class="footer">This website is made by Bagranov Gleb for the project of Messina University</div>
        </div>

    </main>
</div>

<script src="js/upload.js"></script>

</body>
</html>