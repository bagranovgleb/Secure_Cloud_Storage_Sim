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

// --- DYNAMICALLY DECRYPT ACTIVE AVATAR FROM BLOB STORAGE ---
$avatar_src = "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='40' height='40' viewBox='0 0 100 100'><circle cx='50' cy='50' r='50' fill='%23ccc'/><text x='50%' y='55%' font-size='40' text-anchor='middle' dominant-baseline='middle'>👤</text></svg>"; // Vector fallback icon

if (isset($conn) && $conn instanceof mysqli && isset($_SESSION['encryption_key'])) {
    $av_stmt = $conn->prepare("SELECT avatar_blob, avatar_mime FROM users WHERE id = ?");
    $av_stmt->bind_param("i", $current_admin_id);
    $av_stmt->execute();
    $av_result = $av_stmt->get_result()->fetch_assoc();
    $av_stmt->close();

    if (!empty($av_result['avatar_blob']) && !empty($av_result['avatar_mime'])) {
        $cipher_method  = "aes-256-ctr";
        $iv_length      = openssl_cipher_iv_length($cipher_method);
        $db_payload     = $av_result['avatar_blob'];
        $extracted_iv   = substr($db_payload, 0, $iv_length);
        $encrypted_data = substr($db_payload, $iv_length);
        $encryption_key = hex2bin($_SESSION['encryption_key']);
        $decrypted      = openssl_decrypt($encrypted_data, $cipher_method, $encryption_key, OPENSSL_RAW_DATA, $extracted_iv);
        if ($decrypted !== false) {
            $avatar_src = "data:" . htmlspecialchars($av_result['avatar_mime']) . ";base64," . base64_encode($decrypted);
        }
    }
}

// 3. CASCADING DELETION ENGINE (Processes User + Disk Files)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete_user') {
    verify_csrf_token();
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
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel — CloudSim</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Google+Sans:wght@400;500;600&family=Roboto+Mono:wght@400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="styles/main.css">
    <link rel="stylesheet" href="styles/dashboard.css">
    <link rel="stylesheet" href="styles/admin.css">
</head>
<body>

<!-- ── TOPBAR ── -->
<header class="topbar">
    <a href="admin_dashboard.php" class="topbar-brand">
        <div class="topbar-brand-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
        </div>
        <span class="topbar-brand-name">Cloud<span>Sim</span></span>
    </a>
    <span class="topbar-badge">Admin</span>

    <div class="topbar-spacer"></div>

    <div class="topbar-actions">
        <?php if (isset($_SESSION['role']) && $_SESSION['role'] === 'admin'): ?>
        <a href="admin_dashboard.php" class="topbar-icon-btn active" title="Admin Panel">
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
        <a href="upload.php" class="sidebar-item">
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
        <a href="admin_dashboard.php" class="sidebar-item active">
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
            <div>
                <h1 class="page-title">Admin Dashboard</h1>
                <p class="page-sub">System overview, audit logs, and user management.</p>
            </div>
        </div>

        <?php
        // ── Status banners ──
        if (isset($_GET['status'])) {
            if ($_GET['status'] === 'purge_success') {
                echo "<div class='alert alert-success'><svg width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2.5' stroke-linecap='round' stroke-linejoin='round'><polyline points='20 6 9 17 4 12'/></svg> User and all their encrypted cloud storage contents were purged successfully.</div>";
            } elseif ($_GET['status'] === 'self_deletion_blocked') {
                echo "<div class='alert alert-danger'><svg width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2.5' stroke-linecap='round' stroke-linejoin='round'><circle cx='12' cy='12' r='10'/><line x1='12' y1='8' x2='12' y2='12'/><line x1='12' y1='16' x2='12.01' y2='16'/></svg> Security block: You cannot delete your own active admin account.</div>";
            }
        }

        // ── Stats ──
        $total_users = 0; $total_files = 0; $total_bytes = 0;
        if (isset($conn) && $conn instanceof mysqli) {
            $r = $conn->query("SELECT COUNT(*) AS c FROM users");
            if ($r) $total_users = $r->fetch_assoc()['c'];
            $r = $conn->query("SELECT COUNT(*) AS c, COALESCE(SUM(file_size),0) AS b FROM file_registry");
            if ($r) { $row = $r->fetch_assoc(); $total_files = $row['c']; $total_bytes = $row['b']; }
        }
        $total_gb = round($total_bytes / (1024**3), 2);
        ?>

        <!-- ── STAT CHIPS ── -->
        <div class="stats-row">
            <div class="stat-chip">
                <div class="stat-chip-label">Total Users</div>
                <div class="stat-chip-value"><?= $total_users ?></div>
                <div class="stat-chip-sub">registered accounts</div>
            </div>
            <div class="stat-chip">
                <div class="stat-chip-label">Stored Files</div>
                <div class="stat-chip-value"><?= $total_files ?></div>
                <div class="stat-chip-sub">across all users</div>
            </div>
            <div class="stat-chip">
                <div class="stat-chip-label">Storage Used</div>
                <div class="stat-chip-value"><?= $total_gb ?></div>
                <div class="stat-chip-sub">GB total encrypted data</div>
            </div>
        </div>

        <!-- ── AUDIT LOG ── -->
        <div class="section-card">
            <div class="section-card-header">
                <div>
                    <div class="section-card-title">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
                        Security Audit Log
                    </div>
                    <div class="section-card-sub">Last 30 events, newest first</div>
                </div>
            </div>

            <!-- log viewer -->
            <div class="log-box" id="logBox">
                <div class="log-toolbar">
                    <div class="log-toolbar-left">
                        <div class="log-dot"></div>
                        <span class="log-live-label">LIVE &nbsp;·&nbsp; security_audit.log</span>
                    </div>
                    <div style="display:flex; gap:8px; align-items:center;">
                        <span class="log-count" id="logCount"></span>
                        <button class="log-scroll-btn" onclick="document.getElementById('logRows').lastElementChild?.scrollIntoView({behavior:'smooth'})">↓ latest</button>
                    </div>
                </div>
                <div id="logRows">
                <?php
                $log_directory = dirname(__DIR__, 2) . '/secure_logs/';
                $log_file      = $log_directory . 'security_audit.log';

                if (file_exists($log_file) && is_readable($log_file)) {
                    $log_lines = file($log_file);
                    if (!empty($log_lines)) {
                        $recent = array_reverse(array_slice($log_lines, -30));
                        foreach ($recent as $line) {
                            $line = htmlspecialchars(rtrim($line));
                            // Parse: [ts] [ip] [user] [action] -> detail
                            if (preg_match('/^\[([^\]]+)\]\s\[([^\]]+)\]\s\[([^\]]+)\]\s\[([^\]]+)\]\s->\s(.*)$/', $line, $m)) {
                                $ts     = $m[1];
                                $ip     = $m[2];
                                $user   = $m[3];
                                $action = $m[4];
                                $detail = $m[5];

                                // colour-code the action keyword
                                echo "<div class='log-row'>";
                                echo "<span class='log-ts'>[{$ts}]</span>";
                                echo "<span class='log-ip'>[{$ip}]</span>";
                                echo "<span class='log-user'>[{$user}]</span>";
                                echo "<span class='log-action'>[{$action}]</span>";
                                echo "<span class='log-detail'>→ {$detail}</span>";
                                echo "</div>";
                            } else {
                                // fallback for lines that don't match the pattern
                                echo "<div class='log-row'><span class='log-detail'>{$line}</span></div>";
                            }
                        }
                    } else {
                        echo "<div class='log-empty'>Log file is empty.</div>";
                    }
                } else {
                    echo "<div class='log-empty'>⚠ Log file not accessible.</div>";
                }
                ?>
                </div>
            </div>
        </div>

        <!-- ── USERS TABLE ── -->
        <div class="section-card">
            <div class="section-card-header">
                <div>
                    <div class="section-card-title">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/></svg>
                        User Management
                    </div>
                    <div class="section-card-sub">All registered accounts — purge removes user and all their encrypted files permanently</div>
                </div>
            </div>
            <table class="user-table">
                <thead>
                    <tr>
                        <th>User</th>
                        <th>Role</th>
                        <th>Registered</th>
                        <th></th>
                    </tr>
                </thead>
                <tbody>
                <?php
                if (isset($conn) && $conn instanceof mysqli) {
                    $result = $conn->query("SELECT id, username, role, created_at FROM users ORDER BY created_at DESC");
                    if ($result) {
                        while ($row = $result->fetch_assoc()):
                            $is_self = ($row['id'] === $current_admin_id);
                            $initial = strtoupper(substr($row['username'], 0, 1));
                ?>
                    <tr>
                        <td>
                            <div class="user-cell">
                                <div class="user-avatar-placeholder <?= $row['role'] === 'admin' ? 'admin-av' : '' ?>">
                                    <?= htmlspecialchars($initial) ?>
                                </div>
                                <div>
                                    <div class="user-name"><?= htmlspecialchars($row['username']) ?></div>
                                    <div class="user-id">#<?= intval($row['id']) ?></div>
                                </div>
                            </div>
                        </td>
                        <td>
                            <span class="role-badge <?= $row['role'] === 'admin' ? 'role-badge-admin' : 'role-badge-user' ?>">
                                <?= htmlspecialchars($row['role']) ?>
                            </span>
                        </td>
                        <td class="user-date"><?= htmlspecialchars($row['created_at']) ?></td>
                        <td>
                            <?php if ($is_self): ?>
                                <span class="self-label">— your account —</span>
                            <?php else: ?>
                                <form action="admin_dashboard.php" method="POST" style="margin:0;"
                                      onsubmit="return confirm('Permanently delete <?= htmlspecialchars(addslashes($row['username'])) ?> and all their files? This cannot be undone.');">
                                    <input type="hidden" name="csrf_token" value="<?= csrf_token() ?>">
                                    <input type="hidden" name="action" value="delete_user">
                                    <input type="hidden" name="target_user_id" value="<?= intval($row['id']) ?>">
                                    <button type="submit" class="btn btn-danger">
                                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/></svg>
                                        Purge
                                    </button>
                                </form>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php
                        endwhile;
                        $result->free();
                    } else {
                        echo "<tr><td colspan='4' style='padding:20px; color:var(--text-3); text-align:center;'>Error loading users.</td></tr>";
                    }
                }
                ?>
                </tbody>
            </table>
        </div>

        <div class="page-footer">
                <div class="footer">This website is made by Bagranov Gleb for the project of Messina University</div>
        </div>

    </main>
</div>

<script>
(function () {
    // Update log count badge
    const rows = document.querySelectorAll('#logRows .log-row');
    const countEl = document.getElementById('logCount');
    if (countEl) countEl.textContent = rows.length + ' events';

    // Scroll to top of log (newest first) on load
    const box = document.getElementById('logBox');
    if (box) box.scrollTop = 0;
})();
</script>

</body>
</html>