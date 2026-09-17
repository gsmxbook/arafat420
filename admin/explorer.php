<?php
// ✅ Step 1: Initialize Secure Output Buffering to prevent Header Already Sent exceptions
ob_start();
error_reporting(E_ALL & ~E_NOTICE & ~E_WARNING);

// ✅ Step 2: Start runtime session parameters safely
require_once __DIR__ . '/_admin_session.php';

// Release session lock early to prevent parallel request queueing / spinning loading
if (function_exists('session_write_close')) {
    session_write_close();
}

// =========================================================================
// 🛡️ RE-OPTIMIZED SECURE FIREWALL HEADERS (SESSIONS & COOKIE SAFE)
// =========================================================================
header("X-Frame-Options: SAMEORIGIN"); 
header("X-Content-Type-Options: nosniff"); 
header("X-XSS-Protection: 1; mode=block"); 

// ================= ADMIN SECURITY LOCK SYSTEM =================
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    ob_end_clean();
    header("Location: /admin/admin_login.php");
    exit();
}
// =============================================================

include '../db.php';

// Auto installer for simple photo cards (Picture + Name + Description)
try {
    $conn->query("CREATE TABLE IF NOT EXISTS photo_cards (
        id INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
        folder_id INT(11) NOT NULL DEFAULT 0,
        card_name VARCHAR(255) NOT NULL,
        description TEXT NULL,
        image_path TEXT NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY idx_folder_id (folder_id),
        KEY idx_created_at (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
    $conn->query("ALTER TABLE photo_cards MODIFY image_path TEXT NOT NULL");
} catch (Exception $e) {
    // Silent fallback
}

// ANTI-CSRF TOKEN GENERATOR FOR ADMIN EXPLORER STATE ACTIONS
if (empty($_SESSION['admin_csrf_token'])) {
    $_SESSION['admin_csrf_token'] = bin2hex(random_bytes(32));
}

// Track current step location
$current_folder_id = isset($_GET['folder_id']) ? intval($_GET['folder_id']) : 0;
$search_term = isset($_GET['search']) ? trim($_GET['search']) : '';
$message = "";

// Photo Card helper engine
function gsmxbook_photo_card_paths_from_db($image_path_value) {
    $image_path_value = trim((string)$image_path_value);
    if ($image_path_value === '') { return []; }

    $decoded_paths = json_decode($image_path_value, true);
    if (is_array($decoded_paths)) {
        $clean_paths = [];
        foreach ($decoded_paths as $path) {
            $path = trim((string)$path);
            if ($path !== '') { $clean_paths[] = $path; }
        }
        return $clean_paths;
    }

    return [$image_path_value];
}

function gsmxbook_photo_card_paths_to_db($paths) {
    $clean_paths = [];
    foreach ((array)$paths as $path) {
        $path = trim((string)$path);
        if ($path !== '' && !in_array($path, $clean_paths, true)) { $clean_paths[] = $path; }
    }
    if (count($clean_paths) <= 1) { return $clean_paths[0] ?? ''; }
    return json_encode($clean_paths, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

function gsmxbook_resolve_photo_card_img_src($raw_path) {
    $raw_path = trim((string)$raw_path);
    if ($raw_path === '') { return ''; }

    $candidates = [
        $raw_path,
        '../' . $raw_path,
        'uploads/photo_cards/' . basename($raw_path),
        '../uploads/photo_cards/' . basename($raw_path),
        '../uploads/' . basename($raw_path)
    ];

    foreach ($candidates as $candidate) {
        if (file_exists($candidate)) { return $candidate; }
    }
    return '';
}

function gsmxbook_upload_photo_card_images($file_key, &$message, $required = false) {
    $uploaded_paths = [];
    if (!isset($_FILES[$file_key])) {
        if ($required) { $message = "<script>alert('Please upload at least one picture for the photo card.');</script>"; }
        return $uploaded_paths;
    }

    $files = $_FILES[$file_key];
    $names = is_array($files['name']) ? $files['name'] : [$files['name']];
    $tmp_names = is_array($files['tmp_name']) ? $files['tmp_name'] : [$files['tmp_name']];
    $errors = is_array($files['error']) ? $files['error'] : [$files['error']];

    $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
    $upload_dir = "../uploads/photo_cards/";
    if (!is_dir($upload_dir)) { mkdir($upload_dir, 0755, true); }

    $valid_upload_found = false;
    $max_uploads = 12;

    foreach ($names as $idx => $img_name) {
        $img_name = (string)$img_name;
        if (trim($img_name) === '') { continue; }
        $valid_upload_found = true;

        if (count($uploaded_paths) >= $max_uploads) { break; }

        $err_code = intval($errors[$idx] ?? UPLOAD_ERR_NO_FILE);
        if ($err_code !== UPLOAD_ERR_OK) {
            $message = "<script>alert('Photo card image upload failed! Error Code: $err_code');</script>";
            return [];
        }

        $img_tmp = $tmp_names[$idx] ?? '';
        $ext = strtolower(pathinfo($img_name, PATHINFO_EXTENSION));
        if (!in_array($ext, $allowed_extensions, true)) {
            $message = "<script>alert('Invalid image format! Upload JPG, JPEG, PNG, GIF, or WEBP only.');</script>";
            return [];
        }

        $new_img_name = "photo_card_" . time() . "_" . rand(1000, 9999) . "_" . $idx . "." . $ext;
        if (move_uploaded_file($img_tmp, $upload_dir . $new_img_name)) {
            $uploaded_paths[] = "uploads/photo_cards/" . $new_img_name;
        } else {
            $message = "<script>alert('Error: Failed to save uploaded photo card image. Check uploads/photo_cards permission.');</script>";
            return [];
        }
    }

    if ($required && !$valid_upload_found) {
        $message = "<script>alert('Please upload at least one picture for the photo card.');</script>";
    }

    return $uploaded_paths;
}

if (!function_exists('gsmxbook_admin_passwords_to_array')) {
    function gsmxbook_admin_passwords_to_array($raw_password) {
        $raw_password = trim((string)$raw_password);
        if ($raw_password === '') { return []; }

        $items = [];
        $decoded = json_decode($raw_password, true);
        if (is_array($decoded)) {
            foreach ($decoded as $pass) {
                $pass = trim((string)$pass);
                if ($pass !== '' && !in_array($pass, $items, true)) { $items[] = $pass; }
            }
            return $items;
        }

        $parts = preg_split('/\r\n|\r|\n|,|\||;|\s+\/\s+/', $raw_password);
        foreach ((array)$parts as $pass) {
            $pass = trim((string)$pass);
            if ($pass !== '' && !in_array($pass, $items, true)) { $items[] = $pass; }
        }

        return $items;
    }
}

if (!function_exists('gsmxbook_admin_collect_passwords_from_post')) {
    function gsmxbook_admin_collect_passwords_from_post($legacy_key = 'password', $list_key = 'password_list') {
        $items = [];

        if (isset($_POST[$list_key]) && is_array($_POST[$list_key])) {
            foreach ($_POST[$list_key] as $pass) {
                $pass = trim((string)$pass);
                if ($pass !== '' && !in_array($pass, $items, true)) { $items[] = $pass; }
            }
        }

        if (empty($items) && isset($_POST[$legacy_key])) {
            $items = gsmxbook_admin_passwords_to_array($_POST[$legacy_key]);
        }

        return implode("\n", $items);
    }
}

// 1. Create and insert a new directory folder
if (isset($_POST['create_folder'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['admin_csrf_token']) {
        header("HTTP/1.1 403 Forbidden"); die("Security Error: CSRF token validation failed.");
    }
    
    $folder_name = trim($_POST['folder_name']);
    if (!empty($folder_name)) {
        $stmt = $conn->prepare("INSERT INTO folders (name, parent_id) VALUES (?, ?)");
        $stmt->bind_param("si", $folder_name, $current_folder_id);
        if ($stmt->execute()) {
            $stmt->close();
            ob_end_clean();
            header("Location: /admin/explorer.php?folder_id=" . $current_folder_id);
            exit();
        }
        $stmt->close();
    }
}

// 2. Append a new file entity
if (isset($_POST['upload_file'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['admin_csrf_token']) {
        header("HTTP/1.1 403 Forbidden"); die("Security Error: CSRF token validation failed.");
    }

    $title   = trim($_POST['title']);
    $file_path = trim($_POST['file_path']);
    $price   = floatval($_POST['price']);
    $size    = trim($_POST['size']);
    $desc    = isset($_POST['description']) ? trim($_POST['description']) : '';
    $tags    = isset($_POST['tags']) ? trim($_POST['tags']) : '';
    $password = gsmxbook_admin_collect_passwords_from_post();
    $password_access = isset($_POST['password_access']) ? trim($_POST['password_access']) : 'enable'; 

    $access_rule       = isset($_POST['access_rule']) ? trim($_POST['access_rule']) : '';
    $is_premium        = 0;
    $allow_package     = 1;
    $target_package_id = 0;

    if ($access_rule === 'premium_file') {
        $is_premium = 1;
        $allow_package = 0;
        $target_package_id = 0;
    } 
    elseif ($access_rule === 'without_package') {
        $is_premium = 0;
        $allow_package = 0;
        $target_package_id = 0;
    } 
    elseif ($access_rule === 'all_packages') {
        $is_premium = 0;
        $allow_package = 1;
        $target_package_id = 0;
    } 
    elseif (strpos($access_rule, 'pkg_') === 0) {
        $is_premium = 0;
        $allow_package = 1;
        $target_package_id = intval(str_replace('pkg_', '', $access_rule)); 
    }
    elseif (strpos($access_rule, 'strict_pkg_') === 0) {
        $is_premium = 0;
        $allow_package = 2;
        $target_package_id = intval(str_replace('strict_pkg_', '', $access_rule));
        $price = 0.00;
    }

    if (!empty($title) && !empty($file_path) && !empty($access_rule)) {
        $db_folder_id = ($current_folder_id === 0) ? 0 : $current_folder_id;
        
        $stmt = $conn->prepare("INSERT INTO files (folder_id, title, file_path, price, size, description, tags, password, password_access, is_premium, allow_package, target_package_id, sort_order, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NOW())");
        
        $stmt->bind_param("issdsssssiii", $db_folder_id, $title, $file_path, $price, $size, $desc, $tags, $password, $password_access, $is_premium, $allow_package, $target_package_id);
        if ($stmt->execute()) {
            $stmt->close();
            ob_end_clean();
            header("Location: /admin/explorer.php?folder_id=" . $current_folder_id);
            exit();
        }
        $stmt->close();
    }
}

// 3. Firmware specification card handler
if (isset($_POST['submit_info_card'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['admin_csrf_token']) {
        header("HTTP/1.1 403 Forbidden"); die("Security Error: CSRF token validation failed.");
    }

    $phone_name   = trim($_POST['phone_name']);
    $model        = trim($_POST['model']);
    $product_code = trim($_POST['product_code']);
    $android_ver  = trim($_POST['android_ver']);
    $os_ver       = trim($_POST['os_ver']);
    $cpu_type     = trim($_POST['cpu_type']);
    $storage_type = trim($_POST['storage_type']);
    $other_specs  = trim($_POST['other_specs']);
    
    $image_db_path = "";
    
    if (isset($_FILES['info_image']) && $_FILES['info_image']['name'] != "") {
        if ($_FILES['info_image']['error'] === 0) {
            $img_name = $_FILES['info_image']['name'];
            $img_tmp  = $_FILES['info_image']['tmp_name'];
            $ext      = strtolower(pathinfo($img_name, PATHINFO_EXTENSION));
            $allowed_extensions = array('jpg', 'jpeg', 'png', 'gif', 'webp');
            
            if (in_array($ext, $allowed_extensions)) {
                $new_img_name = "info_" . time() . "_" . rand(1000, 9999) . "." . $ext;
                $upload_dir   = "../uploads/"; 
                
                if (!is_dir($upload_dir)) {
                    mkdir($upload_dir, 0755, true);
                }
                
                if (move_uploaded_file($img_tmp, $upload_dir . $new_img_name)) {
                    $image_db_path = "uploads/" . $new_img_name; 
                } else {
                    $message = "<script>alert('Error: Failed to save uploaded image asset onto server destination directory!');</script>";
                }
            } else {
                $message = "<script>alert('Invalid file format! JPG, PNG, GIF, or WEBP only.');</script>";
            }
        } else {
            $err_code = $_FILES['info_image']['error'];
            $message = "<script>alert('Image upload failure! Error Code: $err_code');</script>";
        }
    }
    
    if (empty($message)) {
        $stmt = $conn->prepare("INSERT INTO firmware_info (folder_id, phone_name, model, product_code, android_ver, os_ver, cpu_type, storage_type, other_specs, image_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->bind_param("isssssssss", $current_folder_id, $phone_name, $model, $product_code, $android_ver, $os_ver, $cpu_type, $storage_type, $other_specs, $image_db_path);
        if ($stmt->execute()) {
            $stmt->close();
            ob_end_clean();
            header("Location: /admin/explorer.php?folder_id=" . $current_folder_id);
            exit();
        }
        $stmt->close();
    }
}

// 4. Create simple photo card
if (isset($_POST['submit_photo_card'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['admin_csrf_token']) {
        header("HTTP/1.1 403 Forbidden"); die("Security Error: CSRF token validation failed.");
    }

    $photo_card_name = trim($_POST['photo_card_name'] ?? '');
    $photo_card_description = trim($_POST['photo_card_description'] ?? '');

    if (empty($photo_card_name)) {
        $message = "<script>alert('Please enter a photo card name.');</script>";
    }

    $uploaded_photo_paths = [];
    if (empty($message)) {
        $uploaded_photo_paths = gsmxbook_upload_photo_card_images('photo_card_images', $message, true);
    }

    if (empty($message) && !empty($uploaded_photo_paths)) {
        $photo_image_db_path = gsmxbook_photo_card_paths_to_db($uploaded_photo_paths);
        $stmt = $conn->prepare("INSERT INTO photo_cards (folder_id, card_name, description, image_path, created_at) VALUES (?, ?, ?, ?, NOW())");
        $stmt->bind_param("isss", $current_folder_id, $photo_card_name, $photo_card_description, $photo_image_db_path);
        if ($stmt->execute()) {
            $stmt->close();
            ob_end_clean();
            header("Location: /admin/explorer.php?folder_id=" . $current_folder_id);
            exit();
        }
        $stmt->close();
    }
}

// 4B. Photo Card edit handler
if (isset($_POST['edit_photo_card_action'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['admin_csrf_token']) {
        header("HTTP/1.1 403 Forbidden"); die("Security Error: CSRF token validation failed.");
    }

    $photo_card_id = intval($_POST['photo_card_id'] ?? 0);
    $photo_card_name = trim($_POST['photo_card_name'] ?? '');
    $photo_card_description = trim($_POST['photo_card_description'] ?? '');
    $existing_paths = gsmxbook_photo_card_paths_from_db($_POST['existing_photo_card_paths'] ?? '');
    $replace_images = isset($_POST['replace_photo_images']) && $_POST['replace_photo_images'] === '1';

    if ($photo_card_id <= 0 || $photo_card_name === '') {
        $message = "<script>alert('Photo card edit data is invalid.');</script>";
    }

    $new_uploaded_paths = [];
    if (empty($message)) {
        $new_uploaded_paths = gsmxbook_upload_photo_card_images('photo_card_edit_images', $message, false);
    }

    if (empty($message)) {
        if ($replace_images && !empty($new_uploaded_paths)) {
            $final_paths = $new_uploaded_paths;
        } elseif (!empty($new_uploaded_paths)) {
            $final_paths = array_merge($existing_paths, $new_uploaded_paths);
        } else {
            $final_paths = $existing_paths;
        }

        if (empty($final_paths)) {
            $message = "<script>alert('Photo card needs at least one picture.');</script>";
        } else {
            $photo_image_db_path = gsmxbook_photo_card_paths_to_db($final_paths);
            $stmt = $conn->prepare("UPDATE photo_cards SET card_name = ?, description = ?, image_path = ? WHERE id = ?");
            $stmt->bind_param("sssi", $photo_card_name, $photo_card_description, $photo_image_db_path, $photo_card_id);
            if ($stmt->execute()) {
                $stmt->close();
                ob_end_clean();
                header("Location: /admin/explorer.php?folder_id=" . $current_folder_id);
                exit();
            }
            $stmt->close();
        }
    }
}

// -------------------------------------------------------------------------
// NEW: File Order Re-arranger Pipeline Handler (Move Up / Move Down)
// -------------------------------------------------------------------------
if (isset($_GET['reorder_file_id']) && isset($_GET['dir'])) {
    if (!isset($_GET['token']) || $_GET['token'] !== $_SESSION['admin_csrf_token']) {
        header("HTTP/1.1 403 Forbidden"); die("Security Error: Token verification failed.");
    }
    
    $target_file_id = intval($_GET['reorder_file_id']);
    $direction = ($_GET['dir'] === 'up') ? 'up' : 'down';

    // Find current folder ID of target file
    $stmt = $conn->prepare("SELECT folder_id FROM files WHERE id = ? LIMIT 1");
    $stmt->bind_param("i", $target_file_id);
    $stmt->execute();
    $target_res = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if ($target_res) {
        $f_id = intval($target_res['folder_id']);
        
        // Fetch ordered file IDs in the current folder
        if ($f_id === 0) {
            $q = mysqli_query($conn, "SELECT id FROM files WHERE folder_id = 0 OR folder_id IS NULL ORDER BY sort_order ASC, id DESC");
        } else {
            $stmt = $conn->prepare("SELECT id FROM files WHERE folder_id = ? ORDER BY sort_order ASC, id DESC");
            $stmt->bind_param("i", $f_id);
            $stmt->execute();
            $q = $stmt->get_result();
        }

        $items = [];
        while ($r = mysqli_fetch_assoc($q)) {
            $items[] = intval($r['id']);
        }
        if (isset($stmt) && $f_id !== 0) { $stmt->close(); }

        $idx = array_search($target_file_id, $items, true);
        if ($idx !== false) {
            $swap_idx = ($direction === 'up') ? ($idx - 1) : ($idx + 1);
            if ($swap_idx >= 0 && $swap_idx < count($items)) {
                // Swap position in array
                $temp = $items[$idx];
                $items[$idx] = $items[$swap_idx];
                $items[$swap_idx] = $temp;

                // Bulk update sort_order cleanly in a single fast query
                $case_sql = [];
                $ids_sql = [];
                foreach ($items as $order_index => $file_item_id) {
                    $new_order = ($order_index + 1) * 10;
                    $case_sql[] = "WHEN " . intval($file_item_id) . " THEN " . $new_order;
                    $ids_sql[] = intval($file_item_id);
                }
                if (!empty($ids_sql)) {
                    $bulk_sql = "UPDATE files SET sort_order = CASE id " . implode(" ", $case_sql) . " END WHERE id IN (" . implode(",", $ids_sql) . ")";
                    mysqli_query($conn, $bulk_sql);
                }
            }
        }
    }

    ob_end_clean();
    header("Location: /admin/explorer.php?folder_id=" . $current_folder_id);
    exit();
}

// Target folder entity delete handler
if (isset($_GET['delete_folder_id'])) {
    if (!isset($_GET['token']) || $_GET['token'] !== $_SESSION['admin_csrf_token']) {
        header("HTTP/1.1 403 Forbidden"); die("Security Error: Token verification failed.");
    }
    $del_f_id = intval($_GET['delete_folder_id']);
    $stmt = $conn->prepare("DELETE FROM folders WHERE id = ?");
    $stmt->bind_param("i", $del_f_id);
    $stmt->execute();
    $stmt->close();
    ob_end_clean();
    header("Location: /admin/explorer.php?folder_id=" . $current_folder_id);
    exit();
}

// Target file entity delete handler
if (isset($_GET['delete_file_id'])) {
    if (!isset($_GET['token']) || $_GET['token'] !== $_SESSION['admin_csrf_token']) {
        header("HTTP/1.1 403 Forbidden"); die("Security Error: Token verification failed.");
    }
    $del_file_id = intval($_GET['delete_file_id']);
    $stmt = $conn->prepare("DELETE FROM files WHERE id = ?");
    $stmt->bind_param("i", $del_file_id);
    $stmt->execute();
    $stmt->close();
    ob_end_clean();
    header("Location: /admin/explorer.php?folder_id=" . $current_folder_id);
    exit();
}

// Target firmware info card entity delete handler
if (isset($_GET['delete_info_id'])) {
    if (!isset($_GET['token']) || $_GET['token'] !== $_SESSION['admin_csrf_token']) {
        header("HTTP/1.1 403 Forbidden"); die("Security Error: Token verification failed.");
    }
    $del_info_id = intval($_GET['delete_info_id']);
    $stmt = $conn->prepare("DELETE FROM firmware_info WHERE id = ?");
    $stmt->bind_param("i", $del_info_id);
    $stmt->execute();
    $stmt->close();
    ob_end_clean();
    header("Location: /admin/explorer.php?folder_id=" . $current_folder_id);
    exit();
}

// Target simple photo card delete processor handler
if (isset($_GET['delete_photo_card_id'])) {
    if (!isset($_GET['token']) || $_GET['token'] !== $_SESSION['admin_csrf_token']) {
        header("HTTP/1.1 403 Forbidden"); die("Security Error: Token verification failed.");
    }
    $del_photo_card_id = intval($_GET['delete_photo_card_id']);
    $stmt = $conn->prepare("DELETE FROM photo_cards WHERE id = ?");
    $stmt->bind_param("i", $del_photo_card_id);
    $stmt->execute();
    $stmt->close();
    ob_end_clean();
    header("Location: /admin/explorer.php?folder_id=" . $current_folder_id);
    exit();
}

// Directory folder move handler
if (isset($_POST['move_folder_action'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['admin_csrf_token']) {
        header("HTTP/1.1 403 Forbidden"); die("Security Error: CSRF token validation failed.");
    }
    $folder_to_move = intval($_POST['folder_to_move']);
    $target_parent_id = intval($_POST['target_parent_id']);
    if ($folder_to_move !== $target_parent_id && $folder_to_move > 0) {
        $stmt = $conn->prepare("UPDATE folders SET parent_id = ? WHERE id = ?");
        $stmt->bind_param("ii", $target_parent_id, $folder_to_move);
        $stmt->execute();
        $stmt->close();
        ob_end_clean();
        header("Location: /admin/explorer.php?folder_id=" . $current_folder_id);
        exit();
    }
}

// Directory folder cloner copy handler
if (isset($_POST['copy_folder_action'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['admin_csrf_token']) {
        header("HTTP/1.1 403 Forbidden"); die("Security Error: CSRF token validation failed.");
    }
    $folder_to_copy = intval($_POST['folder_to_move']);
    $target_parent_id = intval($_POST['target_parent_id']);
    if ($folder_to_copy > 0) {
        $stmt = $conn->prepare("SELECT name FROM folders WHERE id = ? LIMIT 1");
        $stmt->bind_param("i", $folder_to_copy);
        $stmt->execute();
        $orig = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        
        if ($orig) {
            $stmt = $conn->prepare("INSERT INTO folders (name, parent_id) VALUES (?, ?)");
            $stmt->bind_param("si", $orig['name'], $target_parent_id);
            $stmt->execute();
            $stmt->close();
        }
        ob_end_clean();
        header("Location: /admin/explorer.php?folder_id=" . $current_folder_id);
        exit();
    }
}

// File move handler
if (isset($_POST['move_file_action'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['admin_csrf_token']) {
        header("HTTP/1.1 403 Forbidden"); die("Security Error: CSRF token validation failed.");
    }
    $file_to_move = intval($_POST['file_to_move']);
    $target_folder_id = intval($_POST['target_folder_id']);
    if ($file_to_move > 0) {
        $stmt = $conn->prepare("UPDATE files SET folder_id = ? WHERE id = ?");
        $stmt->bind_param("ii", $target_folder_id, $file_to_move);
        $stmt->execute();
        $stmt->close();
        ob_end_clean();
        header("Location: /admin/explorer.php?folder_id=" . $current_folder_id);
        exit();
    }
}

// File cloner copy handler
if (isset($_POST['copy_file_action'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['admin_csrf_token']) {
        header("HTTP/1.1 403 Forbidden"); die("Security Error: CSRF token validation failed.");
    }

    $file_to_copy = intval($_POST['file_to_move']);
    $target_folder_id = intval($_POST['target_folder_id']);

    if ($file_to_copy > 0) {
        $stmt = $conn->prepare("
            SELECT title, file_path, price, size, description, tags, password, password_access, is_premium, allow_package, target_package_id
            FROM files WHERE id = ? LIMIT 1
        ");
        $stmt->bind_param("i", $file_to_copy);
        $stmt->execute();
        $orig = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if ($orig) {
            $stmt = $conn->prepare("
                INSERT INTO files (
                    folder_id, title, file_path, price, size, description, tags, password, password_access, is_premium, allow_package, target_package_id, sort_order, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NOW())
            ");

            $stmt->bind_param(
                "issdsssssiii",
                $target_folder_id,
                $orig['title'],
                $orig['file_path'],
                $orig['price'],
                $orig['size'],
                $orig['description'],
                $orig['tags'],
                $orig['password'],
                $orig['password_access'],
                $orig['is_premium'],
                $orig['allow_package'],
                $orig['target_package_id']
            );

            $stmt->execute();
            $stmt->close();
        }

        ob_end_clean();
        header("Location: /admin/explorer.php?folder_id=" . $current_folder_id);
        exit();
    }
}

// Firmware info card move handler
if (isset($_POST['move_card_action'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['admin_csrf_token']) {
        header("HTTP/1.1 403 Forbidden"); die("Security Error: CSRF token validation failed.");
    }
    $card_id = intval($_POST['card_id']);
    $target_folder_id = intval($_POST['target_folder_id']);
    if ($card_id > 0) {
        $stmt = $conn->prepare("UPDATE firmware_info SET folder_id = ? WHERE id = ?");
        $stmt->bind_param("ii", $target_folder_id, $card_id);
        $stmt->execute();
        $stmt->close();
        ob_end_clean();
        header("Location: /admin/explorer.php?folder_id=" . $current_folder_id);
        exit();
    }
}

// Firmware info card copy handler
if (isset($_POST['copy_card_action'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['admin_csrf_token']) {
        header("HTTP/1.1 403 Forbidden"); die("Security Error: CSRF token validation failed.");
    }
    $card_id = intval($_POST['card_id']);
    $target_folder_id = intval($_POST['target_folder_id']);
    if ($card_id > 0) {
        $stmt = $conn->prepare("SELECT phone_name, model, product_code, android_ver, os_ver, cpu_type, storage_type, other_specs, image_path FROM firmware_info WHERE id = ? LIMIT 1");
        $stmt->bind_param("i", $card_id);
        $stmt->execute();
        $orig = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        
        if ($orig) {
            $stmt = $conn->prepare("INSERT INTO firmware_info (folder_id, phone_name, model, product_code, android_ver, os_ver, cpu_type, storage_type, other_specs, image_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("isssssssss", $target_folder_id, $orig['phone_name'], $orig['model'], $orig['product_code'], $orig['android_ver'], $orig['os_ver'], $orig['cpu_type'], $orig['storage_type'], $orig['other_specs'], $orig['image_path']);
            $stmt->execute();
            $stmt->close();
        }
        ob_end_clean();
        header("Location: /admin/explorer.php?folder_id=" . $current_folder_id);
        exit();
    }
}

// Photo Card relocation handler
if (isset($_POST['move_photo_card_action'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['admin_csrf_token']) {
        header("HTTP/1.1 403 Forbidden"); die("Security Error: CSRF token validation failed.");
    }
    $photo_card_id = intval($_POST['photo_card_id'] ?? 0);
    $target_folder_id = intval($_POST['target_folder_id'] ?? 0);
    if ($photo_card_id > 0) {
        $stmt = $conn->prepare("UPDATE photo_cards SET folder_id = ? WHERE id = ?");
        $stmt->bind_param("ii", $target_folder_id, $photo_card_id);
        $stmt->execute();
        $stmt->close();
        ob_end_clean();
        header("Location: /admin/explorer.php?folder_id=" . $current_folder_id);
        exit();
    }
}

// Photo Card copy handler
if (isset($_POST['copy_photo_card_action'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['admin_csrf_token']) {
        header("HTTP/1.1 403 Forbidden"); die("Security Error: CSRF token validation failed.");
    }
    $photo_card_id = intval($_POST['photo_card_id'] ?? 0);
    $target_folder_id = intval($_POST['target_folder_id'] ?? 0);
    if ($photo_card_id > 0) {
        $stmt = $conn->prepare("SELECT card_name, description, image_path FROM photo_cards WHERE id = ? LIMIT 1");
        $stmt->bind_param("i", $photo_card_id);
        $stmt->execute();
        $orig = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if ($orig) {
            $stmt = $conn->prepare("INSERT INTO photo_cards (folder_id, card_name, description, image_path, created_at) VALUES (?, ?, ?, ?, NOW())");
            $stmt->bind_param("isss", $target_folder_id, $orig['card_name'], $orig['description'], $orig['image_path']);
            $stmt->execute();
            $stmt->close();
        }
        ob_end_clean();
        header("Location: /admin/explorer.php?folder_id=" . $current_folder_id);
        exit();
    }
}

// Resolve identity strings
$current_folder_name = "Main Home Page";
$parent_id = 0;
if ($current_folder_id > 0) {
    $stmt = $conn->prepare("SELECT name, parent_id FROM folders WHERE id = ? LIMIT 1");
    $stmt->bind_param("i", $current_folder_id);
    $stmt->execute();
    $f_info = $stmt->get_result()->fetch_assoc();
    if ($f_info) {
        $current_folder_name = $f_info['name'];
        $parent_id = $f_info['parent_id'];
    }
    $stmt->close();
}

// Query compilation with updated sort_order ASC
if (!empty($search_term)) {
    $safe_search = mysqli_real_escape_string($conn, $search_term);
    $folders_list = mysqli_query($conn, "SELECT * FROM folders WHERE name LIKE '%$safe_search%' ORDER BY name ASC");
    $files_list = mysqli_query($conn, "SELECT files.*, packages.name AS target_package_name FROM files LEFT JOIN packages ON files.target_package_id = packages.id WHERE files.title LIKE '%$safe_search%' OR files.description LIKE '%$safe_search%' OR files.tags LIKE '%$safe_search%' ORDER BY files.sort_order ASC, files.id DESC");
    $info_cards_list = mysqli_query($conn, "SELECT * FROM firmware_info WHERE phone_name LIKE '%$safe_search%' OR model LIKE '%$safe_search%' ORDER BY id DESC");
    $photo_cards_list = mysqli_query($conn, "SELECT * FROM photo_cards WHERE card_name LIKE '%$safe_search%' OR description LIKE '%$safe_search%' ORDER BY id DESC");
} else {
    $stmt = $conn->prepare("SELECT * FROM folders WHERE parent_id = ? ORDER BY name ASC");
    $stmt->bind_param("i", $current_folder_id);
    $stmt->execute();
    $folders_list = $stmt->get_result(); 
    $stmt->close();

    $stmt = $conn->prepare("SELECT * FROM photo_cards WHERE folder_id = ? ORDER BY id DESC");
    $stmt->bind_param("i", $current_folder_id); $stmt->execute();
    $photo_cards_list = $stmt->get_result();
    $stmt->close();

    $stmt = $conn->prepare("SELECT * FROM firmware_info WHERE folder_id = ? ORDER BY id DESC");
    $stmt->bind_param("i", $current_folder_id); $stmt->execute();
    $info_cards_list = $stmt->get_result();
    $stmt->close();

    if ($current_folder_id === 0) {
        $files_list = mysqli_query($conn, "SELECT files.*, packages.name AS target_package_name FROM files LEFT JOIN packages ON files.target_package_id = packages.id WHERE files.folder_id = 0 OR files.folder_id IS NULL ORDER BY files.sort_order ASC, files.id DESC");
    } else {
        $stmt = $conn->prepare("SELECT files.*, packages.name AS target_package_name FROM files LEFT JOIN packages ON files.target_package_id = packages.id WHERE files.folder_id = ? ORDER BY files.sort_order ASC, files.id DESC");
        $stmt->bind_param("i", $current_folder_id);
        $stmt->execute();
        $files_list = $stmt->get_result();
        $stmt->close();
    }
}

// Fetch all folders for dropdown
$all_folders_res = mysqli_query($conn, "SELECT id, name, parent_id FROM folders ORDER BY name ASC");
$folders_array = [];
if ($all_folders_res) {
    while ($f_row = mysqli_fetch_assoc($all_folders_res)) {
        $folders_array[] = $f_row;
    }
}

// OPTIMIZED & CACHED FOLDER DROPDOWN GENERATOR
function build_secure_folder_dropdown($folders, $parent_id = 0, $spacing = '', $exclude_id = 0, $depth = 0) {
    if ($depth > 15) return ''; 
    $options = '';
    foreach ($folders as $folder) {
        if (intval($folder['parent_id']) === intval($parent_id)) {
            if (intval($folder['id']) === intval($exclude_id)) continue;
            $options .= '<option value="' . intval($folder['id']) . '">' . $spacing . htmlspecialchars($folder['name'] ?? '', ENT_QUOTES, 'UTF-8') . '</option>';
            $options .= build_secure_folder_dropdown($folders, $folder['id'], $spacing . ' └── ', $exclude_id, $depth + 1);
        }
    }
    return $options;
}

// Cache wrapper to stop recursive lag inside loops
function get_cached_folder_dropdown($folders, $exclude_id = 0) {
    static $cache = [];
    if (!isset($cache[$exclude_id])) {
        $cache[$exclude_id] = build_secure_folder_dropdown($folders, 0, '', $exclude_id, 0);
    }
    return $cache[$exclude_id];
}

function get_admin_breadcrumb_links($conn, $f_id) {
    $crumbs = array();
    $safety_counter = 0;
    while ($f_id > 0 && $safety_counter < 15) {
        $safety_counter++;
        $stmt = $conn->prepare("SELECT id, name, parent_id FROM folders WHERE id = ? LIMIT 1");
        $stmt->bind_param("i", $f_id);
        $stmt->execute();
        $folder = $stmt->get_result()->fetch_assoc();
        if ($folder) {
            $link = '<a href="/admin/explorer.php?folder_id=' . intval($folder['id']) . '" style="color: #38bdf8; text-decoration:none; font-weight:700;">' . htmlspecialchars($folder['name'] ?? '', ENT_QUOTES, 'UTF-8') . '</a>';
            array_unshift($crumbs, $link); 
            $f_id = intval($folder['parent_id']); 
        } else {
            $stmt->close();
            break;
        }
        $stmt->close();
    }
    return $crumbs;
}

$master_dropdown_options = get_cached_folder_dropdown($folders_array, 0);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title><?php echo gsmx_site_e('site_name'); ?> - Admin Step Manager</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Plus Jakarta Sans', sans-serif; }
        body { 
            background-color: #0b0f19; 
            color: #f1f5f9; 
            display: flex; 
            min-height: 100vh; 
            flex-direction: row; 
            overflow-x: hidden; 
            zoom: 0.88;
            background-image: 
                radial-gradient(circle at 10% 0%, rgba(56, 189, 248, 0.08), transparent 400px),
                radial-gradient(circle at 90% 10%, rgba(168, 85, 247, 0.06), transparent 450px);
        }
        a { text-decoration: none; color: inherit; }

        .sidebar { width: 250px; background-color: #0f172a; color: #94a3b8; padding: 20px 0; display: flex; flex-direction: column; align-items: center; flex-shrink: 0; border-right: 1px solid #1f2937; }
        .sidebar-logo-container { width: 100%; text-align: center; padding: 10px 20px 20px 20px; border-bottom: 1px solid #1e293b; margin-top: -20px; }
        .sidebar-logo { width: 110px; height: 110px; object-fit: contain; background: #fff; padding: 5px; border-radius: 50%; box-shadow: 0 4px 8px rgba(0,0,0,0.2); }
        .sidebar-menu { list-style: none; margin-top: 20px; width: 100%; }
        .sidebar-menu li a { display: flex; align-items: center; padding: 12px 25px; font-size: 14px; gap: 12px; transition: 0.2s; color: #94a3b8; border-left: 4px solid transparent; font-weight: 600; }
        .sidebar-menu li.active a, .sidebar-menu li a:hover { background-color: #1e293b; color: #38bdf8; border-left-color: #38bdf8; }

        .main-content { flex: 1; display: flex; flex-direction: column; justify-content: space-between; min-width: 0; overflow-x: hidden; }
        .top-navbar { background-color: #0f172a; height: 60px; display: flex; justify-content: space-between; align-items: center; padding: 0 30px; border-bottom: 1px solid #1f2937; width: 100%; }
        .container { padding: 30px; flex: 1; width: 100%; }

        .search-section { 
            background: linear-gradient(180deg, rgba(17, 24, 39, 0.95) 0%, rgba(15, 23, 42, 0.98) 100%); 
            padding: 20px; 
            border-radius: 16px; 
            margin-bottom: 25px; 
            box-shadow: 0 12px 25px -5px rgba(0,0,0,0.4); 
            display: flex; 
            gap: 12px; 
            align-items: center; 
            border: 1px solid rgba(148, 163, 184, 0.2); 
        }
        .search-input { flex: 1; padding: 12px 16px; border: 1px solid #374151; background: #0b0f19; color: #fff; border-radius: 10px; font-size: 14px; font-weight: 700; outline: none; transition: 0.3s; }
        .search-input:focus { border-color: #38bdf8; box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.12); }
        .search-input::placeholder { color: #64748b; font-weight: 600; }
        .btn-search { padding: 12px 24px; background: linear-gradient(135deg, #0284c7 0%, #38bdf8 100%); color: #0f172a; border: none; border-radius: 10px; font-weight: 900; cursor: pointer; display: inline-flex; align-items: center; gap: 8px; transition: 0.2s; box-shadow: 0 8px 20px rgba(56, 189, 248, 0.22); }
        .btn-search:hover { transform: translateY(-1px); filter: brightness(1.1); }
        .btn-clear-search { padding: 12px 16px; background: #1f2937; color: #cbd5e1; border: 1px solid #374151; border-radius: 10px; font-weight: 800; cursor: pointer; display: inline-flex; align-items: center; gap: 8px; transition: 0.2s; }
        .btn-clear-search:hover { background: #2d3748; color: #fff; }

        .action-buttons-wrapper { display: flex; gap: 14px; margin-bottom: 25px; flex-wrap: wrap; }
        .trigger-btn { padding: 12px 22px; font-size: 13.5px; font-weight: 900; color: #fff; border: none; border-radius: 12px; cursor: pointer; display: inline-flex; align-items: center; gap: 8px; box-shadow: 0 10px 22px rgba(0,0,0,0.25); transition: 0.2s ease; }
        .btn-trigger-folder { background: linear-gradient(135deg, #059669 0%, #10b981 100%); box-shadow: 0 10px 22px rgba(16, 185, 129, 0.25); }
        .btn-trigger-folder:hover { transform: translateY(-2px); filter: brightness(1.1); }
        .btn-trigger-file { background: linear-gradient(135deg, #0284c7 0%, #38bdf8 100%); color: #0f172a; box-shadow: 0 10px 22px rgba(56, 189, 248, 0.25); }
        .btn-trigger-file:hover { transform: translateY(-2px); filter: brightness(1.1); }
        .btn-trigger-info { background: linear-gradient(135deg, #d97706 0%, #f59e0b 100%); box-shadow: 0 10px 22px rgba(245, 158, 11, 0.25); }
        .btn-trigger-info:hover { transform: translateY(-2px); filter: brightness(1.1); }
        .btn-trigger-photo { background: linear-gradient(135deg, #db2777 0%, #ec4899 100%); box-shadow: 0 10px 22px rgba(236, 72, 153, 0.28); }
        .btn-trigger-photo:hover { transform: translateY(-2px); filter: brightness(1.1); }

        .gsmx-password-manager { grid-column: span 2; padding: 14px; border: 1px solid rgba(56, 189, 248, 0.22); border-radius: 14px; background: rgba(15, 23, 42, 0.5); }
        .gsmx-password-helper { color: #94a3b8; font-size: 12px; font-weight: 600; margin: -2px 0 12px; line-height: 1.55; }
        .gsmx-password-list { display: flex; flex-direction: column; gap: 10px; }
        .gsmx-password-row-admin { display: grid; grid-template-columns: 40px minmax(0, 1fr) 42px; align-items: center; gap: 8px; }
        .gsmx-password-index-admin { width: 40px; height: 42px; border-radius: 10px; display: inline-flex; align-items: center; justify-content: center; background: rgba(56, 189, 248, 0.12); border: 1px solid rgba(56, 189, 248, 0.42); color: #e0f2fe; font-weight: 900; font-size: 13px; box-shadow: 0 0 14px rgba(56, 189, 248, 0.08); }
        .gsmx-password-row-admin input { width: 100% !important; height: 42px !important; min-height: 42px !important; padding: 0 14px !important; border-radius: 10px !important; background: #0b0f19 !important; border: 1px solid #334155 !important; color: #e5f7ff !important; font-size: 14px !important; font-weight: 700 !important; line-height: 42px !important; outline: none !important; box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.03) !important; }
        .gsmx-password-row-admin input:focus { border-color: #38bdf8 !important; box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.12), inset 0 1px 0 rgba(255, 255, 255, 0.03) !important; }
        .gsmx-password-row-admin input::placeholder { color: #64748b !important; font-weight: 600 !important; }
        .gsmx-pass-remove-btn, .gsmx-pass-add-btn { border: none; cursor: pointer; display: inline-flex; align-items: center; justify-content: center; gap: 6px; font-weight: 900; transition: 0.2s; }
        .gsmx-pass-remove-btn { height: 42px; width: 42px; border-radius: 10px; background: rgba(239, 68, 68, 0.12); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.38); font-size: 13px; }
        .gsmx-pass-remove-btn:hover { background: rgba(239, 68, 68, 0.22); color: #fff; transform: translateY(-1px); }
        .gsmx-pass-remove-btn:disabled { opacity: 0.35; cursor: not-allowed; transform: none; }
        .gsmx-pass-add-btn { margin-top: 12px; height: 40px; padding: 0 16px; border-radius: 10px; background: linear-gradient(135deg, #38bdf8 0%, #0284c7 100%); color: #06121f; font-size: 12.5px; box-shadow: 0 8px 18px rgba(56, 189, 248, 0.15); }
        .gsmx-pass-add-btn:hover { transform: translateY(-1px); box-shadow: 0 10px 24px rgba(56, 189, 248, 0.20); }

        .payment-modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(3, 7, 18, 0.85); backdrop-filter: blur(6px); justify-content: center; align-items: center; z-index: 99999; padding: 15px; }
        .payment-modal-box { background: linear-gradient(180deg, rgba(17, 24, 39, 0.98) 0%, rgba(15, 23, 42, 0.99) 100%); border: 1px solid rgba(148, 163, 184, 0.25); border-radius: 16px; width: 700px; max-width: 95%; padding: 30px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6); border-top: 4px solid #38bdf8; animation: slideDown 0.2s ease-out; overflow-y: auto; max-height: 95vh; }
        @keyframes slideDown { from { opacity: 0; transform: translateY(-15px); } to { opacity: 1; transform: translateY(0); } }
        
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 12px; }
        .modal-header h3 { font-size: 16px; color: #fff; font-weight: 900; display: flex; align-items: center; gap: 8px; }
        .modal-header h3 span { color: #38bdf8; }
        .close-modal-btn { background: none; border: none; font-size: 24px; color: #64748b; cursor: pointer; }
        .close-modal-btn:hover { color: #ef4444; }

        .input-field { width: 100%; padding: 12px 14px; margin-bottom: 15px; background: #0b0f19; border: 1px solid #374151; border-radius: 10px; font-size: 14px; font-weight: 700; outline: none; color: #fff; transition: 0.3s; }
        .input-field:focus { border-color: #38bdf8; box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.12); }
        .input-field::placeholder { color: #64748b; font-weight: 600; }
        
        .btn-action { border: none; padding: 12px 20px; font-size: 14px; font-weight: 900; border-radius: 10px; cursor: pointer; color: #fff; display: inline-flex; align-items: center; gap: 8px; width: 100%; justify-content: center; box-shadow: 0 8px 20px rgba(0,0,0,0.2); transition: 0.2s; }
        .btn-green { background: linear-gradient(135deg, #10b981 0%, #059669 100%); } 
        .btn-blue { background: linear-gradient(135deg, #38bdf8 0%, #0284c7 100%); color: #0f172a; } 
        .btn-brown { background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); }

        .file-upload-smart-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
        .grid-span-full { grid-column: span 2; }
        .info-form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
        .info-form-full { grid-column: span 2; }
        .info-img-upload-box { grid-column: span 2; border: 2px dashed rgba(56,189,248,0.35); padding: 22px; text-align: center; border-radius: 12px; margin-bottom: 15px; cursor: pointer; background: #0b0f19; color: #94a3b8; position: relative; transition: 0.2s; font-weight: 700; }
        .info-img-upload-box:hover { border-color: #38bdf8; color: #38bdf8; background: rgba(56,189,248,0.03); }

        .info-card-render-container { display: flex; flex-direction: column; gap: 24px; margin-bottom: 35px; width: 100%; }
        .info-card-render-box { display: flex; background: linear-gradient(135deg, #f7dfcb 0%, #e6be9a 100%); border: 1px solid rgba(255, 255, 255, 0.5); border-radius: 18px; padding: 24px; gap: 25px; position: relative; align-items: center; box-shadow: 0 15px 35px -5px rgba(0, 0, 0, 0.35); width: 100%; flex-wrap: nowrap; }
        .info-card-img-side { width: 280px; min-width: 280px; background: #ffffff; display: flex; justify-content: center; align-items: center; overflow: hidden; border-radius: 14px; padding: 15px; border: 1px solid #e2e8f0; flex-shrink: 0; }
        .info-card-img-side img { width: 100%; height: auto; object-fit: contain; max-height: 240px; }
        .info-card-data-side { flex: 1; display: flex; flex-direction: column; justify-content: center; min-width: 0; }
        .info-card-data-side h2 { font-size: 24px; font-weight: 900; background: #ffffff; color: #1e293b; display: inline-block; padding: 6px 18px; margin-bottom: 15px; border-radius: 8px; align-self: flex-start; max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; box-shadow: 0 4px 12px rgba(0,0,0,0.08); }
        .info-data-grid-layout { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; width: 100%; }
        .info-grid-full-width { grid-column: span 2; }
        .info-smart-badge { background: rgba(255, 255, 255, 0.75); backdrop-filter: blur(4px); padding: 9px 14px; border-radius: 10px; font-size: 13px; font-weight: 800; color: #334155; display: flex; align-items: center; gap: 8px; border: 1px solid rgba(255,255,255,0.8); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; box-shadow: 0 2px 6px rgba(0,0,0,0.04); }
        .info-smart-badge i { color: #0f172a; font-size: 14px; width: 18px; text-align: center; }

        .btn-card-actions { display: flex; gap: 9px; flex-direction: column; width: 220px; min-width: 220px; margin-left: auto; z-index: 10; flex-shrink: 0; }
        .photo-card-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 24px; margin-bottom: 38px; width: 100%; }
        .photo-card-box { background: linear-gradient(180deg, rgba(17, 24, 39, 0.95) 0%, rgba(15, 23, 42, 0.98) 100%); border: 1px solid rgba(148, 163, 184, 0.22); border-radius: 20px; padding: 20px; overflow: hidden; box-shadow: 0 16px 32px rgba(0,0,0,0.3); transition: 0.25s; min-height: 380px; display: flex; flex-direction: column; }
        .photo-card-box:hover { transform: translateY(-3px); border-color: rgba(236,72,153,0.55); box-shadow: 0 24px 45px rgba(0,0,0,0.4), 0 0 22px rgba(236,72,153,0.12); }
        .photo-card-box.photo-card-wide { grid-column: 1 / -1; min-height: auto; padding: 24px; }
        .photo-card-image { width: 100%; aspect-ratio: 16 / 10; min-height: 220px; border-radius: 14px; background: #0b0f19; border: 1px solid rgba(71,85,105,0.78); overflow: hidden; display: flex; align-items: center; justify-content: center; margin-bottom: 16px; padding: 10px; }
        .photo-card-box.photo-card-wide .photo-card-image { aspect-ratio: auto; min-height: 320px; padding: 14px; }
        .photo-card-image img { width: 100%; height: 100%; object-fit: contain; display: block; }
        .photo-card-name { color: #ffffff; font-size: 18px; line-height: 1.34; font-weight: 950; text-align: center; margin-bottom: 10px; word-break: break-word; }
        .photo-card-desc { color: #dbeafe; font-size: 14px; line-height: 1.6; text-align: center; white-space: pre-line; word-break: break-word; min-height: 26px; font-weight: 600; }
        .photo-card-gallery { width: 100%; height: 100%; display: grid; grid-template-columns: 1fr; gap: 8px; align-items: stretch; }
        .photo-card-gallery.is-multiple { grid-template-columns: repeat(var(--photo-cols, 3), minmax(0, 1fr)); }
        .photo-card-gallery img { width: 100%; height: 100%; min-height: 132px; object-fit: contain; display: block; background: #020617; border: 1px solid rgba(71,85,105,0.55); border-radius: 10px; padding: 6px; }
        .photo-card-gallery.is-single img { min-height: 190px; }
        .photo-card-gallery.is-multiple img { min-height: 132px; }
        .photo-card-box.photo-card-wide .photo-card-gallery { gap: 16px; align-items: stretch; }
        .photo-card-box.photo-card-wide .photo-card-gallery.is-multiple img { min-height: 300px; height: 320px; border-radius: 14px; padding: 12px; }
        .photo-card-footer { margin-top: auto; padding-top: 16px; border-top: 1px solid rgba(255,255,255,0.06); display: flex; flex-direction: column; gap: 10px; }
        .photo-action-row { display: flex; justify-content: center; gap: 8px; flex-wrap: wrap; }
        .btn-photo-action { padding: 9px 14px; border-radius: 10px; font-size: 12.5px; font-weight: 900; border: 1px solid transparent; display: inline-flex; align-items: center; gap: 6px; transition: 0.2s; cursor: pointer; }
        .btn-edit-photo-card { background: rgba(56, 189, 248, 0.12); color: #7dd3fc; border-color: rgba(56, 189, 248, 0.32); }
        .btn-edit-photo-card:hover { background: #0284c7; color: #fff; border-color: #0284c7; }
        .btn-delete-photo-card { background: rgba(239, 68, 68, 0.12); color: #fca5a5; border-color: rgba(239, 68, 68, 0.28); }
        .btn-delete-photo-card:hover { background: #ef4444; color: #fff; border-color: #ef4444; }
        .photo-move-form { display: flex; flex-direction: column; gap: 7px; background: rgba(2,6,23,0.55); border: 1px solid rgba(71,85,105,0.55); border-radius: 12px; padding: 10px; }
        .photo-move-row { display: flex; gap: 7px; }
        .photo-move-row .btn-move-submit { flex: 1; padding: 8px; }
        .photo-current-preview { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; margin: 0 0 14px; }
        .photo-current-preview img { width: 100%; height: 78px; object-fit: contain; background: #020617; border: 1px solid rgba(71,85,105,0.7); border-radius: 10px; padding: 5px; }
        .photo-edit-note { color: #94a3b8; font-size: 12px; line-height: 1.5; margin: -4px 0 12px; font-weight: 600; }
        .replace-photo-row { display: flex; align-items: center; gap: 8px; color: #cbd5e1; font-size: 12.5px; font-weight: 800; margin-bottom: 14px; }
        .replace-photo-row input { accent-color: #ec4899; width: 16px; height: 16px; cursor: pointer; }
        .btn-delete-card-abs { background: linear-gradient(135deg, #991b1b 0%, #7f1d1d 100%); color: #fca5a5; padding: 11px; border-radius: 10px; font-size: 13px; font-weight: 900; border: 1px solid rgba(239,68,68,0.35); cursor: pointer; text-align: center; display: block; transition: 0.2s; box-shadow: 0 4px 12px rgba(153,27,27,0.25); }
        .btn-delete-card-abs:hover { background: #dc2626; color: #fff; }
        .btn-edit-card-abs { background: linear-gradient(135deg, #1e40af 0%, #1e3a8a 100%); color: #bfdbfe; padding: 11px; border-radius: 10px; font-size: 13px; font-weight: 900; border: 1px solid rgba(56,189,248,0.35); text-align: center; display: block; transition: 0.2s; box-shadow: 0 4px 12px rgba(30,64,175,0.25); }
        .btn-edit-card-abs:hover { background: #2563eb; color: #fff; }

        .explorer-card { background: linear-gradient(180deg, rgba(17, 24, 39, 0.95) 0%, rgba(15, 23, 42, 0.98) 100%); border-radius: 18px; padding: 25px; box-shadow: 0 16px 35px -5px rgba(0,0,0,0.4); margin-bottom: 25px; border: 1px solid rgba(148, 163, 184, 0.2); width: 100%; }
        .breadcrumb-bar { background-color: #0f172a; padding: 14px 20px; border-radius: 12px; font-weight: 700; margin-bottom: 25px; border: 1px solid rgba(56,189,248,0.22); display: flex; align-items: center; justify-content: space-between; font-size: 13.5px; box-shadow: inset 0 1px 0 rgba(255,255,255,0.04); }
        .btn-back-nav { background-color: #1f2937; color: #cbd5e1; border: 1px solid #374151; padding: 8px 16px; border-radius: 8px; font-size: 12.5px; font-weight: 800; }
        .btn-back-nav:hover { background: #2d3748; color: #fff; }

        .folder-section-title { font-size: 13px; text-transform: uppercase; color: #cbd5e1; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; font-weight: 900; letter-spacing: 0.8px; }
        .folder-grid { display: grid; grid-template-columns: repeat(6, 1fr); gap: 14px; margin-bottom: 35px; width: 100%; }
        .folder-item { 
            background: linear-gradient(145deg, rgba(30, 41, 59, 0.9), rgba(15, 23, 42, 0.95)); 
            border: 1px solid rgba(148, 163, 184, 0.22); 
            border-radius: 14px; 
            padding: 16px 10px; 
            text-align: center; 
            position: relative; 
            transition: 0.2s; 
            min-width: 0; 
            box-shadow: 0 10px 20px rgba(0,0,0,0.2);
        }
        .folder-item:hover { border-color: rgba(56, 189, 248, 0.5); transform: translateY(-2px); box-shadow: 0 14px 26px rgba(0,0,0,0.3), 0 0 15px rgba(56,189,248,0.1); }
        .folder-title { font-weight: 800; color: #fff; font-size: 13.5px; margin-top: 6px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .btn-del-item { color: #f87171; font-size: 11.5px; cursor: pointer; display: inline-block; font-weight: 800; }
        .btn-del-item:hover { text-decoration: underline; color: #ef4444; }
        
        .move-form-inline { display: flex; flex-direction: column; gap: 6px; background: #0b0f19; padding: 10px; border-radius: 10px; border: 1px solid #374151; margin-top: 8px; width: 100%; }
        .move-select { width: 100%; padding: 8px; font-size: 11.5px; font-weight: 700; border-radius: 8px; border: 1px solid #374151; outline: none; background: #1f2937; color: #fff; height: 32px; }
        .btn-move-submit { color: #fff; border: none; padding: 7px; border-radius: 8px; font-size: 11.5px; font-weight: 900; cursor: pointer; transition: 0.2s; display: inline-flex; align-items: center; justify-content: center; gap: 5px; box-shadow: 0 4px 10px rgba(0,0,0,0.2); }
        .btn-move-submit:hover { filter: brightness(1.15); transform: translateY(-1px); }

        .file-list-container { display: flex; flex-direction: column; gap: 16px; margin-top: 15px; }
        .file-matrix-item {
            position: relative;
            overflow: hidden;
            background: linear-gradient(135deg, rgba(30, 41, 59, 0.96) 0%, rgba(15, 23, 42, 0.98) 100%);
            padding: 22px;
            border: 1px solid rgba(71, 85, 105, 0.85);
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 22px;
            box-shadow: 0 16px 34px rgba(2, 6, 23, 0.34), inset 0 1px 0 rgba(255,255,255,0.04);
            transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
        }
        .file-matrix-item::before {
            content: "";
            position: absolute;
            left: 0;
            top: 16px;
            bottom: 16px;
            width: 4px;
            border-radius: 99px;
            background: linear-gradient(180deg, #fde68a 0%, #38bdf8 100%);
            box-shadow: 0 0 18px rgba(56,189,248,0.45);
        }
        .file-matrix-item::after {
            content: "";
            position: absolute;
            inset: 0;
            pointer-events: none;
            background: radial-gradient(circle at 10% 0%, rgba(56,189,248,0.10), transparent 34%), radial-gradient(circle at 85% 100%, rgba(168,85,247,0.08), transparent 35%);
            opacity: 0.65;
        }
        .file-matrix-item:hover { transform: translateY(-2px); border-color: rgba(56,189,248,0.65); box-shadow: 0 20px 42px rgba(2, 6, 23, 0.46), 0 0 0 1px rgba(56,189,248,0.12); }
        .file-info-col, .file-actions-col { position: relative; z-index: 1; }
        .file-info-col { display: flex; align-items: center; gap: 16px; flex: 1; min-width: 0; }
        .file-icon-square {
            width: 50px;
            height: 50px;
            background: linear-gradient(135deg, rgba(8, 145, 178, 0.25), rgba(15, 23, 42, 0.92));
            border: 1px solid rgba(125, 211, 252, 0.45);
            border-radius: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 21px;
            color: #67e8f9;
            flex-shrink: 0;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.12), 0 0 22px rgba(34,211,238,0.22);
        }
        .file-icon-square i { filter: drop-shadow(0 0 8px rgba(103,232,249,0.55)); }
        .file-info-col .title { font-weight: 900; color: #ffffff; font-size: 15.5px; line-height: 1.42; word-break: break-word; margin-bottom: 8px; text-shadow: 0 1px 0 rgba(0,0,0,0.28); }
        .file-meta-stats { font-size: 13px; color: #94a3b8; display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
        .admin-file-pill {
            min-height: 24px;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 10px;
            border-radius: 999px;
            font-weight: 900;
            font-size: 11.2px;
            line-height: 1;
            letter-spacing: -0.1px;
            white-space: nowrap;
            border: 1px solid rgba(148,163,184,0.24);
            background: linear-gradient(180deg, rgba(51,65,85,0.88), rgba(15,23,42,0.92));
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.10), 0 7px 16px rgba(2,6,23,0.22);
        }
        .admin-file-pill i { font-size: 11px; }
        .admin-file-pill-size { color:#7dd3fc; border-color:rgba(34,211,238,0.38); background:linear-gradient(180deg, rgba(8,145,178,0.34), rgba(15,23,42,0.95)); box-shadow: inset 0 1px 0 rgba(255,255,255,0.10), 0 0 18px rgba(34,211,238,0.14); }
        .admin-file-pill-download { color:#fde68a; border-color:rgba(245,158,11,0.38); background:linear-gradient(180deg, rgba(146,64,14,0.34), rgba(15,23,42,0.95)); box-shadow: inset 0 1px 0 rgba(255,255,255,0.10), 0 0 18px rgba(245,158,11,0.12); }
        
        .file-actions-col { display: flex; flex-direction: column; gap: 10px; align-items: flex-end; flex-shrink: 0; width: 320px; }
        .file-control-triggers { display: flex; align-items: center; justify-content: flex-end; gap: 7px; width: 100%; flex-wrap: wrap; }
        .file-price-badge {
            margin-right: auto;
            min-width: 62px;
            text-align: center;
            background: linear-gradient(135deg, #34d399 0%, #059669 100%);
            color: #04111d;
            border: 1px solid rgba(110, 231, 183, 0.70);
            padding: 8px 14px;
            border-radius: 10px;
            font-weight: 950;
            font-size: 12.5px;
            letter-spacing: -0.2px;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.25), 0 8px 22px rgba(16,185,129,0.20);
        }
        .file-price-badge.price-package { background: linear-gradient(135deg, #fde68a 0%, #f59e0b 100%); color:#111827; border-color:rgba(251,191,36,0.78); box-shadow: inset 0 1px 0 rgba(255,255,255,0.30), 0 8px 24px rgba(251,191,36,0.20); }
        .file-price-badge.price-paid { background: linear-gradient(135deg, #22d3ee 0%, #2563eb 100%); color:#eff6ff; border-color:rgba(125,211,252,0.58); box-shadow: inset 0 1px 0 rgba(255,255,255,0.18), 0 8px 24px rgba(59,130,246,0.20); }
        .file-control-triggers a { font-weight: 900; font-size: 12px; display: inline-flex; align-items: center; gap: 5px; text-decoration: none; }
        .admin-action-edit, .admin-action-delete, .admin-action-order { padding: 8px 12px; border-radius: 10px; border: 1px solid transparent; font-weight: 900; }
        .admin-action-edit { color:#7dd3fc !important; background:rgba(56,189,248,0.10); border-color:rgba(56,189,248,0.28); }
        .admin-action-delete { color:#fca5a5 !important; background:rgba(239,68,68,0.10); border-color:rgba(239,68,68,0.28); }
        .admin-action-edit:hover { background:rgba(56,189,248,0.22); color:#e0f2fe !important; }
        .admin-action-delete:hover { background:rgba(239,68,68,0.22); color:#fee2e2 !important; }

        /* Up/Down Reorder Buttons */
        .admin-action-order { 
            padding: 8px 11px; 
            background: rgba(168, 85, 247, 0.14); 
            border: 1px solid rgba(168, 85, 247, 0.35); 
            color: #d8b4fe !important; 
            font-size: 12px;
            cursor: pointer;
        }
        .admin-action-order:hover { 
            background: rgba(168, 85, 247, 0.32); 
            color: #ffffff !important; 
            transform: translateY(-1px); 
        }

        .password-badge { color:#fecdd3; border-color:rgba(244,63,94,0.40); background:linear-gradient(180deg, rgba(190,18,60,0.34), rgba(15,23,42,0.95)); box-shadow: inset 0 1px 0 rgba(255,255,255,0.10), 0 0 18px rgba(244,63,94,0.13); }
        .password-badge i { font-size: 11px; color:#fb7185; }
        .password-secret { color:#fff; background:rgba(2,6,23,0.50); padding:2px 7px; border-radius:999px; font-family:monospace; font-size:11px; letter-spacing:0.35px; max-width:220px; overflow:hidden; text-overflow:ellipsis; display:inline-block; vertical-align:middle; }

        .rule-badge-premium, .rule-badge-wallet, .rule-badge-allpkg, .rule-badge-specpkg, .rule-badge-selected-only, .pass-badge-enabled, .pass-badge-disabled { min-height: 24px; padding: 4px 11px; border-radius: 999px; font-weight: 950; font-size: 11.2px; display: inline-flex; align-items: center; gap: 5px; line-height: 1; white-space: nowrap; box-shadow: inset 0 1px 0 rgba(255,255,255,0.10), 0 7px 16px rgba(2,6,23,0.22); }
        .rule-badge-premium { background: linear-gradient(135deg, rgba(13,148,136,0.35), rgba(15,23,42,0.94)); border: 1px solid rgba(94,234,212,0.46); color: #ccfbf1; text-shadow: 0 0 10px rgba(45,212,191,0.25); }
        .rule-badge-wallet { background: linear-gradient(135deg, rgba(120,53,15,0.42), rgba(15,23,42,0.94)); border: 1px solid rgba(251,146,60,0.46); color: #fed7aa; }
        .rule-badge-allpkg { background: linear-gradient(135deg, rgba(88,28,135,0.50), rgba(30,41,59,0.95)); border: 1px solid rgba(216,180,254,0.45); color: #f5d0fe; box-shadow: inset 0 1px 0 rgba(255,255,255,0.10), 0 0 22px rgba(168,85,247,0.15); }
        .rule-badge-specpkg { background: linear-gradient(135deg, rgba(6,78,59,0.42), rgba(15,23,42,0.94)); border: 1px solid rgba(52,211,153,0.45); color: #bbf7d0; }
        .rule-badge-selected-only { background: linear-gradient(135deg, rgba(113,63,18,0.50), rgba(88,28,135,0.45)); border: 1px solid rgba(251,191,36,0.64); color: #fffbeb; box-shadow: inset 0 1px 0 rgba(255,255,255,0.14), 0 0 26px rgba(251,191,36,0.20); }
        .selected-no-balance-chip { color:#111827; background:linear-gradient(135deg,#fde68a,#f59e0b); border-radius:999px; padding:2px 7px; font-size:9.5px; font-weight:950; letter-spacing:-0.1px; margin-left:2px; }

        .pass-badge-enabled { background: linear-gradient(135deg, rgba(6,95,70,0.38), rgba(15,23,42,0.94)); border: 1px solid rgba(16,185,129,0.45); color: #a7f3d0; }
        .pass-badge-disabled { background: linear-gradient(135deg, rgba(127,29,29,0.42), rgba(15,23,42,0.94)); border: 1px solid rgba(248,113,113,0.45); color: #fecaca; }

        .dashboard-footer-wrapper { width: 100%; padding: 0; background-color: transparent; margin-top: auto; border: none; }

        @media (max-width: 1450px) { .folder-grid { grid-template-columns: repeat(5, 1fr); } }
        @media (max-width: 1200px) { .folder-grid { grid-template-columns: repeat(4, 1fr); } }
        @media (max-width: 992px) { .folder-grid { grid-template-columns: repeat(3, 1fr); } }
        @media (max-width: 768px) {
            body { flex-direction: column; zoom: 1; } 
            .sidebar { width: 100%; padding: 15px 0 0 0; }
            .sidebar-logo-container { display: flex; align-items: center; justify-content: center; gap: 15px; padding: 10px 20px; border-bottom: 1px solid #1e293b; margin-top: 0; }
            .sidebar-logo { width: 50px; height: 50px; padding: 2px; }
            .sidebar-menu { display: flex; flex-wrap: wrap; margin-top: 10px; padding: 0 10px; justify-content: center; }
            .sidebar-menu li { flex: calc(50% - 10px); margin: 5px; }
            .sidebar-menu li a { padding: 10px; border-radius: 6px; border-left: none; border-bottom: 3px solid transparent; justify-content: center; font-size: 13px; background: #1e293b; }
            .sidebar-menu li.active a { border-bottom-color: #38bdf8; background: #0f172a; }
            
            .top-navbar { padding: 15px; flex-direction: column; gap: 8px; height: auto; border-bottom: 1px solid #1f2937; text-align: center; }
            .container { padding: 15px 10px; } 
            .search-section { flex-direction: column; padding: 15px; gap: 12px; }
            .search-section form { flex-direction: column; width: 100%; }
            .btn-search, .btn-clear-search, .trigger-btn { width: 100%; justify-content: center; }
            
            .folder-grid { grid-template-columns: repeat(2, 1fr); gap: 10px; }
            .folder-item { padding: 14px 10px; } .folder-title { font-size: 13px; }
            
            .info-card-render-box { flex-direction: column; gap: 15px; padding: 15px; } 
            .info-card-img-side { width: 100%; min-width: 100%; }
            .info-card-img-side img { max-height: 180px; }
            .info-card-data-side h2 { font-size: 20px; text-align: center; align-self: center; width: 100%; }
            .info-data-grid-layout { grid-template-columns: 1fr; } 
            .btn-card-actions { margin-left: 0; width: 100%; min-width: 100%; }
            
            .file-matrix-item { flex-direction: column; align-items: stretch; gap: 15px; padding: 15px; }
            .file-actions-col { width: 100%; min-width: 100%; align-items: stretch; }
            .file-price-badge { margin-right: 0; }
            
            .breadcrumb-bar { flex-direction: column; gap: 10px; text-align: center; padding: 12px; }
            .btn-back-nav { width: 100%; text-align: center; }

            .file-upload-smart-grid { grid-template-columns: 1fr; }
            .grid-span-full { grid-column: span 1; }
        }
        @media (max-width: 992px) { .photo-card-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 18px; } .photo-card-image { min-height: 190px; } .photo-card-box.photo-card-wide { grid-column: 1 / -1; } .photo-card-box.photo-card-wide .photo-card-gallery.is-multiple img { min-height: 220px; height: 240px; } }
        @media (max-width: 560px) { .photo-card-grid { grid-template-columns: 1fr; gap: 16px; } .photo-card-box { min-height: auto; padding: 14px; } .photo-card-image { min-height: 180px; } .photo-card-box.photo-card-wide { padding: 14px; } .photo-card-box.photo-card-wide .photo-card-image { min-height: 180px; } .photo-card-gallery.is-multiple { gap: 6px; } .photo-card-box.photo-card-wide .photo-card-gallery.is-multiple img { min-height: 112px; height: 130px; padding: 4px; border-radius: 10px; } }
        @media (max-width: 480px) { .folder-grid { grid-template-columns: repeat(1, 1fr); } .photo-card-grid { grid-template-columns: 1fr; } }
    </style>
</head>
<body>

    <?php include 'sidebar.php'; ?>

    <div class="main-content">
        <?php include 'header.php'; ?>

        <div class="container">
            
            <?php if(!empty($message)) echo $message; ?>

            <div class="search-section">
                <form action="/admin/explorer.php" method="GET" style="display: flex; gap: 12px; align-items: center; flex: 1;">
                    <i class="fa-solid fa-magnifying-glass" style="color: #38bdf8; font-size: 18px;"></i>
                    <input type="text" name="search" class="search-input" placeholder="Search Files, Folders, Phone Models..." value="<?php echo htmlspecialchars($search_term); ?>">
                    <button type="submit" class="btn-search"><i class="fa-solid fa-search"></i> Search Manager</button>
                </form>
                <?php if (!empty($search_term)): ?>
                    <a href="/admin/explorer.php" class="btn-clear-search"><i class="fa-solid fa-times"></i> Clear console</a>
                <?php endif; ?>
            </div>

            <div class="action-buttons-wrapper">
                <button class="trigger-btn btn-trigger-folder" onclick="openModal('folderModal')"><i class="fa-solid fa-folder-plus"></i> Create New Folder</button>
                <button class="trigger-btn btn-trigger-file" onclick="openModal('fileModal')"><i class="fa-solid fa-file-circle-plus"></i> Add New File</button>
                <button class="trigger-btn btn-trigger-info" onclick="openModal('infoFormModal')"><i class="fa-solid fa-rectangle-list"></i> Create File Info Card</button>
                <button class="trigger-btn btn-trigger-photo" onclick="openModal('photoCardModal')"><i class="fa-solid fa-image"></i> Create Photo Card</button>
            </div>

            <div id="folderModal" class="payment-modal-overlay" onclick="closeModalOnOutsideClick(event, 'folderModal')">
                <div class="payment-modal-box" style="border-top-color: #10b981;">
                    <div class="modal-header">
                        <h3><i class="fa-solid fa-folder-plus" style="color:#10b981;"></i> Add Sub-Folder inside [<span><?php echo htmlspecialchars($current_folder_name); ?></span>]</h3>
                        <button class="close-modal-btn" onclick="closeModal('folderModal')">&times;</button>
                    </div>
                    <form action="" method="POST">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                        <input type="text" name="folder_name" class="input-field" placeholder="Enter Folder Name..." required>
                        <button type="submit" name="create_folder" class="btn-action btn-green"><i class="fa-solid fa-plus"></i> Create Folder</button>
                    </form>
                </div>
            </div>

            <div id="fileModal" class="payment-modal-overlay" onclick="closeModalOnOutsideClick(event, 'fileModal')">
                <div class="payment-modal-box" style="border-top-color: #38bdf8;">
                    <div class="modal-header">
                        <h3><i class="fa-solid fa-file-circle-plus" style="color:#38bdf8;"></i> Add New File inside [<span><?php echo htmlspecialchars($current_folder_name); ?></span>]</h3>
                        <button class="close-modal-btn" onclick="closeModal('fileModal')">&times;</button>
                    </div>
                    
                    <form action="" method="POST">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                        <div class="file-upload-smart-grid">
                            
                            <div class="grid-span-full">
                                <label style="font-size:12px; font-weight:800; color:#94a3b8; display:block; margin-bottom:6px; text-transform:uppercase;">File Title</label>
                                <input type="text" name="title" class="input-field" placeholder="Enter Full Firmware File Name..." required>
                            </div>
                            
                            <div class="grid-span-full">
                                <label style="font-size:12px; font-weight:800; color:#94a3b8; display:block; margin-bottom:6px; text-transform:uppercase;">Download URL</label>
                                <input type="url" name="file_path" class="input-field" placeholder="Paste Full Google Drive, Mega or Server Link..." required>
                            </div>
                            
                            <div>
                                <label style="font-size:12px; font-weight:800; color:#94a3b8; display:block; margin-bottom:6px; text-transform:uppercase;">Price in USD $</label>
                                <input type="number" step="0.01" name="price" class="input-field" placeholder="Price in USD $" required>
                            </div>
                            
                            <div>
                                <label style="font-size:12px; font-weight:800; color:#94a3b8; display:block; margin-bottom:6px; text-transform:uppercase;">File Size</label>
                                <input type="text" name="size" class="input-field" placeholder="File Size (e.g. 2.4 GB)">
                            </div>
                            
                            <div class="grid-span-full">
                                <label style="font-size:12px; font-weight:800; color:#94a3b8; display:block; margin-bottom:6px; text-transform:uppercase;">File Description Notes</label>
                                <textarea name="description" class="input-field" placeholder="File Description Notes" rows="3"></textarea>
                            </div>
                            
                            <div>
                                <label style="font-size:12px; font-weight:800; color:#94a3b8; display:block; margin-bottom:6px; text-transform:uppercase;">Tags</label>
                                <input type="text" name="tags" class="input-field" placeholder="Tags (e.g. Samsung, Flash File)">
                            </div>
                            
                            <div class="grid-span-full gsmx-password-manager" data-password-manager>
                                <label style="font-size:12px; font-weight:900; color:#94a3b8; display:block; margin-bottom:6px; text-transform:uppercase;"><i class="fa-solid fa-key" style="color:#f59e0b; margin-right:5px;"></i> Passwords (Optional - Multiple)</label>
                                <div class="gsmx-password-helper">1ta password hole 1ta box fill korben. Multiple password hole <b>Add More Password</b> diye serial add korben. User side e automatically Try Password 1, 2, 3 dekhabe.</div>
                                <div class="gsmx-password-list" data-password-list>
                                    <div class="gsmx-password-row-admin">
                                        <span class="gsmx-password-index-admin">1</span>
                                        <input type="text" name="password_list[]" class="input-field" placeholder="Try Password 1" autocomplete="off">
                                        <button type="button" class="gsmx-pass-remove-btn" onclick="gsmxRemovePasswordRow(this)" title="Remove this password"><i class="fa-solid fa-xmark"></i></button>
                                    </div>
                                </div>
                                <button type="button" class="gsmx-pass-add-btn" onclick="gsmxAddPasswordRow(this)"><i class="fa-solid fa-plus"></i> Add More Password</button>
                            </div>
                            
                            <div style="text-align: left; margin-bottom: 5px;">
                                <label style="display: block; font-size: 11.5px; color: #94a3b8; font-weight: 800; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px;"><i class="fa-solid fa-shield-halved" style="color: #38bdf8; margin-right: 4px;"></i> Download & Access Rule</label>
                                <select name="access_rule" class="input-field" required style="cursor: pointer; height:46px;">
                                    <option value="" disabled selected>-- Select Access Rule --</option>
                                    <option value="without_package">Without Package (Wallet Balance Only)</option>
                                    <option value="premium_file">Premium File (Strict Wallet Deduction)</option>
                                    
                                    <optgroup label="Allow Package Members" style="background:#111827; color:#38bdf8;">
                                        <option value="all_packages">Package = All Packages (Any Active Member)</option>
                                        <?php 
                                        $pkgs_query = mysqli_query($conn, "SELECT id, name FROM packages ORDER BY price ASC");
                                        if ($pkgs_query && mysqli_num_rows($pkgs_query) > 0) {
                                            while($pkg = mysqli_fetch_assoc($pkgs_query)) {
                                                echo '<option value="pkg_' . $pkg['id'] . '" style="color:#fff;">Package = ' . htmlspecialchars($pkg['name']) . '</option>';
                                            }
                                        }
                                        ?>
                                    </optgroup>

                                    <optgroup label="Selected Package Only (No Wallet Balance)" style="background:#111827; color:#fbbf24;">
                                        <?php
                                        $strict_pkgs_query = mysqli_query($conn, "SELECT id, name FROM packages ORDER BY price ASC");
                                        if ($strict_pkgs_query && mysqli_num_rows($strict_pkgs_query) > 0) {
                                            while($pkg = mysqli_fetch_assoc($strict_pkgs_query)) {
                                                echo '<option value="strict_pkg_' . $pkg['id'] . '" style="color:#fff;">Only ' . htmlspecialchars($pkg['name']) . ' Package (Balance Not Allow)</option>';
                                            }
                                        }
                                        ?>
                                    </optgroup>
                                </select>
                            </div>

                            <div style="text-align: left; margin-bottom: 5px;">
                                <label style="display: block; font-size: 11.5px; color: #94a3b8; font-weight: 800; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px;"><i class="fa-solid fa-key" style="color: #f59e0b; margin-right: 4px;"></i> Password Privilege</label>
                                <select name="password_access" class="input-field" required style="cursor: pointer; height:46px;">
                                    <option value="enable" selected>Password Access Enable</option>
                                    <option value="disable">Password Access Disable</option>
                                </select>
                            </div>

                            <div class="grid-span-full">
                                <button type="submit" name="upload_file" class="btn-action btn-blue" style="height: 48px; font-size:15px;"><i class="fa-solid fa-cloud-arrow-up"></i> Save & Upload File</button>
                            </div>
                            
                        </div>
                    </form>
                </div>
            </div>

            <div id="infoFormModal" class="payment-modal-overlay" onclick="closeModalOnOutsideClick(event, 'infoFormModal')">
                <div class="payment-modal-box" style="border-top-color: #f59e0b; width: 600px;">
                    <div class="modal-header">
                        <h3><i class="fa-solid fa-rectangle-list" style="color:#f59e0b;"></i> Create Firmware Info / Spec Card</h3>
                        <button class="close-modal-btn" onclick="closeModal('infoFormModal')">&times;</button>
                    </div>
                    <form action="" method="POST" enctype="multipart/form-data">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                        <div class="info-img-upload-box" onclick="document.getElementById('infoCardFile').click()">
                            <i class="fa-solid fa-circle-plus" style="font-size: 28px; display: block; margin-bottom: 5px; color:#f59e0b;"></i>
                            <span id="uploadBoxText">Add Brand/Model Logo or ScreenShot</span>
                            <div id="filePreviewName" class="info-img-preview-text"></div>
                            <input type="file" id="infoCardFile" name="info_image" accept="image/*" style="display: none;" onchange="displayFileName(this)">
                        </div>
                        <div class="info-form-grid">
                            <div class="info-form-full"><input type="text" name="phone_name" class="input-field" placeholder="Phone Name (e.g. Xiaomi RedMi Note 12)" required></div>
                            <div><input type="text" name="model" class="input-field" placeholder="Model (e.g. 23021RAAEG)" required></div>
                            <div><input type="text" name="product_code" class="input-field" placeholder="Product Code"></div>
                            <div><input type="text" name="android_ver" class="input-field" placeholder="Android Ver"></div>
                            <div><input type="text" name="os_ver" class="input-field" placeholder="OS Ver (e.g. MIUI 14)"></div>
                            <div><input type="text" name="cpu_type" class="input-field" placeholder="CPU Type"></div>
                            <div><input type="text" name="storage_type" class="input-field" placeholder="Storage Type (e.g. UFS 2.2)"></div>
                            <div class="info-form-full"><input type="text" name="other_specs" class="input-field" placeholder="Other specs / Notes"></div>
                        </div>
                        <button type="submit" name="submit_info_card" class="btn-action btn-brown"><i class="fa-solid fa-square-check"></i> Create Info Card</button>
                    </form>
                </div>
            </div>

            <div id="photoCardModal" class="payment-modal-overlay" onclick="closeModalOnOutsideClick(event, 'photoCardModal')">
                <div class="payment-modal-box" style="border-top-color: #ec4899; width: 560px;">
                    <div class="modal-header">
                        <h3><i class="fa-solid fa-image" style="color:#ec4899;"></i> Create Photo Card</h3>
                        <button class="close-modal-btn" onclick="closeModal('photoCardModal')">&times;</button>
                    </div>
                    <form action="" method="POST" enctype="multipart/form-data">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                        <div class="info-img-upload-box" onclick="document.getElementById('photoCardFile').click()" style="border-color: rgba(236,72,153,0.35);">
                            <i class="fa-solid fa-cloud-arrow-up" style="font-size: 28px; display: block; margin-bottom: 5px; color:#ec4899;"></i>
                            <span id="photoUploadBoxText">1. Picture Upload (Multiple / select again to add more)</span>
                            <div id="photoFilePreviewName" class="info-img-preview-text"></div>
                            <input type="file" id="photoCardFile" name="photo_card_images[]" accept="image/*" multiple style="display: none;" onchange="displayPhotoCardFileName(this)" required>
                        </div>
                        <label style="font-size:12px; font-weight:800; color:#94a3b8; display:block; margin-bottom:6px; text-transform:uppercase;">2. Name</label>
                        <input type="text" name="photo_card_name" class="input-field" placeholder="Enter card name..." required>

                        <label style="font-size:12px; font-weight:800; color:#94a3b8; display:block; margin-bottom:6px; text-transform:uppercase;">3. Description</label>
                        <textarea name="photo_card_description" class="input-field" placeholder="Write short description..." rows="4" required></textarea>

                        <button type="submit" name="submit_photo_card" class="btn-action" style="background: linear-gradient(135deg, #ec4899 0%, #8b5cf6 100%);">
                            <i class="fa-solid fa-square-check"></i> 4. Save Photo Card
                        </button>
                    </form>
                </div>
            </div>

            <?php if ($photo_cards_list && mysqli_num_rows($photo_cards_list) > 0): ?>
                <div class="folder-section-title"><i class="fa-solid fa-images" style="color:#ec4899;"></i> Photo Cards (<?php echo mysqli_num_rows($photo_cards_list); ?>)</div>
                <div class="photo-card-grid">
                    <?php while($photo_card = mysqli_fetch_assoc($photo_cards_list)): ?>
                        <?php
                            $photo_card_paths = gsmxbook_photo_card_paths_from_db($photo_card['image_path'] ?? '');
                            $photo_card_resolved_images = [];
                            foreach ($photo_card_paths as $photo_path_item) {
                                $resolved_photo_src = gsmxbook_resolve_photo_card_img_src($photo_path_item);
                                if ($resolved_photo_src !== '') { $photo_card_resolved_images[] = $resolved_photo_src; }
                            }
                            $photo_count = count($photo_card_resolved_images);
                            $photo_card_id_safe = intval($photo_card['id']);
                            $photo_cols = min(3, max(1, $photo_count));
                            $wide_photo_class = ($photo_count > 1) ? ' photo-card-wide' : '';
                        ?>
                        <div class="photo-card-box<?php echo $wide_photo_class; ?>" style="--photo-cols: <?php echo intval($photo_cols); ?>;">
                            <div class="photo-card-image" style="position: relative;">

                                <?php if ($photo_count > 0): ?>
                                    <div class="photo-card-gallery <?php echo ($photo_count > 1) ? 'is-multiple' : 'is-single'; ?>">
                                        <?php foreach ($photo_card_resolved_images as $photo_img_src): ?>
                                            <img src="<?php echo htmlspecialchars($photo_img_src, ENT_QUOTES, 'UTF-8'); ?>" alt="Photo Card">
                                        <?php endforeach; ?>
                                    </div>
                                <?php else: ?>
                                    <i class="fa-solid fa-image" style="font-size: 58px; color: #64748b;"></i>
                                <?php endif; ?>
                            </div>
                            <div class="photo-card-name"><?php echo htmlspecialchars($photo_card['card_name'] ?? '', ENT_QUOTES, 'UTF-8'); ?></div>
                            <div class="photo-card-desc"><?php echo nl2br(htmlspecialchars($photo_card['description'] ?? '', ENT_QUOTES, 'UTF-8')); ?></div>
                            <div class="photo-card-footer">
                                <div class="photo-action-row">
                                    <button type="button" class="btn-photo-action btn-edit-photo-card" onclick="openModal('editPhotoCardModal<?php echo $photo_card_id_safe; ?>')"><i class="fa-solid fa-pen-to-square"></i> Edit</button>
                                    <a href="/admin/explorer.php?folder_id=<?php echo $current_folder_id; ?>&delete_photo_card_id=<?php echo $photo_card_id_safe; ?>&token=<?php echo $_SESSION['admin_csrf_token']; ?>" class="btn-photo-action btn-delete-photo-card" onclick="return confirm('Are you sure you want to delete this photo card?');"><i class="fa-solid fa-trash-can"></i> Delete</a>
                                </div>

                                <form action="" method="POST" class="photo-move-form">
                                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                                    <input type="hidden" name="photo_card_id" value="<?php echo $photo_card_id_safe; ?>">
                                    <select name="target_folder_id" class="move-select" required>
                                        <option value="">📁 Choose Destination</option>
                                        <option value="0">🏠 Home Page Root</option>
                                        <?php echo $master_dropdown_options; ?>
                                    </select>
                                    <div class="photo-move-row">
                                        <button type="submit" name="move_photo_card_action" class="btn-move-submit" style="background:#4f46e5;"><i class="fa-solid fa-arrows-up-down-left-right"></i> Move</button>
                                        <button type="submit" name="copy_photo_card_action" class="btn-move-submit" style="background:#0284c7;"><i class="fa-solid fa-clone"></i> Copy</button>
                                    </div>
                                </form>
                            </div>
                        </div>

                        <div id="editPhotoCardModal<?php echo $photo_card_id_safe; ?>" class="payment-modal-overlay" onclick="closeModalOnOutsideClick(event, 'editPhotoCardModal<?php echo $photo_card_id_safe; ?>')">
                            <div class="payment-modal-box" style="border-top-color: #38bdf8; width: 620px;">
                                <div class="modal-header">
                                    <h3><i class="fa-solid fa-pen-to-square" style="color:#38bdf8;"></i> Edit Photo Card</h3>
                                    <button class="close-modal-btn" onclick="closeModal('editPhotoCardModal<?php echo $photo_card_id_safe; ?>')" type="button">&times;</button>
                                </div>
                                <form action="" method="POST" enctype="multipart/form-data">
                                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                                    <input type="hidden" name="photo_card_id" value="<?php echo $photo_card_id_safe; ?>">
                                    <input type="hidden" name="existing_photo_card_paths" value="<?php echo htmlspecialchars($photo_card['image_path'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">

                                    <?php if ($photo_count > 0): ?>
                                        <label style="font-size:12px; font-weight:800; color:#94a3b8; display:block; margin-bottom:8px; text-transform:uppercase;">Current Pictures</label>
                                        <div class="photo-current-preview">
                                            <?php foreach ($photo_card_resolved_images as $photo_img_src): ?>
                                                <img src="<?php echo htmlspecialchars($photo_img_src, ENT_QUOTES, 'UTF-8'); ?>" alt="Current Photo">
                                            <?php endforeach; ?>
                                        </div>
                                    <?php endif; ?>

                                    <div class="info-img-upload-box" onclick="document.getElementById('photoCardEditFile<?php echo $photo_card_id_safe; ?>').click()" style="border-color: rgba(56,189,248,0.35);">
                                        <i class="fa-solid fa-cloud-arrow-up" style="font-size: 28px; display: block; margin-bottom: 5px; color:#38bdf8;"></i>
                                        <span id="photoEditUploadText<?php echo $photo_card_id_safe; ?>">Add More Pictures (select again to add more)</span>
                                        <div id="photoEditPreviewName<?php echo $photo_card_id_safe; ?>" class="info-img-preview-text"></div>
                                        <input type="file" id="photoCardEditFile<?php echo $photo_card_id_safe; ?>" name="photo_card_edit_images[]" accept="image/*" multiple style="display: none;" onchange="displayPhotoCardEditFileName(this, '<?php echo $photo_card_id_safe; ?>')">
                                    </div>

                                    <label class="replace-photo-row">
                                        <input type="checkbox" name="replace_photo_images" value="1">
                                        Replace old pictures with newly selected pictures
                                    </label>
                                    <div class="photo-edit-note"><i class="fa-solid fa-circle-info"></i> Unchecked keeps existing images and adds new ones. Checked replaces old images completely.</div>

                                    <label style="font-size:12px; font-weight:800; color:#94a3b8; display:block; margin-bottom:6px; text-transform:uppercase;">Name</label>
                                    <input type="text" name="photo_card_name" class="input-field" value="<?php echo htmlspecialchars($photo_card['card_name'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" required>

                                    <label style="font-size:12px; font-weight:800; color:#94a3b8; display:block; margin-bottom:6px; text-transform:uppercase;">Description</label>
                                    <textarea name="photo_card_description" class="input-field" rows="4" required><?php echo htmlspecialchars($photo_card['description'] ?? '', ENT_QUOTES, 'UTF-8'); ?></textarea>

                                    <button type="submit" name="edit_photo_card_action" class="btn-action btn-blue"><i class="fa-solid fa-square-check"></i> Update Photo Card</button>
                                </form>
                            </div>
                        </div>
                    <?php endwhile; ?>
                </div>
            <?php endif; ?>

            <?php if ($info_cards_list && mysqli_num_rows($info_cards_list) > 0): ?>
                <div class="folder-section-title"><i class="fa-solid fa-id-card" style="color:#f59e0b;"></i> Firmware Specification Card</div>
                <div class="info-card-render-container">
                    <?php while($card = mysqli_fetch_assoc($info_cards_list)): ?>
                        <div class="info-card-render-box">
                            <div class="info-card-img-side">
                                <?php 
                                $show_img = false; $img_src = "";
                                if (!empty($card['image_path'])) {
                                    $raw_path = $card['image_path'];
                                    if (file_exists($raw_path)) { $img_src = $raw_path; $show_img = true; } 
                                    elseif (file_exists('../' . $raw_path)) { $img_src = '../' . $raw_path; $show_img = true; } 
                                    elseif (file_exists('uploads/' . basename($raw_path))) { $img_src = 'uploads/' . basename($raw_path); $show_img = true; } 
                                    elseif (file_exists('../uploads/' . basename($raw_path))) { $img_src = '../uploads/' . basename($raw_path); $show_img = true; }
                                }
                                if ($show_img): 
                                ?>
                                    <img src="<?php echo htmlspecialchars($img_src); ?>" alt="Phone Snapshot">
                                <?php else: ?>
                                    <i class="fa-solid fa-mobile-screen-button" style="font-size: 80px; color: #94a3b8;"></i>
                                <?php endif; ?>
                            </div>

                            <div class="info-card-data-side">
                                <h2><?php echo htmlspecialchars($card['phone_name']); ?></h2>
                                <div class="info-data-grid-layout">
                                    <div class="info-smart-badge info-grid-full-width"><i class="fa-solid fa-mobile-screen-button"></i> <b>Phone:</b>&nbsp;<?php echo htmlspecialchars($card['phone_name']); ?></div>
                                    <div class="info-smart-badge"><i class="fa-solid fa-microchip"></i> <b>Model:</b>&nbsp;<?php echo htmlspecialchars($card['model']); ?></div>
                                    <div class="info-smart-badge"><i class="fa-solid fa-barcode"></i> <b>Product:</b>&nbsp;<?php echo !empty($card['product_code']) ? htmlspecialchars($card['product_code']) : 'N/A'; ?></div>
                                    <div class="info-smart-badge"><i class="fa-brands fa-android"></i> <b>And. Ver:</b>&nbsp;<?php echo htmlspecialchars($card['android_ver']); ?></div>
                                    <div class="info-smart-badge"><i class="fa-solid fa-code-branch"></i> <b>OS Ver:</b>&nbsp;<?php echo htmlspecialchars($card['os_ver']); ?></div>
                                    <div class="info-smart-badge"><i class="fa-solid fa-cpu"></i> <b>CPU Type:</b>&nbsp;<?php echo htmlspecialchars($card['cpu_type']); ?></div>
                                    <div class="info-smart-badge"><i class="fa-solid fa-hard-drive"></i> <b>Storage:</b>&nbsp;<?php echo htmlspecialchars($card['storage_type']); ?></div>
                                    <div class="info-smart-badge info-grid-full-width"><i class="fa-solid fa-circle-info"></i> <b>Other Specs:</b>&nbsp;<?php echo htmlspecialchars($card['other_specs']); ?></div>
                                </div>
                            </div>
                            
                            <div class="btn-card-actions">
                                <a href="edit_info.php?id=<?php echo $card['id']; ?>&back_id=<?php echo $current_folder_id; ?>" class="btn-edit-card-abs"><i class="fa-solid fa-pen-to-square"></i> Edit Info</a>
                                <a href="/admin/explorer.php?folder_id=<?php echo $current_folder_id; ?>&delete_info_id=<?php echo $card['id']; ?>&token=<?php echo $_SESSION['admin_csrf_token']; ?>" class="btn-delete-card-abs" onclick="return confirm('Are you sure you want to permanently delete this info card?');"><i class="fa-solid fa-trash-can"></i> Delete Info</a>
                                
                                <form action="" method="POST" class="move-form-inline">
                                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                                    <input type="hidden" name="card_id" value="<?php echo $card['id']; ?>">
                                    <select name="target_folder_id" class="move-select" required>
                                        <option value="">📁 Choose Destination</option>
                                        <option value="0">🏠 Home Page Root</option>
                                        <?php echo $master_dropdown_options; ?>
                                    </select>
                                    <div style="display: flex; gap: 6px; width: 100%; margin-top: 2px;">
                                        <button type="submit" name="move_card_action" class="btn-move-submit" style="flex: 1; background: #4f46e5;"><i class="fa-solid fa-arrows-up-down-left-right"></i> Move</button>
                                        <button type="submit" name="copy_card_action" class="btn-move-submit" style="flex: 1; background: #0284c7;"><i class="fa-solid fa-clone"></i> Copy</button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    <?php endwhile; ?>
                </div>
            <?php endif; ?>

            <div class="explorer-card">
                <div class="breadcrumb-bar">
                    <div>
                        <span style="color:#94a3b8; font-weight:700;"><i class="fa-solid fa-folder-tree"></i> Directory:</span> 
                        <a href="/admin/explorer.php" style="color: #38bdf8; text-decoration:none; font-weight:700;">Home Page</a> 
                        <?php 
                        if ($current_folder_id > 0) {
                            $breadcrumbs = get_admin_breadcrumb_links($conn, $current_folder_id);
                            foreach ($breadcrumbs as $crumb) { echo ' / ' . $crumb; }
                        }
                        ?>
                    </div>
                    <?php if($current_folder_id > 0): ?>
                        <a href="/admin/explorer.php?folder_id=<?php echo $parent_id; ?>" class="btn-back-nav"><i class="fa-solid fa-arrow-left"></i> Up One Level</a>
                    <?php endif; ?>
                </div>

                <div class="folder-section-title"><i class="fa-solid fa-folder-open" style="color:#eab308;"></i> Folders (<?php echo ($folders_list) ? mysqli_num_rows($folders_list) : 0; ?>)</div>
                <?php if($folders_list && mysqli_num_rows($folders_list) > 0): ?>
                    <div class="folder-grid">
                        <?php while($folder = mysqli_fetch_assoc($folders_list)): ?>
                            <div class="folder-item">
                                <a href="/admin/explorer.php?folder_id=<?php echo $folder['id']; ?>">
                                    <i class="fa-solid fa-folder" style="font-size: 36px; color: #eab308; margin-bottom: 6px; display: block;"></i>
                                    <div class="folder-title"><?php echo htmlspecialchars($folder['name']); ?></div>
                                </a>
                                <div style="display: flex; justify-content: center; gap: 8px; margin-top: 8px; border-top: 1px solid #374151; padding-top: 6px;">
                                    <a href="edit_folder.php?id=<?php echo $folder['id']; ?>&back_id=<?php echo $current_folder_id; ?>" style="color: #38bdf8; font-size: 11px; font-weight: 700;"><i class="fa-solid fa-pen-to-square"></i> Rename</a>
                                    <a href="/admin/explorer.php?folder_id=<?php echo $current_folder_id; ?>&delete_folder_id=<?php echo $folder['id']; ?>&token=<?php echo $_SESSION['admin_csrf_token']; ?>" class="btn-del-item" style="font-size: 11px;" onclick="return confirm('Deleting this folder will permanently erase all its sub-folders and files inside! Proceed?')"><i class="fa-solid fa-trash-can"></i> Delete</a>
                                </div>
                                <form action="" method="POST" class="move-form-inline">
                                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                                    <input type="hidden" name="folder_to_move" value="<?php echo $folder['id']; ?>">
                                    <select name="target_parent_id" class="move-select" required>
                                        <option value="">📁 Destination</option>
                                        <option value="0">🏠 Root Home</option>
                                        <?php echo get_cached_folder_dropdown($folders_array, $folder['id']); ?>
                                    </select>
                                    <div style="display: flex; gap: 4px; width: 100%; margin-top: 2px;">
                                        <button type="submit" name="move_folder_action" class="btn-move-submit" style="flex: 1; background: #4f46e5; padding: 4px; font-size: 11px;"><i class="fa-solid fa-arrows-up-down-left-right"></i> Move</button>
                                        <button type="submit" name="copy_folder_action" class="btn-move-submit" style="flex: 1; background: #0284c7; padding: 4px; font-size: 11px;"><i class="fa-solid fa-clone"></i> Copy</button>
                                    </div>
                                </form>
                            </div>
                        <?php endwhile; ?>
                    </div>
                <?php else: ?>
                    <p style="color:#64748b; font-style:italic; font-size:13px; margin-bottom:30px; padding: 5px 0;">No sub-folders located in this directory.</p>
                <?php endif; ?>

                <div class="folder-section-title" style="margin-top:20px;"><i class="fa-solid fa-file-zipper" style="color:#a78bfa;"></i> Files (<?php echo ($files_list) ? mysqli_num_rows($files_list) : 0; ?>)</div>
                <?php if($files_list && mysqli_num_rows($files_list) > 0): ?>
                    <div class="file-list-container">
                        <?php while($file = mysqli_fetch_assoc($files_list)): ?>
                            
                            <div class="file-matrix-item">
                                <div class="file-info-col">
                                    <div class="file-icon-square">
                                        <i class="fa-solid fa-file-zipper"></i>
                                    </div>
                                    <div class="file-text-block">
                                        <div class="title"><?php echo htmlspecialchars($file['title']); ?></div>
                                        <div class="file-meta-stats">
                                            <span class="admin-file-pill admin-file-pill-size"><i class="fa-solid fa-database"></i><?php echo htmlspecialchars($file['size']); ?></span>
                                            <span class="admin-file-pill admin-file-pill-download"><i class="fa-solid fa-download"></i><?php echo (int)($file['download_count'] ?? 0); ?> Downloads</span>
                                            
                                            <?php if (!empty($file['password'])): ?>
                                                <span class="password-badge admin-file-pill">
                                                    <i class="fa-solid fa-lock"></i> Protected: <strong class="password-secret"><?php echo htmlspecialchars($file['password']); ?></strong>
                                                </span>
                                            <?php endif; ?>

                                            <?php if (($file['password_access'] ?? 'enable') === 'enable'): ?>
                                                <span class="pass-badge-enabled admin-file-pill">
                                                    <i class="fa-solid fa-eye"></i> Pass: Enabled
                                                </span>
                                            <?php else: ?>
                                                <span class="pass-badge-disabled admin-file-pill">
                                                    <i class="fa-solid fa-eye-slash"></i> Pass: Disabled
                                                </span>
                                            <?php endif; ?>

                                            <?php if (intval($file['is_premium']) === 1): ?>
                                                <span class="rule-badge-premium">
                                                    <i class="fa-solid fa-star"></i> Premium File
                                                </span>
                                            <?php elseif (intval($file['allow_package']) === 0): ?>
                                                <span class="rule-badge-wallet">
                                                    <i class="fa-solid fa-wallet"></i> Without Package
                                                </span>
                                            <?php elseif (intval($file['allow_package']) === 2 && !empty($file['target_package_id']) && intval($file['target_package_id']) > 0): ?>
                                                <span class="rule-badge-selected-only">
                                                    <i class="fa-solid fa-shield-halved"></i> Only <?php echo htmlspecialchars($file['target_package_name'] ?? 'Selected Package'); ?> Package <span class="selected-no-balance-chip">No Balance</span>
                                                </span>
                                            <?php elseif (!empty($file['target_package_id']) && intval($file['target_package_id']) > 0): ?>
                                                <span class="rule-badge-specpkg">
                                                    <i class="fa-solid fa-box-open"></i> Package = <?php echo htmlspecialchars($file['target_package_name'] ?? 'Custom Plan'); ?>
                                                </span>
                                            <?php else: ?>
                                                <span class="rule-badge-allpkg">
                                                    <i class="fa-solid fa-crown"></i> Package = All Packages
                                                </span>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="file-actions-col">
                                    <div class="file-control-triggers">
                                        <?php
                                            $is_selected_pkg_only_admin = (intval($file['allow_package']) === 2 && !empty($file['target_package_id']) && intval($file['target_package_id']) > 0);
                                            $admin_price_class = $is_selected_pkg_only_admin ? 'price-package' : (floatval($file['price']) > 0 ? 'price-paid' : '');
                                            $admin_price_text = $is_selected_pkg_only_admin ? ($file['target_package_name'] ?? 'Package') : (floatval($file['price']) == 0 ? 'Free' : '$' . number_format($file['price'], 2));
                                        ?>
                                        <div class="file-price-badge <?php echo $admin_price_class; ?>">
                                            <?php echo htmlspecialchars($admin_price_text); ?>
                                        </div>

                                        <a class="admin-action-order" href="/admin/explorer.php?folder_id=<?php echo $current_folder_id; ?>&reorder_file_id=<?php echo $file['id']; ?>&dir=up&token=<?php echo $_SESSION['admin_csrf_token']; ?>" title="Move Up">
                                            <i class="fa-solid fa-arrow-up"></i> Up
                                        </a>
                                        <a class="admin-action-order" href="/admin/explorer.php?folder_id=<?php echo $current_folder_id; ?>&reorder_file_id=<?php echo $file['id']; ?>&dir=down&token=<?php echo $_SESSION['admin_csrf_token']; ?>" title="Move Down">
                                            <i class="fa-solid fa-arrow-down"></i> Down
                                        </a>

                                        <a class="admin-action-edit" href="edit_file.php?id=<?php echo $file['id']; ?>&back_id=<?php echo $current_folder_id; ?>"><i class="fa-solid fa-edit"></i> Edit</a>
                                        <a class="admin-action-delete" href="/admin/explorer.php?folder_id=<?php echo $current_folder_id; ?>&delete_file_id=<?php echo $file['id']; ?>&token=<?php echo $_SESSION['admin_csrf_token']; ?>" onclick="return confirm('Are you sure you want to permanently delete this file?');"><i class="fa-solid fa-trash"></i> Delete</a>
                                    </div>
                                    
                                    <form action="" method="POST" class="move-form-inline">
                                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['admin_csrf_token']; ?>">
                                        <input type="hidden" name="file_to_move" value="<?php echo $file['id']; ?>">
                                        <select name="target_folder_id" class="move-select" required>
                                            <option value="">📁 Choose Destination</option>
                                            <option value="0">🏠 Home Page Root</option>
                                            <?php echo $master_dropdown_options; ?>
                                        </select>
                                        <div style="display: flex; gap: 6px; width: 100%; margin-top: 2px;">
                                            <button type="submit" name="move_file_action" class="btn-move-submit" style="flex: 1; background: #4f46e5;"><i class="fa-solid fa-arrows-up-down-left-right"></i> Move</button>
                                            <button type="submit" name="copy_file_action" class="btn-move-submit" style="flex: 1; background: #0284c7;"><i class="fa-solid fa-clone"></i> Copy</button>
                                        </div>
                                    </form>
                                </div>
                            </div>

                        <?php endwhile; ?>
                    </div>
                <?php else: ?>
                    <p style="color:#64748b; font-style:italic; font-size:13px; margin-top: 15px; padding: 5px 0;">No uploaded files found in this directory.</p>
                <?php endif; ?>

            </div>
        </div>

        <div class="dashboard-footer-wrapper">
            <?php include 'dashboard_footer.php'; ?>
        </div>
    </div>

    <script>
        function openModal(modalId) { document.getElementById(modalId).style.display = 'flex'; }
        function closeModal(modalId) { document.getElementById(modalId).style.display = 'none'; }
        function closeModalOnOutsideClick(event, modalId) { if (event.target.id === modalId) { closeModal(modalId); } }

        function gsmxRefreshPasswordRows(scope) {
            var manager = scope && scope.closest ? scope.closest('[data-password-manager]') : null;
            if (!manager) { manager = document.querySelector('[data-password-manager]'); }
            if (!manager) { return; }

            var rows = manager.querySelectorAll('.gsmx-password-row-admin');
            rows.forEach(function(row, index) {
                var badge = row.querySelector('.gsmx-password-index-admin');
                var input = row.querySelector('input[name="password_list[]"]');
                var removeBtn = row.querySelector('.gsmx-pass-remove-btn');
                if (badge) { badge.textContent = String(index + 1); }
                if (input) { input.placeholder = 'Try Password ' + (index + 1); }
                if (removeBtn) { removeBtn.disabled = rows.length <= 1; }
            });
        }

        function gsmxAddPasswordRow(button) {
            var manager = button.closest('[data-password-manager]');
            if (!manager) { return; }

            var list = manager.querySelector('[data-password-list]');
            if (!list) { return; }

            var row = document.createElement('div');
            row.className = 'gsmx-password-row-admin';
            row.innerHTML = '<span class="gsmx-password-index-admin"></span>' +
                '<input type="text" name="password_list[]" class="input-field" placeholder="Try Password" autocomplete="off">' +
                '<button type="button" class="gsmx-pass-remove-btn" onclick="gsmxRemovePasswordRow(this)" title="Remove this password"><i class="fa-solid fa-xmark"></i></button>';

            list.appendChild(row);
            gsmxRefreshPasswordRows(row);
            var newInput = row.querySelector('input');
            if (newInput) { newInput.focus(); }
        }

        function gsmxRemovePasswordRow(button) {
            var manager = button.closest('[data-password-manager]');
            if (!manager) { return; }

            var rows = manager.querySelectorAll('.gsmx-password-row-admin');
            if (rows.length <= 1) {
                var onlyInput = rows[0] ? rows[0].querySelector('input[name="password_list[]"]') : null;
                if (onlyInput) { onlyInput.value = ''; onlyInput.focus(); }
                gsmxRefreshPasswordRows(manager);
                return;
            }

            var row = button.closest('.gsmx-password-row-admin');
            if (row) { row.remove(); }
            gsmxRefreshPasswordRows(manager);
        }

        document.addEventListener('DOMContentLoaded', function() {
            document.querySelectorAll('[data-password-manager]').forEach(function(manager) {
                gsmxRefreshPasswordRows(manager);
            });
        });

        function displayFileName(input) {
            if (input.files && input.files[0]) {
                document.getElementById('filePreviewName').innerText = "Selected: " + input.files[0].name;
                document.getElementById('uploadBoxText').innerText = "Change Image";
            }
        }

        var gsmxbookPhotoCardCreateFiles = (window.DataTransfer) ? new DataTransfer() : null;
        var gsmxbookPhotoCardEditFiles = {};

        function gsmxbookFileKey(file) {
            return [file.name, file.size, file.lastModified].join('_');
        }

        function gsmxbookAppendFilesToBucket(bucket, fileList) {
            var seen = {};
            for (var i = 0; i < bucket.files.length; i++) {
                seen[gsmxbookFileKey(bucket.files[i])] = true;
            }
            for (var j = 0; j < fileList.length; j++) {
                var file = fileList[j];
                var key = gsmxbookFileKey(file);
                if (!seen[key]) {
                    bucket.items.add(file);
                    seen[key] = true;
                }
            }
            return bucket;
        }

        function displayPhotoCardFileName(input) {
            if (!input.files || input.files.length === 0) { return; }

            if (gsmxbookPhotoCardCreateFiles) {
                gsmxbookAppendFilesToBucket(gsmxbookPhotoCardCreateFiles, input.files);
                input.files = gsmxbookPhotoCardCreateFiles.files;
            }

            var fileCount = input.files.length;
            document.getElementById('photoFilePreviewName').innerText = fileCount + " picture(s) selected";
            document.getElementById('photoUploadBoxText').innerText = "Add / Change More Pictures";
        }

        function displayPhotoCardEditFileName(input, cardId) {
            if (!input.files || input.files.length === 0) { return; }

            if (window.DataTransfer) {
                if (!gsmxbookPhotoCardEditFiles[cardId]) {
                    gsmxbookPhotoCardEditFiles[cardId] = new DataTransfer();
                }
                gsmxbookAppendFilesToBucket(gsmxbookPhotoCardEditFiles[cardId], input.files);
                input.files = gsmxbookPhotoCardEditFiles[cardId].files;
            }

            var fileCount = input.files.length;
            document.getElementById('photoEditPreviewName' + cardId).innerText = fileCount + " new picture(s) selected";
            document.getElementById('photoEditUploadText' + cardId).innerText = "Add / Change More Pictures";
        }
    </script>
</body>
</html>
<?php
if (ob_get_level() > 0) {
    ob_end_flush();
}
?>