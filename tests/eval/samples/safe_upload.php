<?php
// 無漏洞：安全的檔案上傳 PHP
$allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
$maxSize = 5 * 1024 * 1024;

if ($_FILES['file']['error'] !== UPLOAD_ERR_OK) {
    die("上傳錯誤");
}
if ($_FILES['file']['size'] > $maxSize) {
    die("檔案過大");
}
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mimeType = $finfo->file($_FILES['file']['tmp_name']);
if (!in_array($mimeType, $allowedTypes, true)) {
    die("不允許的檔案類型");
}
$safeFilename = bin2hex(random_bytes(16)) . '.bin';
move_uploaded_file($_FILES['file']['tmp_name'], "/uploads/" . $safeFilename);
?>
