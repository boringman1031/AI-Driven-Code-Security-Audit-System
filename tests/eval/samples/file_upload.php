<?php
// CWE-434: Unrestricted File Upload PHP（含漏洞）
if ($_FILES['file']['error'] === UPLOAD_ERR_OK) {
    $filename = $_FILES['file']['name'];
    // 未驗證副檔名或 MIME 類型，可上傳 PHP webshell
    move_uploaded_file($_FILES['file']['tmp_name'], "/uploads/" . $filename);
    echo "上傳成功: " . $filename;
}
?>
