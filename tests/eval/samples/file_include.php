<?php
// CWE-22: Local File Inclusion PHP（含漏洞）
$page = $_GET['page'];
// 直接將使用者輸入用於 include，存在 LFI/RFI
include("/var/www/pages/" . $page . ".php");
?>
