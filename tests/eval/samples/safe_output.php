<?php
// 無漏洞：安全的輸出 PHP
$name = $_GET['name'] ?? '';
// 使用 htmlspecialchars 防止 XSS
echo "<h1>歡迎, " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . "!</h1>";
?>
