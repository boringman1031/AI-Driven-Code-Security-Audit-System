<?php
// CWE-79: XSS PHP（含漏洞）
$name = $_GET['name'];
// 未過濾直接輸出，存在 XSS
echo "<h1>歡迎, " . $name . "!</h1>";
?>
