<?php
// CWE-89: SQL Injection PHP（含漏洞）
function getUser($username) {
    $conn = new mysqli("localhost", "root", "", "app");
    // 字串拼接 SQL，存在注入風險
    $query = "SELECT * FROM users WHERE username = '" . $username . "'";
    return $conn->query($query);
}
?>
