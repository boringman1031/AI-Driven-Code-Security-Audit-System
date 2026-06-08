<?php
// 無漏洞：安全的 PHP 登入
function getUser(PDO $pdo, string $username): ?array {
    // 使用 PDO Prepared Statement
    $stmt = $pdo->prepare("SELECT id, username FROM users WHERE username = :username");
    $stmt->execute([':username' => $username]);
    return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
}
?>
