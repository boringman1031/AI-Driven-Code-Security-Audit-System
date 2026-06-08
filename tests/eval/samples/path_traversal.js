// CWE-22: Path Traversal Node.js（含漏洞）
const fs = require('fs');
const path = require('path');

function readFile(filename) {
  // 未驗證路徑，攻擊者可傳入 ../../etc/passwd
  const filePath = path.join('/app/public', filename);
  return fs.readFileSync(filePath, 'utf8');
}
