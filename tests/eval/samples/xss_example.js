// CWE-79: XSS（含漏洞）
function renderMessage(userInput) {
  // 直接將使用者輸入插入 DOM，存在 XSS
  document.getElementById('message').innerHTML = userInput;
}
