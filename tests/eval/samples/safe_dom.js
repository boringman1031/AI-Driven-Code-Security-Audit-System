// 無漏洞：安全的 DOM 操作
function renderMessage(userInput) {
  // 使用 textContent 而非 innerHTML，自動逸脫特殊字元
  const el = document.getElementById('message');
  el.textContent = userInput;
}
