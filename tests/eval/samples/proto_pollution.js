// CWE-1321: Prototype Pollution（含漏洞）
function merge(target, source) {
  for (let key in source) {
    // 未過濾 __proto__，存在原型污染
    if (typeof source[key] === 'object') {
      target[key] = merge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
