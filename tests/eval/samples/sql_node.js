// CWE-89: SQL Injection Node.js（含漏洞）
const mysql = require('mysql');
const conn = mysql.createConnection({ host: 'localhost', user: 'root', database: 'app' });

function getUser(username) {
  // 字串拼接 SQL，存在注入風險
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  return new Promise((resolve, reject) => {
    conn.query(query, (err, results) => {
      if (err) reject(err);
      else resolve(results);
    });
  });
}
