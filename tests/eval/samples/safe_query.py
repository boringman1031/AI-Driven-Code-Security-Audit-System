# 無漏洞：參數化查詢
import sqlite3

def get_user(username: str):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users WHERE username = ?", (username,))
    return cursor.fetchone()
