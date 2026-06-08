# CWE-327: Use of Broken Algorithm（含漏洞）
import hashlib

def hash_password(password):
    # MD5 已知不安全，不應用於密碼雜湊
    return hashlib.md5(password.encode()).hexdigest()
