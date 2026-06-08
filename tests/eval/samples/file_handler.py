# CWE-22: Path Traversal（含漏洞）
import os

def read_file(filename):
    # 未驗證路徑，使用者可輸入 ../../etc/passwd
    base_dir = "/app/uploads/"
    file_path = os.path.join(base_dir, filename)
    with open(file_path, "r") as f:
        return f.read()
