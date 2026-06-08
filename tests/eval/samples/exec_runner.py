# CWE-78: OS Command Injection（含漏洞）
import subprocess

def run_script(user_input):
    # 直接將使用者輸入嵌入命令，存在命令注入
    result = subprocess.run(f"bash -c '{user_input}'", shell=True, capture_output=True)
    return result.stdout.decode()
