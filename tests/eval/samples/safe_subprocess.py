# 無漏洞：安全的子程序呼叫（列表形式，無 shell=True）
import subprocess
import shlex

ALLOWED_COMMANDS = {"ls", "date", "whoami"}

def run_safe(command: str, arg: str) -> str:
    if command not in ALLOWED_COMMANDS:
        raise ValueError(f"不允許的指令: {command}")
    result = subprocess.run([command, arg], capture_output=True, text=True, timeout=5)
    return result.stdout
