# 無漏洞：安全的檔案讀取（路徑驗證）
from pathlib import Path

BASE_DIR = Path("/app/uploads").resolve()

def read_file(filename: str) -> str:
    # 確保路徑在允許的目錄內
    target = (BASE_DIR / filename).resolve()
    if not str(target).startswith(str(BASE_DIR)):
        raise ValueError("路徑穿越攻擊被阻擋")
    return target.read_text(encoding="utf-8")
