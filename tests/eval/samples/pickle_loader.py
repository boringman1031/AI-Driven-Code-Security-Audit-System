# CWE-502: Unsafe Deserialization（含漏洞）
import pickle
import base64

def load_session(cookie_data):
    # 直接對使用者提供的 Base64 資料進行 pickle.loads，可執行任意程式碼
    raw = base64.b64decode(cookie_data)
    session = pickle.loads(raw)
    return session
