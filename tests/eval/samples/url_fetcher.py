# CWE-918: SSRF（含漏洞）
import requests

def fetch_url(user_url):
    # 未驗證目標 URL，攻擊者可指向內網服務
    response = requests.get(user_url, timeout=5)
    return response.text
