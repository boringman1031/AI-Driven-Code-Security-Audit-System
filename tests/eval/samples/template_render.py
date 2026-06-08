# CWE-94: Code Injection via eval（含漏洞）
from jinja2 import Environment

def render_template(template_str, user_data):
    # 使用 SandboxedEnvironment 以外的 Environment，允許任意程式碼執行
    env = Environment()
    tmpl = env.from_string(template_str)
    return tmpl.render(**user_data)
