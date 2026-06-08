"""
50 案例評估測試集 Ground Truth（Phase E）。

每個 case 包含:
  - id: 唯一識別碼
  - filename: 模擬的檔案名稱（用於語言感知）
  - language: 程式語言
  - has_vulnerability: 是否含有漏洞
  - expected_cwe: 預期應偵測到的 CWE（含漏洞案例）
  - severity: 最高嚴重程度（含漏洞案例）
  - code_file: 對應的測試程式碼檔案路徑

使用方式:
  python -m backend.eval.run_eval [--backend openai|ollama] [--output data/eval_results]
"""

GROUND_TRUTH: list[dict] = [
    # ── Python（8 有漏洞 + 4 無漏洞 = 12）────────────────────────────
    {"id": "py01", "language": "Python", "filename": "login.py",
     "has_vulnerability": True, "expected_cwe": ["CWE-89"], "severity": "Critical"},
    {"id": "py02", "language": "Python", "filename": "exec_runner.py",
     "has_vulnerability": True, "expected_cwe": ["CWE-78"], "severity": "Critical"},
    {"id": "py03", "language": "Python", "filename": "file_handler.py",
     "has_vulnerability": True, "expected_cwe": ["CWE-22"], "severity": "High"},
    {"id": "py04", "language": "Python", "filename": "template_render.py",
     "has_vulnerability": True, "expected_cwe": ["CWE-94"], "severity": "High"},
    {"id": "py05", "language": "Python", "filename": "config_loader.py",
     "has_vulnerability": True, "expected_cwe": ["CWE-798"], "severity": "High"},
    {"id": "py06", "language": "Python", "filename": "pickle_loader.py",
     "has_vulnerability": True, "expected_cwe": ["CWE-502"], "severity": "Critical"},
    {"id": "py07", "language": "Python", "filename": "url_fetcher.py",
     "has_vulnerability": True, "expected_cwe": ["CWE-918"], "severity": "High"},
    {"id": "py08", "language": "Python", "filename": "crypto_weak.py",
     "has_vulnerability": True, "expected_cwe": ["CWE-327"], "severity": "Medium"},
    {"id": "py09", "language": "Python", "filename": "safe_query.py",
     "has_vulnerability": False, "expected_cwe": [], "severity": None},
    {"id": "py10", "language": "Python", "filename": "safe_file.py",
     "has_vulnerability": False, "expected_cwe": [], "severity": None},
    {"id": "py11", "language": "Python", "filename": "safe_crypto.py",
     "has_vulnerability": False, "expected_cwe": [], "severity": None},
    {"id": "py12", "language": "Python", "filename": "safe_subprocess.py",
     "has_vulnerability": False, "expected_cwe": [], "severity": None},

    # ── JavaScript / TypeScript（6 有漏洞 + 3 無漏洞 = 9）───────────
    {"id": "js01", "language": "JavaScript", "filename": "xss_example.js",
     "has_vulnerability": True, "expected_cwe": ["CWE-79"], "severity": "High"},
    {"id": "js02", "language": "JavaScript", "filename": "sql_node.js",
     "has_vulnerability": True, "expected_cwe": ["CWE-89"], "severity": "Critical"},
    {"id": "js03", "language": "JavaScript", "filename": "proto_pollution.js",
     "has_vulnerability": True, "expected_cwe": ["CWE-1321"], "severity": "High"},
    {"id": "js04", "language": "JavaScript", "filename": "path_traversal.js",
     "has_vulnerability": True, "expected_cwe": ["CWE-22"], "severity": "High"},
    {"id": "ts01", "language": "TypeScript", "filename": "auth_bypass.ts",
     "has_vulnerability": True, "expected_cwe": ["CWE-306"], "severity": "Critical"},
    {"id": "ts02", "language": "TypeScript", "filename": "hardcoded_secret.ts",
     "has_vulnerability": True, "expected_cwe": ["CWE-798"], "severity": "High"},
    {"id": "js05", "language": "JavaScript", "filename": "safe_express.js",
     "has_vulnerability": False, "expected_cwe": [], "severity": None},
    {"id": "ts03", "language": "TypeScript", "filename": "safe_api.ts",
     "has_vulnerability": False, "expected_cwe": [], "severity": None},
    {"id": "js06", "language": "JavaScript", "filename": "safe_dom.js",
     "has_vulnerability": False, "expected_cwe": [], "severity": None},

    # ── Java（5 有漏洞 + 3 無漏洞 = 8）──────────────────────────────
    {"id": "java01", "language": "Java", "filename": "DeserializeEndpoint.java",
     "has_vulnerability": True, "expected_cwe": ["CWE-502"], "severity": "Critical"},
    {"id": "java02", "language": "Java", "filename": "XmlParser.java",
     "has_vulnerability": True, "expected_cwe": ["CWE-611"], "severity": "High"},
    {"id": "java03", "language": "Java", "filename": "SqlBuilder.java",
     "has_vulnerability": True, "expected_cwe": ["CWE-89"], "severity": "Critical"},
    {"id": "java04", "language": "Java", "filename": "FileServlet.java",
     "has_vulnerability": True, "expected_cwe": ["CWE-22"], "severity": "High"},
    {"id": "java05", "language": "Java", "filename": "AccessController.java",
     "has_vulnerability": True, "expected_cwe": ["CWE-862"], "severity": "High"},
    {"id": "java06", "language": "Java", "filename": "SafeUserService.java",
     "has_vulnerability": False, "expected_cwe": [], "severity": None},
    {"id": "java07", "language": "Java", "filename": "SafeFileUpload.java",
     "has_vulnerability": False, "expected_cwe": [], "severity": None},
    {"id": "java08", "language": "Java", "filename": "SafeXmlHandler.java",
     "has_vulnerability": False, "expected_cwe": [], "severity": None},

    # ── C / C++（6 有漏洞 + 3 無漏洞 = 9）──────────────────────────
    {"id": "c01", "language": "C", "filename": "buffer_overflow.c",
     "has_vulnerability": True, "expected_cwe": ["CWE-787"], "severity": "Critical"},
    {"id": "c02", "language": "C", "filename": "use_after_free.c",
     "has_vulnerability": True, "expected_cwe": ["CWE-416"], "severity": "Critical"},
    {"id": "c03", "language": "C", "filename": "oob_read.c",
     "has_vulnerability": True, "expected_cwe": ["CWE-125"], "severity": "High"},
    {"id": "c04", "language": "C", "filename": "format_string.c",
     "has_vulnerability": True, "expected_cwe": ["CWE-134"], "severity": "High"},
    {"id": "cpp01", "language": "C++", "filename": "integer_overflow.cpp",
     "has_vulnerability": True, "expected_cwe": ["CWE-190"], "severity": "High"},
    {"id": "cpp02", "language": "C++", "filename": "dangling_pointer.cpp",
     "has_vulnerability": True, "expected_cwe": ["CWE-416"], "severity": "Critical"},
    {"id": "c05", "language": "C", "filename": "safe_string_ops.c",
     "has_vulnerability": False, "expected_cwe": [], "severity": None},
    {"id": "c06", "language": "C", "filename": "safe_memory.c",
     "has_vulnerability": False, "expected_cwe": [], "severity": None},
    {"id": "cpp03", "language": "C++", "filename": "safe_vector.cpp",
     "has_vulnerability": False, "expected_cwe": [], "severity": None},

    # ── PHP（4 有漏洞 + 3 無漏洞 = 7）───────────────────────────────
    {"id": "php01", "language": "PHP", "filename": "login.php",
     "has_vulnerability": True, "expected_cwe": ["CWE-89"], "severity": "Critical"},
    {"id": "php02", "language": "PHP", "filename": "file_include.php",
     "has_vulnerability": True, "expected_cwe": ["CWE-22"], "severity": "Critical"},
    {"id": "php03", "language": "PHP", "filename": "file_upload.php",
     "has_vulnerability": True, "expected_cwe": ["CWE-434"], "severity": "Critical"},
    {"id": "php04", "language": "PHP", "filename": "xss_output.php",
     "has_vulnerability": True, "expected_cwe": ["CWE-79"], "severity": "High"},
    {"id": "php05", "language": "PHP", "filename": "safe_login.php",
     "has_vulnerability": False, "expected_cwe": [], "severity": None},
    {"id": "php06", "language": "PHP", "filename": "safe_upload.php",
     "has_vulnerability": False, "expected_cwe": [], "severity": None},
    {"id": "php07", "language": "PHP", "filename": "safe_output.php",
     "has_vulnerability": False, "expected_cwe": [], "severity": None},

    # ── Go / Rust / 其他（3 有漏洞 + 2 無漏洞 = 5）────────────────
    {"id": "go01", "language": "Go", "filename": "sql_injection.go",
     "has_vulnerability": True, "expected_cwe": ["CWE-89"], "severity": "Critical"},
    {"id": "go02", "language": "Go", "filename": "cmd_injection.go",
     "has_vulnerability": True, "expected_cwe": ["CWE-78"], "severity": "Critical"},
    {"id": "rs01", "language": "Rust", "filename": "unsafe_block.rs",
     "has_vulnerability": True, "expected_cwe": ["CWE-787"], "severity": "High"},
    {"id": "go03", "language": "Go", "filename": "safe_sql.go",
     "has_vulnerability": False, "expected_cwe": [], "severity": None},
    {"id": "rs02", "language": "Rust", "filename": "safe_memory.rs",
     "has_vulnerability": False, "expected_cwe": [], "severity": None},
]
