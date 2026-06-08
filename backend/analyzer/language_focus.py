"""
語言感知 Prompt 輔助模組（Prompt v4）。

根據檔案名稱偵測程式語言，回傳對應的分析重點提示文字。
"""

from pathlib import Path

# 副檔名 → 語言標準名稱
_EXT_MAP: dict[str, str] = {
    ".c":    "C",
    ".h":    "C",
    ".cpp":  "C++",
    ".cxx":  "C++",
    ".cc":   "C++",
    ".hpp":  "C++",
    ".py":   "Python",
    ".js":   "JavaScript",
    ".mjs":  "JavaScript",
    ".cjs":  "JavaScript",
    ".ts":   "TypeScript",
    ".tsx":  "TypeScript",
    ".jsx":  "JavaScript",
    ".java": "Java",
    ".kt":   "Kotlin",
    ".php":  "PHP",
    ".rb":   "Ruby",
    ".go":   "Go",
    ".rs":   "Rust",
    ".cs":   "C#",
    ".swift":"Swift",
    ".sh":   "Shell",
    ".bash": "Shell",
}

# 語言 → 分析策略文字
_LANGUAGE_FOCUS: dict[str, str] = {
    "C": """\
【C 語言分析重點】
- 記憶體安全：緩衝區溢位（CWE-787）、越界讀取（CWE-125）、Use-After-Free（CWE-416）
- 整數溢位/截斷（CWE-190、CWE-191）導致的記憶體分配錯誤
- 格式字串攻擊（CWE-134）
- 資料流追蹤路徑：malloc → 操作 → free，確認是否有 double-free 或 use-after-free
- 不安全的字串函數：gets、strcpy、sprintf（應改用 fgets、strncpy、snprintf）""",

    "C++": """\
【C++ 語言分析重點】
- 記憶體安全：緩衝區溢位（CWE-787）、Use-After-Free（CWE-416）、懸掛指標
- RAII 違規與手動記憶體管理風險
- 整數溢位（CWE-190）
- 不安全的類型轉換（static_cast vs reinterpret_cast）
- 競態條件（CWE-362）與執行緒安全""",

    "Python": """\
【Python 分析重點】
- 注入攻擊：SQL 注入（CWE-89）、命令注入（CWE-78）
- 程式碼執行：eval/exec 使用（CWE-94）、不安全反序列化（pickle）
- 路徑穿越（CWE-22）：open() 使用者輸入路徑未驗證
- SSRF：requests 呼叫使用者輸入的 URL（CWE-918）
- 硬編碼機敏資料（CWE-798）：API Key、密碼、Token
- 依賴套件安全：已知 CVE 的函式庫版本""",

    "JavaScript": """\
【JavaScript/TypeScript 分析重點】
- XSS（CWE-79）：innerHTML、dangerouslySetInnerHTML、document.write 使用使用者輸入
- 原型污染（Prototype Pollution）：動態設定屬性
- 注入攻擊：eval/Function()、SQL 注入（後端 Node.js）
- 不安全的反序列化（CWE-502）：JSON.parse 後直接使用
- Path Traversal（CWE-22）：fs 模組使用使用者路徑
- 硬編碼機敏資料（CWE-798）""",

    "TypeScript": """\
【TypeScript 分析重點】
- XSS（CWE-79）：innerHTML、dangerouslySetInnerHTML 使用使用者輸入
- 類型斷言繞過（as any）導致的執行時錯誤
- 注入攻擊：eval/Function()、SQL 注入（ORM 原始查詢）
- 不安全的反序列化（CWE-502）
- CSRF 與身份驗證缺失（CWE-352、CWE-306）""",

    "Java": """\
【Java 分析重點】
- 不安全反序列化（CWE-502）：ObjectInputStream.readObject()
- XML 外部實體注入（CWE-611）：未禁用 XXE 的 XML 解析器
- 存取控制缺失（CWE-306、CWE-862）
- SQL 注入（CWE-89）：字串拼接 SQL，未使用 PreparedStatement
- 路徑穿越（CWE-22）：File 物件使用使用者輸入
- Spring 特定風險：Mass Assignment、OGNL 注入""",

    "Kotlin": """\
【Kotlin 分析重點】
- 類同 Java：反序列化（CWE-502）、XXE（CWE-611）
- Nullable 未處理導致 NullPointerException（Android 崩潰攻擊面）
- Android 特定：Intent 注入、WebView 不安全設定（CWE-749）
- 硬編碼憑證（CWE-798）""",

    "PHP": """\
【PHP 分析重點】
- SQL 注入（CWE-89）：字串拼接查詢，未使用 PDO Prepared Statement
- 路徑穿越（CWE-22）：include/require 使用使用者輸入
- 任意檔案上傳（CWE-434）：未驗證 MIME 類型與副檔名
- XSS（CWE-79）：echo/print 未過濾使用者輸入（應用 htmlspecialchars）
- CSRF（CWE-352）：表單無 CSRF Token
- 遠端程式執行：eval/preg_replace /e 修飾符（已廢棄）""",

    "Ruby": """\
【Ruby 分析重點】
- 命令注入（CWE-78）：system/exec/backtick 使用使用者輸入
- SQL 注入（CWE-89）：ActiveRecord 原始查詢字串插值
- 不安全反序列化（CWE-502）：Marshal.load 使用者資料
- 路徑穿越（CWE-22）
- 大量賦值（Mass Assignment）：params.permit 不完整""",

    "Go": """\
【Go 分析重點】
- SQL 注入（CWE-89）：fmt.Sprintf 拼接 SQL
- 命令注入（CWE-78）：exec.Command 使用使用者輸入
- 路徑穿越（CWE-22）：filepath.Join 未驗證
- 競態條件（CWE-362）：goroutine 共享狀態未加鎖
- 錯誤忽略：_ 丟棄 error 回傳值""",

    "Rust": """\
【Rust 分析重點】
- unsafe 區塊的記憶體安全問題
- 整數溢位（debug 模式 panic，release 模式截斷）
- 不安全的 FFI 呼叫
- 競態條件（使用 unsafe 繞過 borrow checker）
- 命令注入（CWE-78）：std::process::Command 使用使用者輸入""",

    "C#": """\
【C# 分析重點】
- 不安全反序列化（CWE-502）：BinaryFormatter、XmlSerializer 使用者資料
- SQL 注入（CWE-89）：字串拼接 SQL，未使用參數化查詢
- 路徑穿越（CWE-22）：File/Directory 操作使用使用者輸入
- LDAP 注入（CWE-90）
- ASP.NET 特定：ViewState 未加密、CSRF 缺失""",

    "Shell": """\
【Shell Script 分析重點】
- 命令注入（CWE-78）：未引號包裹的變數展開
- 路徑穿越（CWE-22）：eval 使用使用者輸入
- 不安全的臨時檔案（CWE-377）：/tmp 競態
- 環境變數注入（CWE-454）
- 特殊字元未逸脫（; && || | > < 等）""",
}

_GENERIC_FOCUS = """\
【通用分析重點】
- 注入攻擊：SQL、命令、LDAP、XPath 等各類注入（CWE-89、CWE-78）
- 身份驗證與存取控制缺失（CWE-306、CWE-862）
- 敏感資料外洩：硬編碼機密、明文傳輸（CWE-798、CWE-312）
- 不安全的隨機數生成（CWE-330）
- 錯誤處理洩漏系統資訊（CWE-209）"""


def detect_language(filename: str) -> str:
    """從檔案名稱偵測程式語言，未知回傳空字串。"""
    ext = Path(filename).suffix.lower()
    return _EXT_MAP.get(ext, "")


def get_language_focus(filename: str) -> str:
    """取得針對該語言的分析重點提示文字。"""
    lang = detect_language(filename)
    return _LANGUAGE_FOCUS.get(lang, _GENERIC_FOCUS)
