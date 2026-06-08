from pathlib import Path
from backend.input_handler.file_reader import CodeFile, MAX_FILE_SIZE_BYTES

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".c", ".cpp", ".cc", ".h",
    ".cs", ".go", ".rb", ".php",
    ".swift", ".kt", ".rs", ".sh", ".bash",
}

MAX_FILES_PER_SCAN = 50


def walk_directory(base_dir: str) -> list[CodeFile]:
    """
    遞迴掃描目錄，回傳所有支援語言的程式碼檔案。
    最多回傳 MAX_FILES_PER_SCAN 個檔案。
    """
    base_path = Path(base_dir).resolve()
    if not base_path.is_dir():
        raise NotADirectoryError(f"找不到目錄: {base_dir}")

    files: list[CodeFile] = []
    for file_path in sorted(base_path.rglob("*")):
        if not file_path.is_file():
            continue
        if file_path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue
        if file_path.stat().st_size > MAX_FILE_SIZE_BYTES:
            continue
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            rel_name = str(file_path.relative_to(base_path))
            files.append(CodeFile(filename=rel_name, content=content))
        except OSError:
            continue
        if len(files) >= MAX_FILES_PER_SCAN:
            break

    return files
