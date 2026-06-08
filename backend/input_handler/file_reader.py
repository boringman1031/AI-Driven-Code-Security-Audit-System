from dataclasses import dataclass

MAX_FILE_SIZE_BYTES = 512 * 1024  # 512 KB


@dataclass
class CodeFile:
    filename: str
    content: str


def read_uploaded_bytes(filename: str, content_bytes: bytes) -> CodeFile:
    if len(content_bytes) > MAX_FILE_SIZE_BYTES:
        raise ValueError(
            f"上傳檔案過大（{len(content_bytes):,} bytes），最大支援 {MAX_FILE_SIZE_BYTES:,} bytes"
        )
    content = content_bytes.decode("utf-8", errors="replace")
    return CodeFile(filename=filename, content=content)
