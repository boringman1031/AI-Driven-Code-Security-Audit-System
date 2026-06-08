"""
GitHub Repository 程式碼抓取器。
支援格式: https://github.com/{owner}/{repo}[/tree/{branch}]
"""
import re
import httpx
from backend.input_handler.file_reader import CodeFile, MAX_FILE_SIZE_BYTES
from backend.input_handler.directory_walker import SUPPORTED_EXTENSIONS
from backend.config import get_settings

_GITHUB_API = "https://api.github.com"
_MAX_FILES = 30

_URL_RE = re.compile(
    r"https?://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)"
    r"(?:/tree/(?P<branch>[^/?#]+))?"
)


def _headers() -> dict:
    settings = get_settings()
    h = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if settings.github_token:
        h["Authorization"] = f"Bearer {settings.github_token}"
    return h


def _default_branch(owner: str, repo: str, client: httpx.Client) -> str:
    resp = client.get(f"{_GITHUB_API}/repos/{owner}/{repo}", headers=_headers())
    resp.raise_for_status()
    return resp.json().get("default_branch", "main")


def fetch_github_repo(url: str) -> list[CodeFile]:
    match = _URL_RE.match(url.strip())
    if not match:
        raise ValueError(
            "無效的 GitHub URL。格式應為 https://github.com/owner/repo"
        )

    owner = match.group("owner")
    repo = match.group("repo")

    with httpx.Client(timeout=30.0) as client:
        branch = match.group("branch") or _default_branch(owner, repo, client)

        tree_url = (
            f"{_GITHUB_API}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
        )
        resp = client.get(tree_url, headers=_headers())
        resp.raise_for_status()
        tree = resp.json()

    blobs = [
        item for item in tree.get("tree", [])
        if item["type"] == "blob"
        and any(item["path"].endswith(ext) for ext in SUPPORTED_EXTENSIONS)
        and item.get("size", 0) <= MAX_FILE_SIZE_BYTES
    ][:_MAX_FILES]

    files: list[CodeFile] = []
    with httpx.Client(timeout=30.0) as client:
        for blob in blobs:
            raw_url = (
                f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{blob['path']}"
            )
            resp = client.get(raw_url, headers=_headers())
            if resp.status_code == 200:
                files.append(CodeFile(filename=blob["path"], content=resp.text))

    return files
