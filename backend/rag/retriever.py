from backend.rag.vector_store import VectorStore


class Retriever:
    def __init__(self, vector_store: VectorStore):
        self._vs = vector_store

    def get_context(self, code: str, n_results: int = 4) -> str:
        cwe_docs = self._vs.query("cwe", code, n_results)
        owasp_docs = self._vs.query("owasp", code, n_results)
        cve_docs = self._vs.query("cve", code, 3)

        parts: list[str] = []
        if cwe_docs:
            parts.append("### 相關 CWE 弱點分類:\n" + "\n---\n".join(cwe_docs))
        if owasp_docs:
            parts.append("### 相關 OWASP Top 10 項目:\n" + "\n---\n".join(owasp_docs))
        if cve_docs:
            parts.append("### 相關 CVE 真實案例:\n" + "\n---\n".join(cve_docs))

        return "\n\n".join(parts)
