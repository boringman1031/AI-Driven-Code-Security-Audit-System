import chromadb
from pathlib import Path


class VectorStore:
    def __init__(self, chroma_dir: str):
        Path(chroma_dir).mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(path=chroma_dir)
        self._collections: dict = {}

    def _get_collection(self, name: str):
        if name not in self._collections:
            self._collections[name] = self._client.get_or_create_collection(name=name)
        return self._collections[name]

    def collection_count(self, name: str) -> int:
        return self._get_collection(name).count()

    def delete_collection(self, name: str) -> None:
        self._client.delete_collection(name=name)
        self._collections.pop(name, None)

    def add_documents(
        self,
        collection_name: str,
        documents: list[str],
        metadatas: list[dict],
        ids: list[str],
    ) -> None:
        self._get_collection(collection_name).add(
            documents=documents,
            metadatas=metadatas,
            ids=ids,
        )

    def query(self, collection_name: str, query_text: str, n_results: int = 5) -> list[str]:
        col = self._get_collection(collection_name)
        count = col.count()
        if count == 0:
            return []
        results = col.query(query_texts=[query_text], n_results=min(n_results, count))
        return results["documents"][0] if results["documents"] else []
