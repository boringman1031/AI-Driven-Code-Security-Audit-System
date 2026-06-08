from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # LLM 後端
    llm_backend: str = "openai"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"

    # Ollama
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "codellama:7b"

    # GitHub
    github_token: str = ""

    # 路徑
    reports_dir: str = "data/reports"
    chroma_dir: str = "data/chromadb"
    knowledge_dir: str = "knowledge"

    model_config = {"env_file": ".env"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
