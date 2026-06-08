from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from backend.routers.scan import router as scan_router
from backend.rag.ingester import run_ingestion


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 啟動時確保知識庫已完成攝入
    try:
        run_ingestion(rebuild=False)
    except Exception as e:
        print(f"[警告] 知識庫攝入失敗: {e}。系統仍可運作，但 RAG 上下文將為空。")
    yield


app = FastAPI(
    title="SecureCodeReview API",
    description="AI 驅動的程式碼安全審查工具",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(scan_router)

app.mount("/static", StaticFiles(directory="frontend/static"), name="static")


@app.get("/", include_in_schema=False)
async def root():
    return FileResponse("frontend/index.html")


@app.get("/health")
async def health():
    return {"status": "ok"}
