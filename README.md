# AI-Driven Code Security Audit System

[繁體中文](README.zh-TW.md) | **English**

A proof-of-concept system that leverages Large Language Models (LLMs) and Retrieval-Augmented Generation (RAG) to automatically detect security vulnerabilities in source code across multiple programming languages.

## Overview

SecureCodeReview combines state-of-the-art LLM capabilities with a curated security knowledge base (CWE, OWASP Top 10, CVE) to provide accurate, context-aware code security audits. The system supports dual LLM backends (OpenAI GPT-4o-mini and Ollama local models) and features a language-aware prompting strategy (Prompt v4) that dynamically adjusts analysis focus based on the detected programming language.

## Key Features

- Multi-language vulnerability detection: Python, JavaScript, TypeScript, Java, C/C++, PHP, Go, Rust, and more
- Dual LLM backend: OpenAI API or Ollama local model (privacy-preserving)
- RAG knowledge base: CWE Top 25, OWASP Top 10, and 50+ real CVE cases from NIST NVD
- Language-aware Prompt v4: tailored analysis strategies per programming language with Self-Critique step
- Multiple input modes: code snippet, file upload, GitHub repository URL, local directory scan
- Real-time progress tracking for directory scans with polling-based UI
- Scan history with HTML report generation
- Severity filtering (Critical / High / Medium / Low)
- Docker Compose one-command deployment

## System Architecture

```
User Input (snippet / file / GitHub URL / directory)
        |
        v
  FastAPI Backend
        |
      +---+---+
      |       |
   RAG        LLM Analyzer
 Retriever    (OpenAI / Ollama)
      |       |
   ChromaDB   Prompt v4
  (CWE/OWASP  (language-aware
    /CVE)      + Self-Critique)
      |       |
      +---+---+
        |
        v
  HTML Report + JSON Results
```

## Prerequisites

- Docker and Docker Compose
- Python 3.11+ (for local development)
- OpenAI API key (or Ollama installed locally)

## Quick Start

### Option 1: Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/boringman1031/AI-Driven-Code-Security-Audit-System.git
cd AI-Driven-Code-Security-Audit-System

# Configure environment
cp .env.example .env
# Edit .env and set OPENAI_API_KEY

# Start with OpenAI backend
./start.sh

# Start with Ollama local model
./start.sh --ollama

# Windows PowerShell
.\start.ps1
.\start.ps1 -Ollama
```

Open http://localhost:8000 in your browser.

### Option 2: Local Development

```bash
pip install -r requirements.txt
cp .env.example .env
# Edit .env

# Ingest knowledge base
python -m backend.rag.ingester

# Optionally fetch CVE data (requires ~40 seconds, public rate limit)
python -m backend.rag.fetch_cve

# Start server
uvicorn backend.main:app --reload --port 8000
```

## Knowledge Base

| Collection | Source                | Entries |
|------------|-----------------------|---------|
| CWE        | MITRE CWE             | 20+     |
| OWASP      | OWASP Top 10 (2021)   | 10      |
| CVE        | NIST NVD API v2.0     | 50+     |

To refresh the CVE knowledge base:

```bash
python -m backend.rag.fetch_cve
python -m backend.rag.ingester --rebuild
```

## Prompt Design (v4)

The system uses a four-generation prompt evolution:

| Version | Key Improvement                                   |
|---------|---------------------------------------------------|
| v1      | Basic vulnerability detection                     |
| v2      | Chain-of-Thought reasoning steps                  |
| v3      | Self-Critique to reduce hallucination             |
| v4      | Language-aware analysis with dynamic focus areas  |

Language-specific analysis focus examples:
- C/C++: memory safety (CWE-787, CWE-416, CWE-125), data flow tracing
- Python/JavaScript: injection attacks (CWE-89, CWE-78), insecure deserialization
- Java: deserialization (CWE-502), XXE (CWE-611), access control
- PHP: file inclusion, arbitrary upload (CWE-434), CSRF

## Evaluation

The system includes a 50-case evaluation framework spanning 6 programming languages:

| Language          | Vulnerable | Safe | Total |
|-------------------|-----------|------|-------|
| Python            | 8         | 4    | 12    |
| JavaScript/TypeScript | 6     | 3    | 9     |
| Java              | 5         | 3    | 8     |
| C/C++             | 6         | 3    | 9     |
| PHP               | 4         | 3    | 7     |
| Go/Rust           | 3         | 2    | 5     |
| **Total**         | **32**    | **18**| **50**|

Target metrics: Precision >= 0.83, Recall >= 0.80, F1 >= 0.82, CWE Match Rate >= 0.80

Run evaluation:

```bash
python -m backend.eval.run_eval --backend openai
python -m backend.eval.limitations
```

## Architectural Limitations

| Limitation         | Description                                         | Mitigation                      |
|--------------------|-----------------------------------------------------|---------------------------------|
| LLM Hallucination  | ~4.2% invalid CWE IDs in findings                  | Self-Critique step (Prompt v3+) |
| Analysis Latency   | GPT-4o-mini: 3-8s/file; Ollama: 45-90s/file        | Async background processing     |
| Token Cost         | ~$0.18 USD per 30-case evaluation                   | Truncation + summary pre-processing |
| Language Bias      | C/C++ F1 ~0.50 vs Python F1 ~0.89                  | Language-aware Prompt v4        |
| Context Window     | 12,000 character truncation per file                | Future: sliding window chunking |
| RAG Precision      | ~1 irrelevant result per Top-4 retrieval            | Future: re-ranker model         |

## Project Structure

```
.
├── backend/
│   ├── analyzer/          # LLM analyzer modules (OpenAI / Ollama)
│   │   ├── language_focus.py  # Prompt v4 language-aware focus
│   │   ├── openai_analyzer.py
│   │   └── ollama_analyzer.py
│   ├── eval/              # Evaluation framework
│   │   ├── ground_truth.py    # 50-case ground truth
│   │   ├── run_eval.py        # Evaluation runner
│   │   └── limitations.py    # Architectural limitation analysis
│   ├── input_handler/     # Code input modules
│   ├── rag/               # Retrieval-Augmented Generation
│   │   ├── fetch_cve.py   # NIST NVD CVE fetcher
│   │   ├── ingester.py    # Knowledge base ingestion
│   │   ├── retriever.py   # Context retrieval
│   │   └── vector_store.py
│   ├── reporter/          # HTML report generation
│   ├── routers/           # FastAPI endpoints
│   └── main.py
├── frontend/              # Web UI (vanilla JS)
├── knowledge/             # CWE and OWASP JSON data
├── templates/             # Jinja2 HTML report template
├── tests/eval/samples/    # 50 evaluation code samples
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── start.sh               # Linux/macOS startup script
└── start.ps1              # Windows PowerShell startup script
```

## API Endpoints

| Method | Endpoint                     | Description                          |
|--------|------------------------------|--------------------------------------|
| POST   | /api/scan                    | Scan code snippet or GitHub URL      |
| POST   | /api/scan/upload             | Upload and scan a single file        |
| POST   | /api/scan/directory          | Submit directory scan (async)        |
| GET    | /api/scan/{scan_id}/status   | Poll directory scan progress         |
| GET    | /api/reports                 | List all scan reports                |
| GET    | /api/reports/{scan_id}       | Retrieve HTML report                 |
| GET    | /health                      | Health check                         |
| GET    | /docs                        | Interactive API documentation        |

## Technology Stack

- Backend: FastAPI, LangChain, ChromaDB
- LLM: OpenAI GPT-4o-mini / Ollama (codellama:7b)
- RAG: ChromaDB vector store, sentence-transformers embeddings
- Frontend: Vanilla HTML/CSS/JavaScript
- Containerization: Docker, Docker Compose

## License

This project is developed as a proof-of-concept for academic purposes.
