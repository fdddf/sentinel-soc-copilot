from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

QDRANT_URL = os.getenv("VECTOR_DB_URL", "http://localhost:6333")
DENSE_MODEL = os.getenv("EMBEDDING_MODEL", "BAAI/bge-small-en-v1.5")
SPARSE_MODEL = "Qdrant/bm25"

KB_COLLECTION = "threat_kb"
LOG_COLLECTION = "endpoint_logs"

COGNEE_SYSTEM_DIR = ROOT / "storage" / "cognee_system"
COGNEE_DATA_DIR = ROOT / "storage" / "cognee_data"
CACHE_DIR = ROOT / "storage" / "cache"

# cognee defaults these to its own package directory inside .venv, and logs the
# default at import time -- before setup_cognee() can override it. Set them in the
# env first so the startup log matches where the data actually goes.
os.environ.setdefault("SYSTEM_ROOT_DIRECTORY", str(COGNEE_SYSTEM_DIR))
os.environ.setdefault("DATA_ROOT_DIRECTORY", str(COGNEE_DATA_DIR))


def setup_cognee():
    import cognee
    from cognee_community_vector_adapter_qdrant import register  # noqa: F401  registers "qdrant"

    cognee.config.system_root_directory(str(COGNEE_SYSTEM_DIR))
    cognee.config.data_root_directory(str(COGNEE_DATA_DIR))
    return cognee
