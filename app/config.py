import os
from dotenv import load_dotenv

load_dotenv()
DB_PATH = os.getenv("PHANTOM_DB_PATH", "data/phantom.db")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
MAX_PROCESSES = int(os.getenv("MAX_PROCESSES", "2000"))
