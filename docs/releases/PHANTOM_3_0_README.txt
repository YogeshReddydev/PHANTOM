PHANTOM 3.0 update — live process observation, file integrity, event timeline

BACK UP your complete existing PHANTOM folder first. Stop the server with Ctrl+C.

Extract this ZIP into the EXISTING PHANTOM folder and allow replacement. It replaces:
  app/main.py
  app/database.py
  app/static/index.html
  app/static/app.js
  app/static/styles.css
and adds:
  app/live_monitor.py
  app/file_integrity.py

It deliberately does NOT replace:
  app/detection.py
  app/monitor.py
  app/local_ai.py
  app/config.py
  .env
  .venv
  data/phantom.db

The database update is additive: it creates a security_events table and preserves existing scans.

Restart in PowerShell from the PHANTOM folder:
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
  .\.venv\Scripts\Activate.ps1
  python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

Keep Ollama running in its own terminal. Open http://127.0.0.1:8000 and press Ctrl+F5.

Features:
- Process snapshot refreshes every 5 seconds (read-only).
- Process events are recorded when first observed after monitoring starts.
- File integrity computes SHA-256 and attempts Windows Authenticode status.
- Event timeline stores scan, newly observed process, and file-hash events in SQLite.
- AI chat remains local through Ollama.

Notes:
- Newly observed processes are not automatically suspicious.
- The process monitor records newly observed PID+creation-time pairs, not every process event.
- SHA-256 is an identity/checksum, not a safety verdict.
- Authenticode status is a trust signal, not proof that a file is safe.
- File inspection is limited to 100 MB and does not modify files.
