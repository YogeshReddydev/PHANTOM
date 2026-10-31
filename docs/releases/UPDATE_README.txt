PHANTOM AI Investigation Center update

1. Back up your existing PHANTOM folder first.
2. Stop the PHANTOM server with Ctrl+C.
3. Extract this ZIP into the EXISTING PHANTOM folder and allow replacement.
4. Do not replace detection.py, monitor.py, database.py, .env, or data/phantom.db.
5. Start PowerShell in the PHANTOM folder and run:

   .\.venv\Scripts\Activate.ps1
   python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

6. Keep Ollama running in its own terminal.
7. Open http://127.0.0.1:8000 and press Ctrl+F5.
8. Scroll below Scan History to AI Investigation Center.

The chat sends the question and optional latest-scan summary to your local Ollama
server only. It does not execute commands or modify your system.
