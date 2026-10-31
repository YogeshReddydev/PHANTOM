# PHANTOM — The Ghost in Your System

A Windows 11, local-first cybersecurity MVP. It takes read-only process snapshots, applies transparent heuristic checks, stores findings in SQLite, and can ask a local Ollama model to explain findings.

**Safety note:** This is a demonstration tool, not antivirus software. Heuristic matches are not proof of malware. PHANTOM does not kill processes, delete files, execute shell commands, or upload telemetry.

## Requirements
- Windows 11
- Python 3.10+ (Python 3.11 recommended)
- Optional: Ollama for local AI explanations

## Install
Open PowerShell in the extracted folder:

```powershell
py -3.11 -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

## Optional local AI
Install Ollama from https://ollama.com/download/windows. Then run:

```powershell
ollama pull qwen2.5:3b
ollama serve
```

Keep Ollama running in another terminal. Intel integrated graphics is fine; the small model can run on CPU, though responses may be slower. The scanner works without Ollama.

## Start PHANTOM
In the activated environment:

```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000. Stop with Ctrl+C.

## Demo
1. Click **Scan My System**.
2. Review process count and heuristic findings.
3. Click **Explain with Local AI** on a finding (requires Ollama).
4. Show the scan history stored in `data/phantom.db`.
5. Disconnect the internet and repeat the scan. Core monitoring works offline.

## Detection rules
The MVP flags selected command-line indicators, certain dual-use tool names, and executables running from temporary/download directories. These signals can match legitimate software. Verify every result.

## Privacy
- The server binds to 127.0.0.1, not your network.
- Scan history is stored locally in SQLite.
- Only limited metadata for the selected finding is sent to your local Ollama endpoint.
- No automatic remediation is included.

## Troubleshooting
- If `py` is not found, install Python from https://www.python.org/downloads/windows and enable PATH integration.
- If activation is blocked, run the process-scoped `Set-ExecutionPolicy` command above.
- If Ollama is unavailable, scanning still works.
- If port 8000 is busy, use `--port 8010` and open http://127.0.0.1:8010.
