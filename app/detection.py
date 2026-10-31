
import ntpath

SUSPICIOUS_NAMES = {
    "mimikatz.exe",
    "psexec.exe",
    "procdump.exe",
    "ncat.exe",
    "netcat.exe",
    "nc.exe",
    "rundll32.exe",
    "regsvr32.exe",
}

SUSPICIOUS_TOKENS = (
    " -enc ",
    " -encodedcommand",
    "frombase64string",
    "downloadstring(",
    " -windowstyle hidden",
    " -w hidden",
)


def analyze(processes):
    findings = []

    for p in processes:
        name = (p.get("name") or "").lower()
        exe = ntpath.normcase(
            ntpath.normpath(p.get("exe") or "")
        )
        cmd = " " + (p.get("cmdline") or "").lower() + " "

        reasons = []
        severity = "low"

        if name in SUSPICIOUS_NAMES:
            reasons.append(
                f"Process name matches a dual-use security tool: {name}"
            )
            severity = "medium"

        if any(token in cmd for token in SUSPICIOUS_TOKENS):
            reasons.append(
                "Command line contains an encoded, hidden, "
                "or download-related execution indicator"
            )
            severity = "high"

        is_venv = any(
            part in ("venv", ".venv")
            for part in exe.split("\\")
        )

        is_temp = (
            "\\appdata\\local\\temp\\" in exe
            or "\\windows\\temp\\" in exe
        )

        is_direct_download = (
            ntpath.basename(ntpath.dirname(exe)) == "downloads"
        )

        if not is_venv and (is_temp or is_direct_download):
            reasons.append(
                "Executable is running from a temporary "
                "or directly user-accessible Downloads location"
            )

            if severity == "low":
                severity = "medium"

        if reasons:
            findings.append({
                "pid": p.get("pid"),
                "process_name": p.get("name"),
                "severity": severity,
                "title": f"Review process: {p.get('name') or 'unknown'}",
                "reasons": reasons,
                "executable": p.get("exe") or "",
                "command_line": p.get("cmdline") or "",
                "recommendation": (
                    "Verify the file location, publisher, "
                    "digital signature, and expected activity."
                ),
            })

    return findings
