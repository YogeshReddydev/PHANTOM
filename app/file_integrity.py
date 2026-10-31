import hashlib, os, subprocess, json

MAX_FILE_BYTES=100*1024*1024

def inspect_file(path):
    """Hash a user-selected local file; never modifies it."""
    if not path or not os.path.isabs(path):
        return {"ok":False,"error":"Enter an absolute file path."}
    full=os.path.abspath(path)
    if not os.path.isfile(full):
        return {"ok":False,"error":"File not found or path is not a regular file."}
    size=os.path.getsize(full)
    if size>MAX_FILE_BYTES:
        return {"ok":False,"error":"For this MVP, files larger than 100 MB are not scanned."}
    digest=hashlib.sha256()
    with open(full,"rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):
            digest.update(chunk)
    result={"ok":True,"file_name":os.path.basename(full),"path":full,
            "size_bytes":size,"sha256":digest.hexdigest(),
            "signature_status":"Not checked","signature_note":"SHA-256 identifies file content; it does not establish that a file is safe."}
    if os.name=="nt":
        # Pass the path over stdin; do not interpolate user input into a PowerShell command.
        script="$p = [Console]::In.ReadLine(); $s = Get-AuthenticodeSignature -LiteralPath $p; [pscustomobject]@{Status=[string]$s.Status;Signer=$(if($s.SignerCertificate){$s.SignerCertificate.Subject}else{''})} | ConvertTo-Json -Compress"
        try:
            proc=subprocess.run(["powershell.exe","-NoProfile","-NonInteractive","-Command",script],
                                input=full+"\n",capture_output=True,text=True,timeout=15,
                                creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
            if proc.returncode==0 and proc.stdout.strip():
                data=json.loads(proc.stdout.strip().splitlines()[-1])
                result["signature_status"]=data.get("Status","Unknown")
                result["signer"]=data.get("Signer") or None
            else:
                result["signature_note"]="Windows signature query did not return a result."
        except (subprocess.SubprocessError, OSError, ValueError):
            result["signature_note"]="Windows signature status could not be checked; SHA-256 is still available."
    return result
