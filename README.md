# Powershell_code_encrtpyer_and_executer

Single-file Python generator that encrypts a PowerShell `.ps1` payload with RSA-OAEP-SHA256 + AES-GCM-256 and emits a self-contained Python executor. Running the generated executor fetches the private PEM, verifies system requirements, decrypts the payload, executes it with PowerShell, and securely removes temp artifacts.

---

## Quick facts

* Generator filename: `Powershell_code_encrtpyer_and_executer.py`
* Default generated executor: `payload_exec.py`
* Crypto: RSA-OAEP-SHA256 (key encapsulation) + AES-GCM-256 (content encryption)
* Dependencies: Python 3.8+; `requests`, `pycryptodome`
* Intended use: controlled, authorized environments only

---

## Table of contents

* Requirements
* Install
* Files in repository
* Generate executor (end-to-end)
* Run generated executor
* How it works (brief)
* Security notes & operational guidance
* Troubleshooting
* Testing checklist
* License

---

## Requirements

* Python 3.8+ (3.10+ recommended)
* `pip`
* PowerShell present on target Windows host (`pwsh` or `powershell.exe`) and on `PATH` for execution.
* Public/private RSA key pair in PEM format:

  * Public PEM: `-----BEGIN PUBLIC KEY-----` (X.509 / SubjectPublicKeyInfo)
  * Private PEM: `-----BEGIN PRIVATE KEY-----` (PKCS#8)
* Private PEM must be reachable via a raw HTTPS URL by the generated executor.

---

## Install

```bash
pip install requests pycryptodome
```

---

## Files

* `Powershell_code_encrtpyer_and_executer.py` — generator. Prompts for inputs and writes the generated executor Python file (default `payload_exec.py`).
* `payload_exec.py` — example name for the generated executor. It is created by the generator and contains the encrypted package plus embedded private-key URL.
* Your plaintext PowerShell payload `.ps1` — user-supplied.

---

## Generate executor (end-to-end)

1. Prepare RSA key pair (example using OpenSSL):

```bash
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in private.pem -pubout -out public.pem
```

2. Host the PEMs so they are reachable via raw HTTPS URLs. Example local test:

```bash
# in folder with public.pem private.pem
python -m http.server 8000
# public URL: http://localhost:8000/public.pem
# private URL: http://localhost:8000/private.pem
```

3. Run generator:

```bash
python Powershell_code_encrtpyer_and_executer.py
```

Follow the prompts:

* `Public PEM URL (raw HTTPS)` → e.g. `https://raw.githubusercontent.com/user/repo/main/public.pem`
* `Private PEM URL (will be embedded in generated file)` → e.g. `https://raw.githubusercontent.com/user/repo/main/private.pem`
* `Path to PowerShell .ps1 to encrypt` → path to local `.ps1` payload
* `Output filename (default payload_exec.py)` → name for generated executor

4. Generator writes the output file (e.g. `payload_exec.py`).

---

## Run generated executor

On the target machine (must have Python and PowerShell):

```bash
pip install requests pycryptodome
python payload_exec.py
```

Behavior:

* Fetches the private PEM from embedded URL (or prompts if missing).
* Verifies host: Windows OS, x64, >= 4 logical CPUs, >= 4 GB RAM.
* If checks fail, attempts best-effort secure deletion of itself and exits.
* Decrypts the embedded package and writes the decrypted PowerShell to a temp `.ps1`.
* Executes PowerShell: `pwsh|powershell -NoProfile -ExecutionPolicy Bypass -File <temp.ps1>`.
* Securely deletes temporary `.ps1`.

---

## How it works (brief)

1. Generator fetches public PEM and reads local `.ps1` payload.
2. Generates random AES-256 key and 12-byte nonce.
3. Encrypts payload with AES-GCM.
4. Encrypts AES key with RSA-OAEP-SHA256 using public key.
5. Packages `RsaKeyEnc`, `Nonce`, `Tag`, `Cipher` into JSON, base64-encodes it and embeds into generated Python executor together with the provided private-key URL.
6. Executor fetches private PEM at runtime, decrypts AES key with RSA private key, decrypts payload with AES-GCM, and executes.

---

## Security notes & operational guidance

* **Only use in authorized, controlled environments.** This tool executes arbitrary PowerShell on the host.
* **Protect the private key URL.** The executor fetches the private PEM at runtime from the embedded URL. If that URL is public, the private key is exposed. Host the private key on a restricted server or use protected storage.
* Use **HTTPS raw links** (e.g., `raw.githubusercontent.com`) not GitHub HTML pages. The generator sanitizes common GitHub URLs but prefer raw links.
* Use appropriate key sizes (2048 minimum; 3072+ or 4096 recommended for high security).
* AES-GCM tag verification ensures ciphertext integrity. RSA OAEP-SHA256 is used for key encapsulation.
* Secure deletion is best-effort. Filesystems, backups, and swap may retain data. For sensitive payloads use additional host-level controls.
* Review payloads and generated executors before deployment. Keep private keys rotated and access-controlled.

---

## Troubleshooting

* `ModuleNotFoundError` → run `pip install requests pycryptodome`.
* `Failed to fetch public PEM` → ensure URL is raw PEM and reachable. Test with `curl` or your browser.
* `Decryption failed` → likely key mismatch or corrupted package. Ensure the public key used to encrypt matches the private key URL used to decrypt.
* `PowerShell not found` → ensure `powershell.exe` or `pwsh` is in `PATH`.
* `System check failed` → executor requires Windows x64 with >=4 CPUs and >=4GB RAM.
* `Generated file contains braces errors` → do not manually edit the generated template placeholders.

---

## Testing checklist

1. Create simple `test.ps1`:

```powershell
Write-Output "hello from ps1"
```

2. Generate `payload_exec.py` with public/private PEM and `test.ps1`.
3. Run `python payload_exec.py` on a Windows x64 machine that meets checks. Confirm output.
4. Change private URL to invalid value. Executor should error fetching private key.
5. Run on non-Windows machine. Executor should fail system check and attempt cleanup.

---

## License

Choose a license appropriate for your project. Example: MIT.

---

## Sample commands

```bash
pip install requests pycryptodome
python Powershell_code_encrtpyer_and_executer.py
python payload_exec.py
```

---

## Contact / notes

Use responsibly. This repository contains code that executes remote-controlled payloads. Validate legal and policy constraints before use.
