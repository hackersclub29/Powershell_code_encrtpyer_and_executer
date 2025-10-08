# README — Powershell_code_encrtpyer_and_executer (encryptor → executable generator)

Short: a single-file Python tool that encrypts a PowerShell `.ps1` payload with RSA-OAEP-SHA256 + AES-GCM-256 and emits a self-contained Python executor. Running the generated executor fetches the private PEM, verifies host requirements, decrypts the payload, runs it in PowerShell, and securely removes temp artifacts.

---

## Table of contents

* Requirements
* Files
* Installation
* Quick example (end-to-end)
* Detailed usage (generator)
* Detailed usage (generated executor)
* Design & crypto summary
* Security notes & operational guidance
* Troubleshooting
* Tests
* License

---

## Requirements

* Python 3.8+ (3.10+ recommended)
* `pip`
* Python packages:

```
pip install requests pycryptodome
```

* PowerShell available in `PATH` on target Windows host (`pwsh` or `powershell.exe`).
* RSA key pair in PEM format (public PEM for encryptor, private PEM accessible via HTTPS raw URL for the executor).

---

## Files

* `pyscripty.py` — generator. Prompts for inputs and writes the generated executor Python file (default `payload_exec.py`).
* `payload_exec.py` (generated) — self-contained runtime: fetch private PEM, check system, decrypt, run `.ps1`, cleanup.
* Your plaintext PowerShell payload `.ps1` — user-supplied.

---

## Installation

1. Clone repository or copy files.
2. Install dependencies:

```bash
pip install requests pycryptodome
```

---

## Quick example (end-to-end)

1. Generate RSA keys (example with OpenSSL):

```bash
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in private.pem -pubout -out public.pem
```

2. Host `public.pem` and `private.pem` using a raw HTTPS URL (S3, GitHub raw, internal server). Example local test:

```bash
python -m http.server 8000
# public: http://localhost:8000/public.pem
# private: http://localhost:8000/private.pem
```

3. Run generator:

```bash
python pyscripty.py
# follow prompts:
#  - Public PEM URL (raw)
#  - Private PEM URL (raw) — embedded in generated file
#  - Path to .ps1 to encrypt (local)
#  - Output filename (default payload_exec.py)
```

4. Run generated executor on the target Windows host:

```bash
python payload_exec.py
```

---

## Detailed usage — generator (`pyscripty.py`)

1. Start:

```
python pyscripty.py
```

2. Enter:

* **Public PEM URL**: raw HTTPS link to `public.pem`.
* **Private PEM URL**: raw HTTPS link to `private.pem` (this URL is embedded in the generated executor).
* **Path to .ps1**: local PowerShell script to encrypt.
* **Output filename**: filename for the generated Python executor (default `payload_exec.py`).

3. Result: a single-file Python executor containing the encrypted package and the embedded `PrivateKeyUrl`.

---

## Detailed usage — generated executor (`payload_exec.py`)

1. Ensure dependencies installed on the machine that will run the executor:

```
pip install requests pycryptodome
```

2. Run:

```
python payload_exec.py
```

Behavior:

* Fetches private PEM from embedded `PRIVATE_KEY_URL` (or prompts if missing).
* Verifies host: Windows OS, x64, >= 4 logical CPUs, >= 4 GB RAM.
* If checks fail, attempts to securely delete itself and exits.
* Decrypts payload (RSA-OAEP-SHA256 decrypt of AES key + AES-GCM decryption of payload).
* Writes decrypted `.ps1` to secure temp file, executes with PowerShell via:

  ```
  pwsh|powershell -NoProfile -ExecutionPolicy Bypass -File <temp.ps1>
  ```
* Securely wipes and removes the temp `.ps1`.

---

## Design & crypto summary

* Hybrid approach: RSA-OAEP-SHA256 encrypts AES-256 key. AES-GCM (nonce 12 bytes, tag 16 bytes) encrypts payload.
* Encrypted package stored as compact JSON then base64-embedded in generated Python file.
* Uses `pycryptodome` (`RSA.import_key`, `PKCS1_OAEP`, `AES.MODE_GCM`).
* Private key is fetched at runtime via HTTPS raw URL. The private key must match the public PEM used during encryption.

---

## Security notes & operational guidance

* **Protect private key**. The executor fetches the private PEM via URL. If that URL is public, rotate keys immediately.
* Use HTTPS raw links only. Do not supply GitHub HTML pages; generator sanitizes some GitHub URL patterns to raw links.
* Verify PEM format: `-----BEGIN PRIVATE KEY-----` (PKCS#8) and `-----BEGIN PUBLIC KEY-----` (X.509) work.
* Running generated executor gives the runtime power to execute arbitrary PowerShell payloads. Use only in trusted, controlled environments.
* The script attempts secure deletion by zeroing files before unlinking. This is best-effort and depends on filesystem semantics.
* Audit network connectivity and ensure the private PEM URL is available only to intended hosts.

---

## Troubleshooting

* **Missing deps**: `ModuleNotFoundError` → `pip install requests pycryptodome`.
* **PEM import fails**: Ensure raw PEM content (not HTML) and correct headers/footers. Use raw.githubusercontent.com links or convert keys with OpenSSL.
* **Decryption failed**: Usually public/private key mismatch or corrupted payload.
* **PowerShell not found**: Ensure `pwsh` or `powershell.exe` in `PATH`.
* **System check failed**: Verify OS is Windows and system meets architecture/CPU/RAM requirements.
* **Generated file error about braces**: Use generator as-is; do not alter generated file template placeholders.

---

## Tests

* Unit tests not included. Manual tests:

  1. Create a small `echo.ps1` with `Write-Output "hello"`. Encrypt and generate executor. Run executor on a Windows machine. Confirm output `hello`.
  2. Modify private PEM URL to be invalid. Executor should fail to fetch and print an error.
  3. Run executor on a non-Windows or low-resource VM to confirm system-check failure and file purge behavior.

---

## License

Choose and add a license file as appropriate (MIT/Apache/BSD). This repository contains cryptographic code and tooling; follow your organization’s security and export policies.

---

End.
