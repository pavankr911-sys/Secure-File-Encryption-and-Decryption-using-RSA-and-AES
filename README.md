# Secure File Encryption and Decryption System Using AES and RSA

**Subject / Domain:** Cryptography and Network Security (CNS) Mini-Project  
**Technology Stack:** Python (Flask), HTML5, CSS3, JavaScript, PyCryptodome  

---

## 1. Project Overview

This project implements a **Hybrid Cryptosystem** designed to securely transmit and store arbitrary files. Modern cryptographic security relies on combining the complementary strengths of symmetric and asymmetric encryption:

1. **Symmetric Encryption (AES-256-GCM):**  
   Files of any size are encrypted using a one-time, cryptographically secure 256-bit symmetric session key (`get_random_bytes(32)`). **Galois/Counter Mode (GCM)** ensures authenticated encryption, providing both **confidentiality** and **tamper-proof integrity** via a 128-bit authentication tag and a fresh 12-byte nonce.

2. **Asymmetric Encryption (RSA-3072 with OAEP):**  
   The ephemeral AES session key is securely encrypted using the recipient's RSA public key with **OAEP (Optimal Asymmetric Encryption Padding)**, SHA-256 hash, and MGF1-SHA256 mask generation. This eliminates the symmetric key exchange vulnerability.

3. **Decryption & Verification:**  
   The recipient unwarps the AES session key using their private RSA key, checks the GCM authentication tag, and decrypts the original file. If any byte has been modified in transit, GCM verification fails immediately.

---

## 2. Directory Structure

```text
CNS project/
├── app.py                      # Flask server, route registry, and health endpoint
├── crypto_utils.py             # Native PyCryptodome cryptographic primitives (AES-GCM & RSA-OAEP)
├── package_utils.py            # Versioned .sfe container serialization, safe parsing & validation
├── requirements.txt            # Project dependencies (Flask, pycryptodome, pytest)
├── README.md                   # System documentation, package format spec, and setup guide
├── templates/
│   └── index.html              # Responsive web dashboard UI
├── static/
│   ├── css/
│   │   └── style.css           # Modern cybersecurity theme styles
│   └── js/
│       └── main.js             # Client-side health ping & UI interaction logic
└── tests/
    ├── __init__.py             # Test package marker
    ├── test_crypto.py          # Unit tests verifying cryptographic primitives & Flask routes
    └── test_package.py         # Unit tests verifying .sfe package format, malformed inputs & limits
```

---

## 3. Versioned .sfe Encrypted File Package Format

The system packages encrypted files into an authenticated, portable container format with the **`.sfe`** (Secure File Encryption) extension.

### 3.1 Container Architecture
An `.sfe` package is a hardened, single-file ZIP archive containing exactly two distinct members:

```text
encrypted_package.sfe (ZIP Container)
├── manifest.json               # Cryptographic parameters, algorithm IDs, and file metadata
└── payload.enc                 # Raw binary AES-256-GCM ciphertext
```

### 3.2 Manifest Schema (`manifest.json`)
The manifest contains the parameters required for key recovery and authenticated decryption. The RSA private key is **strictly prohibited** from the package.

```json
{
  "format_version": "1.0",
  "algorithms": {
    "symmetric": "AES-256-GCM",
    "asymmetric": "RSA-OAEP-SHA256-MGF1"
  },
  "crypto": {
    "nonce": "dGVzdF9ub25jZV8xMmI=",
    "tag": "dGVzdF9hdXRoX3RhZ18xNmI=",
    "wrapped_key": "c2Vzc2lvbl9rZXlfd3JhcHBlZF9ieV9yc2Ffb2FlcA=="
  },
  "file_metadata": {
    "original_filename": "confidential_project_report.pdf",
    "original_size": 204850,
    "created_at_utc": "2026-10-09T16:15:00.000000+00:00"
  },
  "custom_metadata": {
    "classification": "RESTRICTED",
    "department": "CNS"
  }
}
```

| Field | Type | Description |
|---|---|---|
| `format_version` | String | Format specification version (currently `"1.0"`). |
| `algorithms.symmetric` | String | Must equal `"AES-256-GCM"`. |
| `algorithms.asymmetric` | String | Must equal `"RSA-OAEP-SHA256-MGF1"`. |
| `crypto.nonce` | Base64 String | 12-byte initialization nonce for AES-GCM (NIST SP 800-38D). |
| `crypto.tag` | Base64 String | 16-byte (128-bit) GCM authentication tag. |
| `crypto.wrapped_key` | Base64 String | Ephemeral 32-byte AES key encrypted via RSA-OAEP. |
| `file_metadata.original_filename` | String | Sanitized filename (stripped of path traversal prefixes). |
| `file_metadata.original_size` | Integer | Original plaintext size in bytes. |

### 3.3 Safe Archive Handling & Security Controls
1. **Strict Member Whitelist:** The archive must contain **only** `manifest.json` and `payload.enc`. Any directory entries or unrecognized files trigger immediate rejection.
2. **Path Traversal Defense:** Filenames in metadata and archive paths are sanitized via `sanitize_filename()` to remove directory components (`..`, `/`, `\`) and illegal characters.
3. **Zip-Bomb & Resource Defense:**
   - Maximum total package size: **32 MB**
   - Maximum manifest size: **64 KB**
   - Maximum uncompressed payload: **32 MB**
4. **Base64 Length Validation:** Nonce must decode to exactly 12 bytes; tag must decode to exactly 16 bytes.
5. **Private Key Exclusion:** Proactive regex and byte scanning prevents private keys from ever being written into or parsed from the package.

---

## 4. Installation and Setup

### Prerequisites
- Python 3.10+ installed
- PowerShell or Terminal

### Step 1: Create and Activate Virtual Environment
```powershell
# Navigate to the project root
cd "c:\Users\Foxin\Desktop\BE\7th sem\CNS project"

# Create virtual environment
python -m venv venv

# Activate virtual environment (Windows PowerShell)
.\venv\Scripts\Activate.ps1
```

### Step 2: Install Required Dependencies
```powershell
pip install -r requirements.txt
```

---

## 5. Running the Tests

To execute the test suite (verifying cryptography, `.sfe` package validation, tamper detection, and Flask routes):

```powershell
pytest -v
```

All 46 unit and integration tests are automated:
- `tests/test_crypto.py`: 20 tests (RSA generation, AES-GCM AEAD, OAEP wrapping, Flask endpoints)
- `tests/test_package.py`: 26 tests (manifest parsing, missing fields, malformed JSON, corrupted ZIPs, size limits, path sanitization)

---

## 6. Running the Application

Launch the Flask development server:
```powershell
python app.py
```

Open your browser and navigate to:
```text
http://127.0.0.1:5000
```

### Health Check Endpoint
To inspect the system state and active cryptographic algorithms:
```text
http://127.0.0.1:5000/health
```

Expected JSON response:
```json
{
  "algorithms": {
    "asymmetric": "RSA-3072 with OAEP (SHA-256 / MGF1 padding)",
    "rng": "CSPRNG (get_random_bytes)",
    "symmetric": "AES-256-GCM (Authenticated Encryption)"
  },
  "crypto_engine": "PyCryptodome",
  "service": "CNS File Encryption & Decryption System",
  "status": "healthy",
  "version": "1.0.0"
}
```

---

## 7. Security Guarantees & CNS Principles

- **Ephemeral Keys (Forward Secrecy per file):** Every encryption session generates a new random 256-bit AES key and a distinct 12-byte nonce.
- **Indistinguishability under Chosen Ciphertext Attack (IND-CCA2):** Provided by RSA-OAEP with SHA-256 and MGF1-SHA256.
- **Authenticated Encryption with Associated Data (AEAD):** AES-GCM guarantees that any modification of ciphertext or nonce leads to authentication failure prior to data release.
- **Private Key Confidentiality:** Private keys never leave the client or enter container files.
