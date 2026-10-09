"""
package_utils.py
Container serialization and parsing for the .sfe (Secure File Encryption) package format.

Specification:
- Container: Standard ZIP-based archive with strict structure validation.
- Internal Files:
  1. manifest.json: Metadata, algorithm IDs, GCM nonce, GCM auth tag, RSA-wrapped AES key.
  2. payload.enc: Raw binary ciphertext.
- Security Features:
  - Strict size limits against memory exhaustion and zip-bomb attacks.
  - Path traversal and arbitrary member injection defense.
  - Manifest schema validation (format version, algorithm IDs, base64 key/tag/nonce lengths).
  - Explicit prohibition of RSA private keys in package creation or parsing.
"""

import os
import io
import json
import base64
import zipfile
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional, Union
from Crypto.PublicKey import RSA

import crypto_utils
from crypto_utils import (
    CryptoError,
    InvalidKeyError,
    AuthenticationError,
    DecryptionError,
    AES_KEY_SIZE_BYTES,
    AES_NONCE_SIZE_BYTES,
    AES_TAG_SIZE_BYTES,
)


# ==============================================================================
# PACKAGE FORMAT CONSTANTS
# ==============================================================================

SFE_FORMAT_VERSION = "1.0"
SFE_SUPPORTED_VERSIONS = {SFE_FORMAT_VERSION}

ALG_SYMMETRIC_EXPECTED = "AES-256-GCM"
ALG_ASYMMETRIC_EXPECTED = "RSA-OAEP-SHA256-MGF1"

MANIFEST_FILENAME = "manifest.json"
PAYLOAD_FILENAME = "payload.enc"
ALLOWED_ARCHIVE_MEMBERS = {MANIFEST_FILENAME, PAYLOAD_FILENAME}

# Safety Limits
MAX_PACKAGE_SIZE_BYTES = 32 * 1024 * 1024    # 32 MB max package size
MAX_MANIFEST_SIZE_BYTES = 64 * 1024          # 64 KB max manifest size
MAX_PAYLOAD_SIZE_BYTES = 32 * 1024 * 1024    # 32 MB max ciphertext size
MAX_FILENAME_LENGTH = 255


# ==============================================================================
# PACKAGE EXCEPTIONS
# ==============================================================================

class PackageError(CryptoError):
    """Base exception for all .sfe packaging and parsing operations."""
    pass


class PackageFormatError(PackageError):
    """Raised when manifest structure, required fields, or versions are malformed or invalid."""
    pass


class CorruptedPackageError(PackageError):
    """Raised when the zip archive is corrupt, truncated, or tampered with."""
    pass


class SecurityLimitExceededError(PackageError):
    """Raised when an archive or component exceeds allowable size or member limits."""
    pass


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def sanitize_filename(filename: str) -> str:
    """
    Sanitizes an input filename to prevent path traversal or filesystem exploits.
    """
    if not filename or not isinstance(filename, str):
        return "unnamed_payload.bin"

    # Strip directory components (both / and \)
    clean_name = os.path.basename(filename.replace("\\", "/"))
    # Remove null bytes or control characters
    clean_name = "".join(c for c in clean_name if c.isprintable() and c not in '<>:"/\\|?*')
    clean_name = clean_name.strip(". ")

    if not clean_name:
        return "unnamed_payload.bin"

    return clean_name[:MAX_FILENAME_LENGTH]


def _b64_encode(data: bytes) -> str:
    """Encodes bytes to standard base64 ASCII string."""
    return base64.b64encode(data).decode("ascii")


def _b64_decode(data_str: str, expected_len: Optional[int] = None, field_name: str = "") -> bytes:
    """
    Decodes base64 string and validates length if expected_len is specified.
    """
    if not isinstance(data_str, str):
        raise PackageFormatError(f"Field '{field_name}' must be a base64-encoded string.")

    try:
        raw_bytes = base64.b64decode(data_str, validate=True)
    except Exception:
        raise PackageFormatError(f"Field '{field_name}' contains invalid base64 data.") from None

    if expected_len is not None and len(raw_bytes) != expected_len:
        raise PackageFormatError(
            f"Field '{field_name}' must decode to exactly {expected_len} bytes (got {len(raw_bytes)})."
        )

    return raw_bytes


# ==============================================================================
# SERIALIZATION: CREATE .SFE PACKAGE
# ==============================================================================

def create_sfe_package(
    ciphertext: bytes,
    nonce: bytes,
    tag: bytes,
    wrapped_key: bytes,
    original_filename: str,
    original_size: int,
    custom_metadata: Optional[Dict[str, Any]] = None
) -> bytes:
    """
    Serializes encryption outputs and metadata into a versioned .sfe ZIP package.
    
    Args:
        ciphertext: Raw AES-256-GCM ciphertext bytes.
        nonce: 12-byte GCM initialization nonce.
        tag: 16-byte GCM authentication tag.
        wrapped_key: RSA-OAEP encrypted AES key bytes.
        original_filename: Original name of the plaintext file.
        original_size: Original size in bytes of the plaintext file.
        custom_metadata: Optional additional non-sensitive metadata dictionary.
        
    Returns:
        Bytes of the complete .sfe archive.
        
    Raises:
        PackageFormatError: If input parameters fail validation.
        SecurityLimitExceededError: If payload exceeds size limits.
    """
    # Strict parameter validations
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise PackageFormatError("Ciphertext must be bytes.")
    if len(ciphertext) > MAX_PAYLOAD_SIZE_BYTES:
        raise SecurityLimitExceededError(
            f"Ciphertext size ({len(ciphertext)} bytes) exceeds maximum limit of {MAX_PAYLOAD_SIZE_BYTES} bytes."
        )

    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != AES_NONCE_SIZE_BYTES:
        raise PackageFormatError(f"Nonce must be exactly {AES_NONCE_SIZE_BYTES} bytes.")

    if not isinstance(tag, (bytes, bytearray)) or len(tag) != AES_TAG_SIZE_BYTES:
        raise PackageFormatError(f"Authentication tag must be exactly {AES_TAG_SIZE_BYTES} bytes.")

    if not isinstance(wrapped_key, (bytes, bytearray)) or len(wrapped_key) == 0:
        raise PackageFormatError("Wrapped AES key must be non-empty bytes.")

    # Guard: Never allow private key material inside the package
    if b"PRIVATE KEY" in wrapped_key:
        raise PackageFormatError("Security violation: RSA private key must NEVER be included in package.")

    if not isinstance(original_size, int) or original_size < 0:
        raise PackageFormatError("Original size must be a non-negative integer.")

    clean_filename = sanitize_filename(original_filename)

    # Build manifest
    manifest: Dict[str, Any] = {
        "format_version": SFE_FORMAT_VERSION,
        "algorithms": {
            "symmetric": ALG_SYMMETRIC_EXPECTED,
            "asymmetric": ALG_ASYMMETRIC_EXPECTED,
        },
        "crypto": {
            "nonce": _b64_encode(bytes(nonce)),
            "tag": _b64_encode(bytes(tag)),
            "wrapped_key": _b64_encode(bytes(wrapped_key)),
        },
        "file_metadata": {
            "original_filename": clean_filename,
            "original_size": original_size,
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
        }
    }

    if custom_metadata and isinstance(custom_metadata, dict):
        # Validate that custom metadata does not leak sensitive terms
        serialized_custom = json.dumps(custom_metadata)
        if "PRIVATE KEY" in serialized_custom.upper():
            raise PackageFormatError("Security violation: private key material detected in metadata.")
        manifest["custom_metadata"] = custom_metadata

    manifest_json_bytes = json.dumps(manifest, indent=2).encode("utf-8")
    if len(manifest_json_bytes) > MAX_MANIFEST_SIZE_BYTES:
        raise SecurityLimitExceededError("Manifest size exceeds allowed limit.")

    # Write in-memory ZIP package
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Write manifest.json
        manifest_info = zipfile.ZipInfo(MANIFEST_FILENAME)
        manifest_info.compress_type = zipfile.ZIP_DEFLATED
        zf.writestr(manifest_info, manifest_json_bytes)

        # Write payload.enc (uncompressed or deflated)
        payload_info = zipfile.ZipInfo(PAYLOAD_FILENAME)
        payload_info.compress_type = zipfile.ZIP_STORED
        zf.writestr(payload_info, bytes(ciphertext))

    package_bytes = buffer.getvalue()
    if len(package_bytes) > MAX_PACKAGE_SIZE_BYTES:
        raise SecurityLimitExceededError("Total package size exceeds allowable limit.")

    return package_bytes


# ==============================================================================
# PARSING: EXTRACT & VALIDATE .SFE PACKAGE
# ==============================================================================

def parse_sfe_package(package_bytes: bytes) -> Dict[str, Any]:
    """
    Safely opens, validates, and parses a .sfe package archive.
    
    Args:
        package_bytes: Raw bytes of the .sfe package archive.
        
    Returns:
        Dictionary containing:
            - 'ciphertext': bytes
            - 'nonce': bytes (12 bytes)
            - 'tag': bytes (16 bytes)
            - 'wrapped_key': bytes
            - 'manifest': parsed manifest dict
            - 'original_filename': sanitized filename
            - 'original_size': int
            
    Raises:
        CorruptedPackageError: If archive is invalid ZIP or corrupt.
        PackageFormatError: If manifest has missing/unsupported fields or wrong algorithm IDs.
        SecurityLimitExceededError: If archive or entries exceed size boundaries.
    """
    if not isinstance(package_bytes, (bytes, bytearray)):
        raise PackageFormatError("Package input must be bytes.")

    if len(package_bytes) == 0:
        raise CorruptedPackageError("Package data is empty.")

    if len(package_bytes) > MAX_PACKAGE_SIZE_BYTES:
        raise SecurityLimitExceededError(
            f"Package size ({len(package_bytes)} bytes) exceeds maximum limit ({MAX_PACKAGE_SIZE_BYTES} bytes)."
        )

    # Open ZIP container safely
    try:
        zf = zipfile.ZipFile(io.BytesIO(package_bytes), mode="r")
    except (zipfile.BadZipFile, zipfile.LargeZipFile) as err:
        raise CorruptedPackageError(f"Corrupted package: invalid ZIP archive structure ({str(err)}).") from None
    except Exception as err:
        raise CorruptedPackageError(f"Failed to open package archive: {str(err)}.") from None

    with zf:
        # Check for CRC/Archive integrity
        bad_file = zf.testzip()
        if bad_file:
            raise CorruptedPackageError(f"Corrupted package: CRC failure detected in '{bad_file}'.")

        entries = zf.namelist()

        # Archive hardening: Allow only exactly MANIFEST_FILENAME and PAYLOAD_FILENAME
        if set(entries) != ALLOWED_ARCHIVE_MEMBERS:
            missing = ALLOWED_ARCHIVE_MEMBERS - set(entries)
            extra = set(entries) - ALLOWED_ARCHIVE_MEMBERS
            if missing:
                raise PackageFormatError(f"Malformed package: missing required file(s): {sorted(missing)}.")
            if extra:
                raise PackageFormatError(f"Security violation: unexpected file(s) found in archive: {sorted(extra)}.")

        # Validate member sizes and types before extracting
        for member in zf.infolist():
            if member.is_dir():
                raise PackageFormatError("Security violation: directories are forbidden inside .sfe packages.")

            if member.filename == MANIFEST_FILENAME and member.file_size > MAX_MANIFEST_SIZE_BYTES:
                raise SecurityLimitExceededError(
                    f"Manifest size ({member.file_size} bytes) exceeds limit ({MAX_MANIFEST_SIZE_BYTES} bytes)."
                )

            if member.filename == PAYLOAD_FILENAME and member.file_size > MAX_PAYLOAD_SIZE_BYTES:
                raise SecurityLimitExceededError(
                    f"Payload size ({member.file_size} bytes) exceeds limit ({MAX_PAYLOAD_SIZE_BYTES} bytes)."
                )

        # 1. Read and parse manifest.json
        try:
            manifest_raw = zf.read(MANIFEST_FILENAME).decode("utf-8")
        except UnicodeDecodeError:
            raise PackageFormatError("Manifest is not valid UTF-8 text.") from None

        try:
            manifest = json.loads(manifest_raw)
        except json.JSONDecodeError as err:
            raise PackageFormatError(f"Malformed manifest JSON: {str(err)}.") from None

        if not isinstance(manifest, dict):
            raise PackageFormatError("Manifest root must be a JSON object.")

        # 2. Validate format version
        version = manifest.get("format_version")
        if not version or not isinstance(version, str):
            raise PackageFormatError("Manifest missing required 'format_version'.")
        if version not in SFE_SUPPORTED_VERSIONS:
            raise PackageFormatError(
                f"Unsupported package format version '{version}'. Supported versions: {sorted(SFE_SUPPORTED_VERSIONS)}."
            )

        # 3. Validate algorithms
        algs = manifest.get("algorithms")
        if not isinstance(algs, dict):
            raise PackageFormatError("Manifest missing 'algorithms' object.")
        if algs.get("symmetric") != ALG_SYMMETRIC_EXPECTED:
            raise PackageFormatError(
                f"Unsupported symmetric algorithm '{algs.get('symmetric')}'. Expected '{ALG_SYMMETRIC_EXPECTED}'."
            )
        if algs.get("asymmetric") != ALG_ASYMMETRIC_EXPECTED:
            raise PackageFormatError(
                f"Unsupported asymmetric algorithm '{algs.get('asymmetric')}'. Expected '{ALG_ASYMMETRIC_EXPECTED}'."
            )

        # 4. Validate crypto parameters
        crypto_section = manifest.get("crypto")
        if not isinstance(crypto_section, dict):
            raise PackageFormatError("Manifest missing 'crypto' object.")

        nonce = _b64_decode(
            crypto_section.get("nonce"),
            expected_len=AES_NONCE_SIZE_BYTES,
            field_name="crypto.nonce"
        )
        tag = _b64_decode(
            crypto_section.get("tag"),
            expected_len=AES_TAG_SIZE_BYTES,
            field_name="crypto.tag"
        )
        wrapped_key = _b64_decode(
            crypto_section.get("wrapped_key"),
            expected_len=None,
            field_name="crypto.wrapped_key"
        )
        if len(wrapped_key) == 0:
            raise PackageFormatError("Wrapped AES key cannot be empty.")

        # Guard: Ensure private key is not inside manifest or wrapped_key
        if b"PRIVATE KEY" in wrapped_key:
            raise PackageFormatError("Security violation: private key material detected in wrapped key payload.")

        # 5. Validate file metadata
        meta = manifest.get("file_metadata")
        if not isinstance(meta, dict):
            raise PackageFormatError("Manifest missing 'file_metadata' object.")

        original_filename = sanitize_filename(meta.get("original_filename", "decrypted_file.bin"))
        original_size = meta.get("original_size")
        if not isinstance(original_size, int) or original_size < 0:
            raise PackageFormatError("Field 'file_metadata.original_size' must be a non-negative integer.")

        # 6. Read payload.enc
        ciphertext = zf.read(PAYLOAD_FILENAME)

        return {
            "ciphertext": ciphertext,
            "nonce": nonce,
            "tag": tag,
            "wrapped_key": wrapped_key,
            "manifest": manifest,
            "original_filename": original_filename,
            "original_size": original_size,
        }


# ==============================================================================
# HIGH-LEVEL CONVENIENCE WORKFLOWS (.SFE ENCRYPT & DECRYPT)
# ==============================================================================

def encrypt_file_to_sfe_package(
    file_bytes: bytes,
    filename: str,
    recipient_public_key: Union[str, bytes, RSA.RsaKey],
    custom_metadata: Optional[Dict[str, Any]] = None
) -> bytes:
    """
    Encrypts a file payload using AES-256-GCM + RSA-OAEP and packs it directly into a .sfe package.
    """
    if not isinstance(file_bytes, (bytes, bytearray)):
        raise TypeError("File data must be bytes or bytearray.")

    original_size = len(file_bytes)
    hybrid_result = crypto_utils.encrypt_file_hybrid(file_bytes, recipient_public_key)

    return create_sfe_package(
        ciphertext=hybrid_result["ciphertext"],
        nonce=hybrid_result["nonce"],
        tag=hybrid_result["tag"],
        wrapped_key=hybrid_result["wrapped_key"],
        original_filename=filename,
        original_size=original_size,
        custom_metadata=custom_metadata
    )


def decrypt_file_from_sfe_package(
    package_bytes: bytes,
    recipient_private_key: Union[str, bytes, RSA.RsaKey],
    passphrase: Optional[str] = None
) -> Tuple[bytes, Dict[str, Any]]:
    """
    Parses a .sfe package, unwraps the AES session key, verifies the tag, and decrypts the file.
    
    Returns:
        Tuple of (decrypted_plaintext_bytes, parsed_manifest_metadata)
    """
    parsed = parse_sfe_package(package_bytes)

    plaintext = crypto_utils.decrypt_file_hybrid(
        ciphertext=parsed["ciphertext"],
        nonce=parsed["nonce"],
        tag=parsed["tag"],
        wrapped_key=parsed["wrapped_key"],
        recipient_private_key=recipient_private_key,
        passphrase=passphrase
    )

    return plaintext, parsed["manifest"]
