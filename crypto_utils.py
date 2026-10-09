"""
crypto_utils.py
Cryptographic engine for the CNS project:
"Secure File Encryption and Decryption System Using AES and RSA"

This module provides independent, production-grade cryptographic primitives
implemented with PyCryptodome:
1. AES-256-GCM authenticated encryption and decryption.
2. Fresh 32-byte AES keys and 12-byte nonces generated via CSPRNG (get_random_bytes).
3. Configurable RSA key generation (default: 3072 bits).
4. RSA-OAEP key wrapping/unwrapping using SHA-256 and MGF1-SHA256.
5. Strict validation of key types, lengths, and parameters.
6. Safe error handling for authentication failures and incorrect keys.

SECURITY NOTICE:
- Plaintext data, raw keys, and private-key material are never logged or leaked.
- Every encryption operation enforces fresh key and nonce generation.
"""

from typing import Tuple, Dict, Optional, Union
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


# ==============================================================================
# CRYPTOGRAPHIC CONSTANTS
# ==============================================================================

AES_KEY_SIZE_BYTES = 32       # 256 bits for AES-256
AES_NONCE_SIZE_BYTES = 12     # 96 bits - Standard recommended nonce size for GCM (NIST SP 800-38D)
AES_TAG_SIZE_BYTES = 16       # 128 bits - Full authentication tag length
RSA_DEFAULT_KEY_SIZE = 3072   # 3072-bit RSA (NIST recommendation for 128-bit security margin)
RSA_MINIMUM_KEY_SIZE = 2048   # Minimum allowable RSA modulus length


# ==============================================================================
# CUSTOM CRYPTOGRAPHIC EXCEPTIONS
# ==============================================================================

class CryptoError(Exception):
    """Base exception for all cryptographic operations."""
    pass


class InvalidKeyError(CryptoError):
    """Raised when an encryption or decryption key fails type, format, or length validation."""
    pass


class AuthenticationError(CryptoError):
    """Raised when AES-GCM authentication fails due to tampering or corrupted ciphertext."""
    pass


class DecryptionError(CryptoError):
    """Raised when decryption or RSA key unwrapping fails (e.g. wrong private key)."""
    pass


# ==============================================================================
# RSA KEY GENERATION & PARSING
# ==============================================================================

def generate_rsa_key_pair(bits: int = RSA_DEFAULT_KEY_SIZE) -> Tuple[str, str]:
    """
    Generates a cryptographically secure RSA key pair.
    
    Args:
        bits: The RSA modulus length in bits (default: 3072).
        
    Returns:
        Tuple of (private_key_pem, public_key_pem) as UTF-8 encoded strings.
        
    Raises:
        InvalidKeyError: If bits is not an integer or is less than 2048 bits.
    """
    if not isinstance(bits, int):
        raise InvalidKeyError("RSA key size must be an integer.")
    if bits < RSA_MINIMUM_KEY_SIZE:
        raise InvalidKeyError(
            f"RSA key size must be at least {RSA_MINIMUM_KEY_SIZE} bits (requested: {bits})."
        )

    rsa_key = RSA.generate(bits)
    private_pem = rsa_key.export_key(format="PEM").decode("utf-8")
    public_pem = rsa_key.publickey().export_key(format="PEM").decode("utf-8")

    return private_pem, public_pem


def _import_rsa_key(
    key_input: Union[str, bytes, RSA.RsaKey],
    passphrase: Optional[str] = None
) -> RSA.RsaKey:
    """
    Safely imports and parses an RSA key from PEM string, bytes, or RSA object.
    
    Raises:
        InvalidKeyError: If key data is malformed or invalid.
    """
    if isinstance(key_input, RSA.RsaKey):
        return key_input

    if not isinstance(key_input, (str, bytes)):
        raise InvalidKeyError("RSA key must be provided as a string, bytes, or RsaKey object.")

    try:
        return RSA.import_key(key_input, passphrase=passphrase)
    except (ValueError, IndexError, TypeError) as err:
        raise InvalidKeyError("Failed to parse RSA key: invalid key format or passphrase.") from None


# ==============================================================================
# SYMMETRIC KEY & NONCE GENERATION
# ==============================================================================

def generate_aes_key() -> bytes:
    """
    Generates a fresh cryptographically secure random 32-byte (256-bit) AES key.
    
    Returns:
        32 random bytes from CSPRNG (get_random_bytes).
    """
    return get_random_bytes(AES_KEY_SIZE_BYTES)


def generate_nonce() -> bytes:
    """
    Generates a fresh cryptographically secure random 12-byte (96-bit) nonce for AES-GCM.
    
    Returns:
        12 random bytes from CSPRNG (get_random_bytes).
    """
    return get_random_bytes(AES_NONCE_SIZE_BYTES)


# ==============================================================================
# RSA-OAEP KEY ENCAPSULATION (WRAP / UNWRAP)
# ==============================================================================

def wrap_aes_key_rsa(
    aes_key: bytes,
    public_key_input: Union[str, bytes, RSA.RsaKey]
) -> bytes:
    """
    Wraps (encrypts) a 32-byte AES key using RSA-OAEP with SHA-256 and MGF1-SHA256.
    
    Args:
        aes_key: 32-byte AES key.
        public_key_input: Recipient's RSA public key (PEM string, bytes, or RsaKey object).
        
    Returns:
        Wrapped (ciphertext) AES key bytes.
        
    Raises:
        InvalidKeyError: If the AES key length is not 32 bytes or the RSA key is invalid.
    """
    if not isinstance(aes_key, (bytes, bytearray)):
        raise InvalidKeyError("AES key must be bytes or bytearray.")
    if len(aes_key) != AES_KEY_SIZE_BYTES:
        raise InvalidKeyError(
            f"AES key must be exactly {AES_KEY_SIZE_BYTES} bytes (received: {len(aes_key)})."
        )

    recipient_rsa = _import_rsa_key(public_key_input)
    if not recipient_rsa.can_encrypt():
        raise InvalidKeyError("Provided RSA key cannot be used for encryption.")

    # Configure RSA-OAEP cipher with SHA-256 and MGF1-SHA256
    cipher_oaep = PKCS1_OAEP.new(
        recipient_rsa,
        hashAlgo=SHA256,
        mgfunc=lambda x, y: PKCS1_OAEP.MGF1(x, y, SHA256)
    )
    return cipher_oaep.encrypt(bytes(aes_key))


def unwrap_aes_key_rsa(
    wrapped_aes_key: bytes,
    private_key_input: Union[str, bytes, RSA.RsaKey],
    passphrase: Optional[str] = None
) -> bytes:
    """
    Unwraps (decrypts) an AES key using RSA-OAEP with SHA-256 and MGF1-SHA256.
    
    Args:
        wrapped_aes_key: The encrypted AES key bytes.
        private_key_input: Recipient's RSA private key (PEM string, bytes, or RsaKey object).
        passphrase: Optional passphrase for encrypted private keys.
        
    Returns:
        Original 32-byte AES key.
        
    Raises:
        InvalidKeyError: If private key is invalid or lacks the private component.
        DecryptionError: If unwrapping fails due to an incorrect private key or corrupted ciphertext.
    """
    if not isinstance(wrapped_aes_key, (bytes, bytearray)):
        raise DecryptionError("Wrapped AES key must be bytes or bytearray.")
    if len(wrapped_aes_key) == 0:
        raise DecryptionError("Wrapped AES key cannot be empty.")

    private_rsa = _import_rsa_key(private_key_input, passphrase=passphrase)
    if not private_rsa.has_private():
        raise InvalidKeyError("Provided RSA key is a public key; private key is required for unwrapping.")

    cipher_oaep = PKCS1_OAEP.new(
        private_rsa,
        hashAlgo=SHA256,
        mgfunc=lambda x, y: PKCS1_OAEP.MGF1(x, y, SHA256)
    )

    try:
        aes_key = cipher_oaep.decrypt(bytes(wrapped_aes_key))
    except ValueError:
        raise DecryptionError("RSA key unwrapping failed: incorrect private key or corrupted key payload.") from None

    if len(aes_key) != AES_KEY_SIZE_BYTES:
        raise DecryptionError("Decrypted AES key has invalid length.")

    return aes_key


# Legacy aliases for backward compatibility
encrypt_session_key_rsa = wrap_aes_key_rsa
decrypt_session_key_rsa = unwrap_aes_key_rsa


# ==============================================================================
# AES-256-GCM SYMMETRIC ENCRYPTION & AUTHENTICATION
# ==============================================================================

def encrypt_aes_gcm(
    data: bytes,
    key: bytes,
    nonce: Optional[bytes] = None
) -> Dict[str, bytes]:
    """
    Encrypts arbitrary byte data using AES-256-GCM (Authenticated Encryption).
    
    Every invocation generates a fresh 12-byte nonce unless explicitly provided.
    Never reuse a nonce with the same AES key.
    
    Args:
        data: Plaintext bytes to encrypt (can be empty b"").
        key: 32-byte AES key.
        nonce: Optional 12-byte initialization nonce. If None, a fresh random nonce is generated.
        
    Returns:
        Dictionary containing:
            - 'ciphertext': Encrypted data bytes
            - 'nonce': 12-byte initialization nonce
            - 'tag': 16-byte authentication tag
            
    Raises:
        InvalidKeyError: If key or nonce length is invalid.
        TypeError: If input data is not bytes-like.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("Plaintext data must be bytes or bytearray.")

    if not isinstance(key, (bytes, bytearray)):
        raise InvalidKeyError("AES key must be bytes or bytearray.")
    if len(key) != AES_KEY_SIZE_BYTES:
        raise InvalidKeyError(
            f"AES key must be exactly {AES_KEY_SIZE_BYTES} bytes (received: {len(key)})."
        )

    if nonce is None:
        nonce = generate_nonce()
    else:
        if not isinstance(nonce, (bytes, bytearray)):
            raise InvalidKeyError("Nonce must be bytes or bytearray.")
        if len(nonce) != AES_NONCE_SIZE_BYTES:
            raise InvalidKeyError(
                f"AES-GCM nonce must be exactly {AES_NONCE_SIZE_BYTES} bytes (received: {len(nonce)})."
            )

    cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=bytes(nonce))
    ciphertext, tag = cipher.encrypt_and_digest(bytes(data))

    return {
        "ciphertext": ciphertext,
        "nonce": bytes(nonce),
        "tag": tag,
    }


def decrypt_aes_gcm(
    ciphertext: bytes,
    key: bytes,
    nonce: bytes,
    tag: bytes
) -> bytes:
    """
    Decrypts and authenticates ciphertext using AES-256-GCM.
    
    Args:
        ciphertext: Encrypted payload bytes.
        key: 32-byte AES key.
        nonce: 12-byte initialization nonce used during encryption.
        tag: 16-byte authentication tag for integrity verification.
        
    Returns:
        Decrypted plaintext bytes.
        
    Raises:
        InvalidKeyError: If key, nonce, or tag dimensions are invalid.
        AuthenticationError: If ciphertext, tag, nonce, or key has been modified or corrupted.
    """
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("Ciphertext must be bytes or bytearray.")

    if not isinstance(key, (bytes, bytearray)):
        raise InvalidKeyError("AES key must be bytes or bytearray.")
    if len(key) != AES_KEY_SIZE_BYTES:
        raise InvalidKeyError(
            f"AES key must be exactly {AES_KEY_SIZE_BYTES} bytes (received: {len(key)})."
        )

    if not isinstance(nonce, (bytes, bytearray)):
        raise InvalidKeyError("Nonce must be bytes or bytearray.")
    if len(nonce) != AES_NONCE_SIZE_BYTES:
        raise InvalidKeyError(
            f"AES-GCM nonce must be exactly {AES_NONCE_SIZE_BYTES} bytes (received: {len(nonce)})."
        )

    if not isinstance(tag, (bytes, bytearray)):
        raise InvalidKeyError("Tag must be bytes or bytearray.")
    if len(tag) != AES_TAG_SIZE_BYTES:
        raise InvalidKeyError(
            f"AES-GCM authentication tag must be exactly {AES_TAG_SIZE_BYTES} bytes (received: {len(tag)})."
        )

    cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=bytes(nonce))

    try:
        plaintext = cipher.decrypt_and_verify(bytes(ciphertext), bytes(tag))
        return plaintext
    except ValueError:
        raise AuthenticationError(
            "AES-GCM authentication failed: data corrupted, incorrect tag, or wrong key."
        ) from None


# ==============================================================================
# HIGH-LEVEL HYBRID CRYPTOSYSTEM INTERFACE
# ==============================================================================

def encrypt_file_hybrid(
    file_bytes: bytes,
    recipient_public_key: Union[str, bytes, RSA.RsaKey]
) -> Dict[str, bytes]:
    """
    High-level hybrid encryption pipeline for files:
    1. Generates a fresh random 32-byte AES key.
    2. Generates a fresh random 12-byte nonce.
    3. Encrypts file payload using AES-256-GCM.
    4. Wraps the AES key using RSA-OAEP (SHA-256 + MGF1-SHA256) with recipient's public key.
    
    Args:
        file_bytes: File content bytes to encrypt.
        recipient_public_key: Recipient's RSA public key.
        
    Returns:
        Dictionary containing:
            - 'ciphertext': Encrypted file payload
            - 'nonce': 12-byte GCM nonce
            - 'tag': 16-byte GCM authentication tag
            - 'wrapped_key': RSA-OAEP encrypted AES key
    """
    aes_key = generate_aes_key()
    nonce = generate_nonce()

    aes_output = encrypt_aes_gcm(file_bytes, aes_key, nonce=nonce)
    wrapped_key = wrap_aes_key_rsa(aes_key, recipient_public_key)

    return {
        "ciphertext": aes_output["ciphertext"],
        "nonce": aes_output["nonce"],
        "tag": aes_output["tag"],
        "wrapped_key": wrapped_key,
    }


def decrypt_file_hybrid(
    ciphertext: bytes,
    nonce: bytes,
    tag: bytes,
    wrapped_key: bytes,
    recipient_private_key: Union[str, bytes, RSA.RsaKey],
    passphrase: Optional[str] = None
) -> bytes:
    """
    High-level hybrid decryption pipeline for files:
    1. Unwraps the 32-byte AES key using RSA-OAEP and recipient's private key.
    2. Authenticates and decrypts file payload using AES-256-GCM.
    
    Args:
        ciphertext: Encrypted file payload.
        nonce: 12-byte GCM nonce.
        tag: 16-byte GCM authentication tag.
        wrapped_key: RSA-OAEP encrypted AES key.
        recipient_private_key: Recipient's RSA private key.
        passphrase: Optional passphrase for the private key.
        
    Returns:
        Decrypted original file bytes.
        
    Raises:
        DecryptionError: If RSA key unwrapping fails.
        AuthenticationError: If AES-GCM verification fails.
    """
    aes_key = unwrap_aes_key_rsa(wrapped_key, recipient_private_key, passphrase=passphrase)
    return decrypt_aes_gcm(ciphertext, aes_key, nonce, tag)
