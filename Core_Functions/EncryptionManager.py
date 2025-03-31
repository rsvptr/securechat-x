"""
EncryptionManager.py

Manages cryptographic operations:
- AES encryption/decryption (CBC mode)
- RSA encryption/decryption for key transport
- Creating/unpacking a digital envelope

Dependencies:
    pip install pycryptodomex
"""

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from rsa import encrypt, decrypt, PublicKey, PrivateKey

def aes_encrypt(plaintext: bytes, key: bytes = None) -> tuple:
    """
    Encrypts 'plaintext' using AES in CBC mode. If 'key' is not provided,
    a new 16-byte (128-bit) random key is generated. 

    Returns a tuple:
        (ciphertext, iv, key)

    Where:
        - ciphertext: The AES-encrypted data.
        - iv: The initialization vector used for CBC mode.
        - key: The 16-byte AES key that was used.
    """
    if key is None:
        # If no key is provided, generate a random 128-bit key
        key = get_random_bytes(16)
    # Create an AES cipher object in CBC mode with the provided (or generated) key
    cipher = AES.new(key, AES.MODE_CBC)
    # The IV is automatically chosen by the library if not provided
    iv = cipher.iv
    # Apply PKCS#7 padding to the plaintext, then encrypt
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    # Return the encrypted data, the IV, and the key used
    return ciphertext, iv, key

def aes_decrypt(ciphertext: bytes, iv: bytes, key: bytes) -> bytes:
    """
    Decrypts 'ciphertext' using AES in CBC mode with the provided 'key' and 'iv'.
    Returns the plaintext in bytes.

    :param ciphertext: The AES-encrypted data
    :param iv: The initialization vector used in encryption
    :param key: The 16-byte AES key used to encrypt
    :return: The original plaintext bytes
    """
    # Create a new AES cipher object for decryption in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Decrypt and then remove PKCS#7 padding
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

def create_digital_envelope(plaintext: bytes, recipient_pub_key: PublicKey) -> tuple:
    """
    Constructs a "digital envelope" by:
      1) Generating a random AES key (16 bytes).
      2) Encrypting the plaintext with that AES key in CBC mode.
      3) RSA-encrypting the AES key with the recipient's public key 
         so only the recipient can recover the key.

    Returns a tuple:
        (encrypted_data, iv, encrypted_key)

    Where:
        - encrypted_data: AES ciphertext of the original plaintext
        - iv: The initialization vector used for AES
        - encrypted_key: The AES key, encrypted with RSA using recipient_pub_key
    """
    # Step 1 & 2: Encrypt plaintext with AES and generate a random key if not provided
    ciphertext, iv, session_key = aes_encrypt(plaintext)
    # Step 3: RSA-encrypt the AES session key using the recipient's public key
    encrypted_key = encrypt(session_key, recipient_pub_key)
    return ciphertext, iv, encrypted_key

def unpack_digital_envelope(encrypted_data: bytes, iv: bytes, encrypted_key: bytes, recipient_priv_key: PrivateKey) -> bytes:
    """
    Reverses the process of create_digital_envelope by:
      1) RSA-decrypting the AES key using the recipient's private key.
      2) AES-decrypting the 'encrypted_data' with that key and the provided IV.

    Returns the original plaintext in bytes.

    :param encrypted_data: The AES ciphertext
    :param iv: The IV used for AES encryption
    :param encrypted_key: The RSA-encrypted AES key
    :param recipient_priv_key: The private key for decrypting the AES key
    :return: The recovered plaintext in bytes
    """
    # RSA-decrypt the session key using the recipient's private key
    session_key = decrypt(encrypted_key, recipient_priv_key)
    # Use the recovered session key to AES-decrypt the ciphertext
    plaintext = aes_decrypt(encrypted_data, iv, session_key)
    return plaintext
