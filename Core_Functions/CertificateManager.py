"""
CertificateManager.py

Defines the 'Certificate' class for storing:
    - Public Key
    - Identity (A, B, C, or S)
    - Certificate Signature

Supports loading/saving from a file, generating signatures, etc.
"""

import pickle
from rsa import PublicKey, PrivateKey, sign

class Certificate:
    """
    The Certificate class encapsulates an entity's public key, its identity,
    and a digital signature. In a real-world scenario, a trusted CA might sign
    this certificate, but here we demonstrate a simplified self-sign or 
    server-sign approach for proof-of-concept.

    Attributes:
        public_key (rsa.PublicKey): The RSA public key of the entity.
        identity (str): The entity's identifier (e.g., 'A', 'B', 'C', or 'S').
        signature (bytes): A signature over (identity + public key), 
                           created with an RSA private key.
    """
    def __init__(self, public_key=None, identity=None, signature=None):
        """
        Constructor that initializes the certificate fields.

        :param public_key: An RSA PublicKey object (or None if to be set later).
        :param identity: A string representing the entity identity.
        :param signature: The signature bytes over the identity+public_key data.
        """
        self.public_key: PublicKey = public_key
        self.identity: str = identity
        self.signature: bytes = signature

    def gen_signature(self, private_key: PrivateKey) -> bytes:
        """
        Generates a signature of the (identity + PEM of publicKey) using
        the provided RSA private key. This simulates a self-sign or 
        a signing by some authority.

        Steps:
        1) Concatenate the identity (as UTF-8 bytes) with the public key in PEM format.
        2) Use rsa.sign(...) with SHA-256 to produce a signature.
        3) Store and return that signature.

        :param private_key: The RSA private key used to sign.
        :return: The signature bytes.
        """
        if not self.identity or not self.public_key:
            raise Exception("Certificate identity/public key is not set.")

        # Convert identity to bytes and append the public key's PEM representation
        data_to_sign = self.identity.encode('utf-8') + self.public_key.save_pkcs1('PEM')
        # Produce a digital signature using SHA-256
        self.signature = sign(data_to_sign, private_key, "SHA-256")
        return self.signature

    def export(self) -> bytes:
        """
        Exports the certificate's internal state (public_key, identity, signature)
        as a serialized bytes object. We use the 'pickle' module for convenience.

        :return: A bytes object containing all certificate fields.
        """
        return pickle.dumps(self.__dict__)

    def load(self, file_path=None, data_bytes=None):
        """
        Loads certificate data from either:
          1) A file on disk (if file_path is provided).
          2) A raw bytes object (if data_bytes is provided).

        Exactly one of file_path or data_bytes must be given.

        :param file_path: Path to the .cer file to read.
        :param data_bytes: Raw bytes from which to load the certificate.
        :raises Exception: If both file_path and data_bytes are provided 
                           or neither is provided.
        """
        # Ensure only one data source is used
        if file_path and not data_bytes:
            # Load the dictionary state from the .cer file
            with open(file_path, 'rb') as file:
                self.__dict__ = pickle.load(file, encoding='utf-8')
        elif data_bytes and not file_path:
            # Unpickle directly from the provided bytes
            self.__dict__ = pickle.loads(data_bytes)
        else:
            raise Exception("Provide either file_path or data_bytes, not both.")

    def save(self, file_path=None):
        """
        Saves the certificate object to a specified file_path in a pickled format.
        If no file_path is provided, defaults to 'Certs/Certificate_<identity>.cer'.

        :param file_path: The path where the certificate will be saved.
        """
        if not file_path:
            file_path = f'Certs/Certificate_{self.identity}.cer'
        # Write the object's dictionary to disk using pickle
        with open(file_path, 'wb') as file:
            pickle.dump(self.__dict__, file)
