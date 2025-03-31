"""
MessageProtocol.py

Contains classes representing different message types
for our chat application. Each message includes:

- a certificate (public key + identity + signature)
- the message type (enum)
- a body (content depends on the specific message type)
- a signature that covers the combination of the certificate
  bytes + the message body.
"""

from enum import Enum, auto
from pickle import dumps, loads
from hashlib import sha256
from cffi import VerificationError
from rsa import sign, verify, PrivateKey

from Core_Functions.CertificateManager import Certificate


class MessageType(Enum):
    """
    Enumeration of all message types used within our chat system.

    Each enum value corresponds to a distinct structure/flow:
      - CONNECTION: A client connecting/announcing identity
      - DISCONNECT: A client disconnect request
      - ENCRYPTED_TEXT: Chat messages secured with the session key
      - CERT_REQUEST: A request for public key certificates
      - CERT_RESPONSE: A response carrying those certificates
      - NONCE_REQUEST: A request in the key establishment protocol
      - NONCE_RESPONSE: A response in the key establishment protocol
    """
    CONNECTION = auto()      # Initial connection message
    DISCONNECT = auto()      # Disconnection request
    ENCRYPTED_TEXT = auto()  # Chat message (encrypted with session key)
    CERT_REQUEST = auto()    # Request for digital certificates
    CERT_RESPONSE = auto()   # Response carrying the certificates
    NONCE_REQUEST = auto()   # Request for nonce from another entity (key exchange)
    NONCE_RESPONSE = auto()  # Response carrying the encrypted nonce (key exchange)


class Message:
    """
    Base Message class, defining a common structure for all messages:
      - certificate: The sender's certificate (containing its public key, identity, signature)
      - message_type: One of the enumerated MessageType values
      - body: A dictionary of fields relevant to this specific message type
      - signature: A digital signature over the (certificate + body)

    In practice, specialized message subclasses below help define the
    body structure for each message type more explicitly.
    """
    def __init__(self):
        """
        Initializes a fresh message object with blank fields.
        Subclasses or factory methods will populate them accordingly.
        """
        # The sender's certificate (certificate.identity, certificate.public_key, etc.)
        self.certificate: Certificate = Certificate()
        # The message type from the MessageType enum
        self.message_type: MessageType = None
        # A dictionary that holds message-specific data
        self.body: dict = {}
        # A digital signature (bytes) that covers certificate + body
        self.signature: bytes = None

    def gen_signature(self, private_key: PrivateKey) -> bytes:
        """
        Generate a signature for the message using the sender's private key.

        The signature covers: certificate.export() + pickled(body).
        We do:
          1) Serialize the certificate to bytes (certificate.export()).
          2) Serialize the body dictionary deterministically (via pickle).
          3) Concatenate these bytes and sign with RSA + SHA-256.

        :param private_key: RSA PrivateKey used to sign
        :return: The produced signature in bytes
        """
        # Serialize the certificate to bytes
        cert_bytes = self.certificate.export()
        # Serialize the body in a stable manner (pickle)
        body_bytes = dumps(loads(dumps(self.body)))  
        # The extra loads/dumps cycle ensures a consistent pickle format
        self.signature = sign(cert_bytes + body_bytes, private_key, "SHA-256")
        return self.signature

    def verify_signature(self) -> bool:
        """
        Verifies this message's signature using the public key stored
        in self.certificate.public_key.

        We replicate the exact data ordering used in gen_signature():
            certificate.export() + pickled(body).

        :return: True if valid, False otherwise
        """
        cert_bytes = self.certificate.export()
        body_bytes = dumps(loads(dumps(self.body)))

        try:
            # 'verify' will raise VerificationError if signature fails
            verify(cert_bytes + body_bytes, self.signature, self.certificate.public_key)
            return True
        except VerificationError:
            return False

    def serialize(self, total_length: int = 0) -> bytes:
        """
        Serializes the entire Message object into raw bytes for sending over the network.

        If total_length > 0, we pad the serialized data with spaces until
        we reach that total_length. This is sometimes done to ensure a fixed buffer size.

        :param total_length: If > 0, the serialized bytes are padded to this length.
        :return: The serialized (optionally padded) bytes.
        """
        if self.signature is None:
            raise Exception("Message signature not generated. Call gen_signature() first.")

        # Convert the internal __dict__ to bytes via pickle
        raw_data = dumps(self.__dict__)
        if total_length > 0:
            # If the user wants a fixed-length message, pad with spaces
            raw_data += b' ' * (total_length - len(raw_data))
        return raw_data

    def deserialize(self, data: bytes) -> None:
        """
        Loads the Message object state from 'data' bytes.

        We also handle the possibility of trailing spaces from padding by rstrip().

        :param data: The raw bytes to unpickle into this object's __dict__.
        """
        # Remove trailing spaces that might have been used for padding
        trimmed_data = data.rstrip(b' ')
        # Unpickle to set this object's __dict__ directly
        self.__dict__ = loads(trimmed_data)


# ---------------------------------------------------------------------
# Below are specialized message classes that inherit from `Message`.
# Each sets a specific 'message_type' and a structured body dictionary.
# ---------------------------------------------------------------------

class MsgDisconnect(Message):
    """
    Represents a DISCONNECT message. 
    Indicates a client wants to leave the chat or close the connection.
    """
    def __init__(self, certificate: Certificate):
        super().__init__()
        # Set the enum to DISCONNECT
        self.message_type = MessageType.DISCONNECT
        # Attach the sender's certificate
        self.certificate = certificate


class MsgConnection(Message):
    """
    Represents a CONNECTION message, sent by a client upon connecting
    to the server to announce its identity.
    """
    def __init__(self, certificate: Certificate):
        super().__init__()
        # Set the enum to CONNECTION
        self.message_type = MessageType.CONNECTION
        self.certificate = certificate
        # The body here holds the identity, e.g. {'identity': 'A'}
        self.body = {
            'identity': certificate.identity
        }


class MsgEncryptedText(Message):
    """
    Represents an ENCRYPTED_TEXT message, used for actual chat messages.
    The body stores 'iv' and 'encrypted_text' for AES decryption by recipients.
    """
    def __init__(self, encrypted_text: bytes, iv: bytes):
        super().__init__()
        # Set the enum to ENCRYPTED_TEXT
        self.message_type = MessageType.ENCRYPTED_TEXT
        # Populate the body with the IV and the ciphertext
        self.body = {
            'iv': iv,
            'encrypted_text': encrypted_text
        }


class MsgCertRequest(Message):
    """
    A CERT_REQUEST message. A client sends this to the server,
    specifying which entities' certificates it needs.

    The body has:
      'requestIDs': A list of identities, e.g. ['B','C']
    """
    def __init__(self, request_ids: list):
        super().__init__()
        self.message_type = MessageType.CERT_REQUEST
        self.body = {
            'requestIDs': request_ids
        }


class MsgCertResponse(Message):
    """
    A CERT_RESPONSE message. The server sends this back to a client,
    providing the requested certificates.

    The body has:
      'certificates': A list of Certificate objects 
                      for the entities the client asked for.
    """
    def __init__(self, certificates: list):
        super().__init__()
        self.message_type = MessageType.CERT_RESPONSE
        self.body = {
            'certificates': certificates
        }


class MsgNonceRequest(Message):
    """
    A NONCE_REQUEST message for the key establishment protocol.
    One entity (the 'origin') wants to challenge some set of other entities.

    The body has:
      'requestIDs': The list of entities we want to challenge.
      For each entity in requestIDs:
         body[entity] = {
            'originCert': <Certificate of the challenger>,
            'nonceChallenge': <RSA-encrypted challenge>
         }

    This structure allows us to pass multiple target challenges at once
    (though the server typically re-sends them individually).
    """
    def __init__(self, request_ids: list, origin_cert: Certificate, nonce_challenges: dict):
        """
        :param request_ids: A list of target identities, e.g. ['B','C']
        :param origin_cert: The challenger's certificate
        :param nonce_challenges: A dict mapping target_id => RSA-encrypted challenge
        """
        super().__init__()
        self.message_type = MessageType.NONCE_REQUEST
        self.body = {
            'requestIDs': request_ids
        }
        # For each target, embed the originCert and the RSA-encrypted challenge
        for entity_id in request_ids:
            self.body[entity_id] = {
                'originCert': origin_cert,
                'nonceChallenge': nonce_challenges[entity_id]
            }


class MsgNonceResponse(Message):
    """
    A NONCE_RESPONSE message in the key establishment protocol.
    Sent by a challenged entity back to the origin, containing:
      - That entity's own nonce, RSA-encrypted with the origin's public key
      - The original challenge from the origin, re-encrypted with the origin's public key
        (to prove correct decryption)

    The body has:
      'target': The origin's identity (who should receive this response)
      'originCert': The responding entity's certificate
      'encrypted_nonce': The responding entity's nonce, RSA-encrypted
      'nonce_challenge_response': The re-encrypted challenge from the origin
    """
    def __init__(self, target: str, origin_cert: Certificate, encrypted_nonce: bytes, nonce_challenge_response: bytes):
        super().__init__()
        self.message_type = MessageType.NONCE_RESPONSE
        self.body = {
            'target': target,
            'originCert': origin_cert,
            'encrypted_nonce': encrypted_nonce,
            'nonce_challenge_response': nonce_challenge_response
        }
