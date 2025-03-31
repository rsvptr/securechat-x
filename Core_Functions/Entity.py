"""
Entity.py

Defines an abstract base class for both ChatServer and ChatClient.
They share:
  - a private key
  - a method to read/parse incoming messages
  - abstract methods for reading specific message types

All actual code is in ChatServer/ChatClient, 
but they both inherit from this class.
"""

import os
import sys

from abc import ABC, abstractmethod
from rsa import PrivateKey

# We are reusing the same message structure
from Core_Functions.MessageProtocol import (
    Message,
    MessageType
)

# A fixed buffer size for reading incoming messages.
MESSAGE_BUFFER_SIZE = 4096 * 3  # 12KB


class Entity(ABC):
    """
    Abstract base class that both ChatServer and ChatClient extend.
    Provides:
    1) Automatic loading of the RSA private key from a file,
       determined by an 'identity' attribute (e.g. 'A', 'B', 'C', 'S').
    2) A read_message method that deserializes a message, verifies its signature,
       and dispatches it to specialized handler methods based on MessageType.

    Derived classes must override the abstract methods below to handle each
    message type appropriately.
    """
    def __init__(self):
        """
        Constructor that expects the child class to have already set self.identity
        (e.g., 'A', 'B', 'C', 'S'). Then it loads the private key corresponding
        to that identity from the Keys folder using load_private_key().
        """
        # Ensure the child has specified an identity before calling super().__init__()
        if not hasattr(self, 'identity'):
            raise Exception("Child class must define 'self.identity' before super().__init__() is called.")

        self.private_key: PrivateKey = None  # Will store the loaded RSA private key object
        self.load_private_key()

    def load_private_key(self) -> None:
        """
        Loads the private key from 'Keys/PrivateKey_<identity>.pem'.
        The file name is derived from self.identity. For example,
        if identity == 'A', we look for 'Keys/PrivateKey_A.pem'.
        """
        key_path = f'Keys/PrivateKey_{self.identity}.pem'
        if not os.path.exists(key_path):
            raise FileNotFoundError(f"Private key file not found: {key_path}")

        # Read the key file and load it into an RSA PrivateKey object
        with open(key_path, 'rb') as file:
            self.private_key = PrivateKey.load_pkcs1(file.read(), 'PEM')

    def read_message(self, raw_bytes: bytes, socket_ref=None):
        """
        Deserializes a Message object from raw_bytes, verifies the signature,
        and then calls the correct handler method based on message_type.

        :param raw_bytes: The raw serialized message received from a socket
        :param socket_ref: Optional reference to the socket from which the data came.
                           The server uses this to send responses or forward data
                           to other clients. The client may ignore this parameter.
        :return: Can return a tuple or a status code that the caller uses for logic
        """
        if not raw_bytes:
            # If there's no data, possibly the connection closed or no content was received
            return

        # Create a Message object and deserialize from raw bytes
        message = Message()
        message.deserialize(raw_bytes)

        # Verify the message signature using the sender's public key (in message.certificate)
        if not message.verify_signature():
            print("[!] WARNING: Message signature verification FAILED.")
            return

        # Based on the message_type, we delegate to a specialized method
        if message.message_type == MessageType.ENCRYPTED_TEXT:
            return self._handle_encrypted_text(message)
        elif message.message_type == MessageType.CERT_REQUEST:
            return self._handle_cert_request(message, socket_ref)
        elif message.message_type == MessageType.CERT_RESPONSE:
            return self._handle_cert_response(message)
        elif message.message_type == MessageType.NONCE_REQUEST:
            return self._handle_nonce_request(message, socket_ref)
        elif message.message_type == MessageType.NONCE_RESPONSE:
            return self._handle_nonce_response(message, socket_ref)
        elif message.message_type == MessageType.CONNECTION:
            return self._handle_connection(message, socket_ref)
        elif message.message_type == MessageType.DISCONNECT:
            return self._handle_disconnection(message, socket_ref)

    # Abstract methods to be implemented by subclasses (ChatServer or ChatClient)
    # Each method corresponds to a different type of message that might be received.

    @abstractmethod
    def _handle_encrypted_text(self, message: Message):
        """
        Called when we receive a MessageType.ENCRYPTED_TEXT.
        The server forwards such messages to other clients.
        The client decrypts and displays the message.
        """
        pass

    @abstractmethod
    def _handle_cert_request(self, message: Message, socket_ref):
        """
        Called when we receive a MessageType.CERT_REQUEST.
        The server is expected to respond with the requested certificates.
        The client typically doesn't handle such a request (only the server does).
        """
        pass

    @abstractmethod
    def _handle_cert_response(self, message: Message):
        """
        Called when we receive a MessageType.CERT_RESPONSE.
        The client uses this to store public keys from the server.
        The server generally doesn't expect to receive a certificate response.
        """
        pass

    @abstractmethod
    def _handle_nonce_request(self, message: Message, socket_ref):
        """
        Called when we receive a MessageType.NONCE_REQUEST.
        This is part of the key establishment protocol, 
        where one entity challenges another to prove identity and share a nonce.
        """
        pass

    @abstractmethod
    def _handle_nonce_response(self, message: Message, socket_ref):
        """
        Called when we receive a MessageType.NONCE_RESPONSE.
        This is the response to a previous challenge, containing the responding
        entity's nonce and a re-encrypted challenge for verification.
        """
        pass

    @abstractmethod
    def _handle_connection(self, message: Message, socket_ref):
        """
        Called when we receive a MessageType.CONNECTION.
        The client sends this upon connecting, identifying itself.
        The server records the identity. Clients typically ignore this message.
        """
        pass

    @abstractmethod
    def _handle_disconnection(self, message: Message, socket_ref):
        """
        Called when we receive a MessageType.DISCONNECT.
        The client or server uses this to handle a user leaving the chat.
        """
        pass
