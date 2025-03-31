"""
ChatClient.py

Implements the secure chat client for either A, B, or C.

Communications:
1) The client connects to the server (S).
2) Press ENTER to start the session key establishment with B and C (or whoever is needed).
3) Once the session key (Kabc) is established, user can type messages to send 
   (encrypted with Kabc).

Usage:
    python ChatClient.py <ID>

Where <ID> is one of A, B, or C.

Press CTRL + C at any time to attempt a graceful exit:
    - The client will ask for confirmation.
    - On "Y", it sends a disconnection message to the server.

NOTE: This file relies on several helper classes from the Core_Functions folder:
      - Entity (abstract base class providing a standard message handling framework)
      - CertificateManager (for handling public key certificates)
      - EncryptionManager (for AES encryption/decryption)
      - MessageProtocol (for consistent message structures/serialization)
"""

import os
import sys
import signal
import select

# Import msvcrt for Windows-specific keyboard input handling, set to None on non-Windows
if os.name == 'nt': 
    import msvcrt
else: 
    msvcrt = None

from socket import socket, AF_INET, SOCK_STREAM
from random import randint

# Dynamically allow importing modules from the "Core_Functions" folder
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(SCRIPT_DIR, "Core_Functions"))

# Import classes and functions from our "Core_Functions" subpackage
from Core_Functions.Entity import Entity, MESSAGE_BUFFER_SIZE
from Core_Functions.CertificateManager import Certificate
from Core_Functions.EncryptionManager import aes_encrypt, aes_decrypt
from Core_Functions.MessageProtocol import (
    MsgConnection, MsgDisconnect, MsgEncryptedText,
    MsgCertRequest, MsgCertResponse, 
    MsgNonceRequest, MsgNonceResponse
)

from rsa import encrypt, decrypt
from Cryptodome.Random import get_random_bytes
from hashlib import sha256
from termcolor import colored

# ---------------------------
# Client Configuration Constants
# ---------------------------
HOST = '127.0.0.1'   # Host/IP of the server
PORT = 6032          # Port the server is listening on

class ChatClient(Entity):
    """
    The ChatClient class represents one of the entities: A, B, or C.
    It inherits from the abstract Entity class to handle message processing.

    Responsibilities:
    1) Connect to the server (S) via TCP.
    2) Request certificate(s) for other entities from the server.
    3) Perform the nonce-based key agreement protocol to derive a shared session key Kabc.
    4) Once Kabc is established, encrypt chat messages with it and send them to the server for relaying.
    5) Display incoming encrypted chat messages (decrypt them with Kabc).

    Internal data tracked includes:
    - self.identity: 'A', 'B', or 'C'
    - self.client_socket: the TCP socket
    - self.public_keys: dictionary of public keys for the other entities
    - self.session_key: the derived shared session key Kabc
    - self.nonces: a dictionary storing our own nonce and the nonces of each other entity
    - self.nonce_challenge: a random integer used to verify that we are receiving correct nonce responses
    - self._terminal_screen, self._terminal_colors: for storing and colorizing chat output
    """
    def __init__(self, client_id: str):
        """
        Initialize a ChatClient object by performing:
        - Validation of the provided client ID (must be 'A', 'B', or 'C')
        - Setting self.identity
        - Loading private key (done via super().__init__())
        - Preparing the client socket
        - Setting up data structures for nonces and public keys
        - Loading the entity certificate (Certificate_A.cer, etc.)

        :param client_id: A string representing the entity identity: 'A', 'B', or 'C'
        """
        # Validate the identity to ensure it is one of the expected ones
        valid_ids = ['A', 'B', 'C']
        if client_id.upper() not in valid_ids:
            raise Exception("Invalid Identity. Must be A, B, or C.")

        # Store the identity in uppercase form (A, B, or C)
        self.identity = client_id.upper()

        # Initialize the parent class (Entity) which loads our private key
        super().__init__()

        # Create a TCP socket for the client
        self.client_socket = socket(AF_INET, SOCK_STREAM)

        # Prepare a list of all possible entities and then remove our own identity
        self.entities = ['A', 'B', 'C']
        self.entities.remove(self.identity)  # We only need the other two

        # Prepare a dictionary to keep track of each entity's nonce
        # We generate our own nonce for ourselves right away (16 bytes random)
        self.nonces = {
            self.identity: get_random_bytes(16)
        }

        # nonce_challenge: used as a random integer for verifying other entities
        self.nonce_challenge = -1  # Will be assigned a random int during protocol

        # This will hold the server's public key once we receive it (if needed)
        self.server_public_key = None

        # This dictionary will map entity ID => RSA Public Key object
        self.public_keys = {}

        # This will eventually hold the derived session key Kabc (16 bytes)
        self.session_key = None

        # Terminal buffer to store chat lines and color them
        self._terminal_screen = []
        self._terminal_colors = []

        # Define a function to clear the console (works on Windows, Mac, Linux)
        self.clear_console = lambda: os.system('cls' if os.name in ('nt','dos') else 'clear')

        # Define a color map for printing chat lines in different colors
        self.color_map = {
            'A': 'cyan',
            'B': 'green',
            'C': 'magenta',
            'X': 'yellow',   # 'X' can be used for debug/system
            'SYSTEM': 'white'
        }

        # Load our own certificate from the "Certs" folder (e.g. "Certificate_A.cer")
        self.certificate = Certificate()
        self.certificate.load(file_path=f"Certs/Certificate_{self.identity}.cer")

    def connect_to_server(self, host: str, port: int):
        """
        Connects this client to the specified server endpoint (host, port).
        Upon successful connection, it sends a MsgConnection message 
        containing our certificate to identify ourselves to the server.

        :param host: The hostname/IP for the server
        :param port: The port number on which the server is listening
        """
        print(f"[CLIENT {self.identity}] Connecting to server {host}:{port} ...")
        try:
            # Attempt to connect to the server
            self.client_socket.connect((host, port))
            print(f"[CLIENT {self.identity}] Successfully connected!")
        except ConnectionRefusedError:
            # This error indicates the connection was refused (server not running?)
            print(f"[CLIENT {self.identity}] ERROR: Server not available at {host}:{port}.")
            sys.exit(1)

        # Immediately upon connecting, send a MsgConnection message
        # containing our certificate to identify ourselves to the server
        conn_msg = MsgConnection(self.certificate)
        conn_msg.gen_signature(self.private_key)
        self.client_socket.send(conn_msg.serialize())

        # Prompt the user to press ENTER to start the key exchange process
        print(f"[CLIENT {self.identity}] Press ENTER to start session key exchange with other entities.")

        # Start the main input loop, depending on OS
        if os.name in ['nt','dos']:
            # On Windows, handle input using a custom loop
            self._windows_loop()
        else:
            # On Unix-based systems (Linux/Mac), we can use select on sys.stdin
            self._unix_loop()

    # ---------------------------
    # MAIN LOOPS FOR USER INPUT AND SOCKET RECEPTION
    # ---------------------------

    def _unix_loop(self):
        """
        Main event loop for Unix-based systems. 
        Uses the 'select' system call to wait on both:
          - sys.stdin (keyboard input)
          - self.client_socket (incoming network data)

        Because Windows does not treat sys.stdin the same way, 
        a separate method (_windows_loop) is used for Windows.
        """
        got_session_key = False  # Track if we have completed key establishment

        while True:
            try:
                # We'll watch these two file descriptors: console input and our socket
                sock_list = [sys.stdin, self.client_socket]
                read_socks, _, _ = select.select(sock_list, [], [])

                # read_socks will contain whichever is ready (keyboard or socket or both)
                for s in read_socks:
                    if s == self.client_socket:
                        # Data from the server
                        data = s.recv(MESSAGE_BUFFER_SIZE)
                        if not data:
                            # If there's no data, it likely means server disconnected or something
                            print(f"\n[CLIENT {self.identity}] Connection lost with server. Disconnecting...")
                            self.client_socket.close()
                            sys.exit(0)
                        self.read_message(data)  # Let the inherited Entity method handle the message
                    else:
                        # This means user typed something at the console (sys.stdin)
                        user_input = sys.stdin.readline().rstrip('\n')
                        # If we don't yet have the session key, pressing ENTER triggers the key exchange
                        if not got_session_key:
                            # Start session key establishment
                            self.obtain_session_key()
                            got_session_key = True
                        else:
                            # Otherwise, we're just sending a normal chat message
                            if user_input.strip():
                                self.send_encrypted_message(user_input)
                                self._update_terminal(f"{self.identity}(You) > {user_input}", self.identity)
            except KeyboardInterrupt:
                # If the user presses CTRL + C, handle a graceful exit prompt
                self._client_exit_prompt()
            except Exception as e:
                print(f"[CLIENT {self.identity}] Exception in _unix_loop: {e}")

    def _windows_loop(self):
        """
        Main event loop for Windows systems.
        Because Windows doesn't allow using 'select' in the same way on sys.stdin,
        we check for keypresses using 'msvcrt.kbhit()' and collect data with input().
        Meanwhile, we also check for incoming socket data using 'select' on the socket only.

        The logic is similar to the Unix loop but split for Windows limitations.
        """
        import msvcrt
        got_session_key = False  # Track if key establishment is done

        while True:
            try:
                # Check if there's incoming data on the client socket
                ready_socks, _, _ = select.select([self.client_socket], [], [], 0.1)
                
                if ready_socks:
                    data = self.client_socket.recv(MESSAGE_BUFFER_SIZE)
                    if not data:
                        print(f"\n[CLIENT {self.identity}] Connection lost with server. Disconnecting...")
                        self.client_socket.close()
                        sys.exit(0)
                    self.read_message(data)

                # Check if user pressed a key
                if msvcrt.kbhit():
                    # If user pressed ENTER the first time => do key exchange
                    user_input = input()
                    if not got_session_key:
                        self.obtain_session_key()
                        got_session_key = True
                    else:
                        # Otherwise it's just a normal chat message
                        if user_input.strip():
                            self.send_encrypted_message(user_input)
                            self._update_terminal(f"{self.identity}(You) > {user_input}", self.identity)

            except KeyboardInterrupt:
                # Handle CTRL + C gracefully
                self._client_exit_prompt()
            except Exception as e:
                print(f"[CLIENT {self.identity}] Exception in _windows_loop: {e}")

    # ---------------------------
    # HELPER METHODS
    # ---------------------------

    def _client_exit_prompt(self):
        """
        Called if the user presses CTRL + C.
        Prompts the user for confirmation to exit the chat.
        If yes, sends a disconnection message to the server and exits.
        If no, resumes the chat.
        """
        print(f"\n[CLIENT {self.identity}] CTRL + C caught. Do you want to exit chat? (Y/N)")
        choice = input().strip().lower()
        if choice == 'y':
            # User confirms exit
            self.send_disconnection_message()
            print(f"[CLIENT {self.identity}] Disconnecting now...")
            self.client_socket.close()
            sys.exit(0)
        else:
            # User wants to continue chatting
            print(f"[CLIENT {self.identity}] Resuming chat.")
            return

    def _update_terminal(self, text_line: str, sender: str = 'SYSTEM'):
        """
        Maintains a buffer of chat lines to display in the terminal.
        Clears the screen, then reprints all lines in the buffer with 
        color-coding determined by 'sender'.

        :param text_line: The new line of text to append
        :param sender: Typically 'A', 'B', 'C', or 'SYSTEM' for color-coding
        """
        # Append the new chat line and corresponding color
        self._terminal_screen.append(text_line)
        self._terminal_colors.append(self.color_map.get(sender, 'white'))

        # Clear the console
        self.clear_console()

        # Reprint all stored lines with their assigned colors
        for line, color in zip(self._terminal_screen, self._terminal_colors):
            print(colored(line, color))

    def send_disconnection_message(self):
        """
        Sends a MsgDisconnect to the server. 
        This indicates we (the client) are going offline or leaving the chat.
        """
        disc_msg = MsgDisconnect(self.certificate)
        disc_msg.gen_signature(self.private_key)
        self.client_socket.send(disc_msg.serialize())

    def send_encrypted_message(self, text: str):
        """
        Encrypts the text using the established session key (Kabc) 
        and sends it to the server inside a MsgEncryptedText.

        Also handles a special command "!disconnect" to force a disconnection.

        :param text: The plaintext message the user typed
        """
        # Allow a special user command "!disconnect" to gracefully exit
        if text.strip().lower() == "!disconnect":
            self.send_disconnection_message()
            print(f"[CLIENT {self.identity}] You used '!disconnect' command. Exiting now.")
            sys.exit(0)

        # Perform AES encryption of the user's text with the session key
        ciphertext, iv, _ = aes_encrypt(text.encode('utf-8'), self.session_key)
        msg = MsgEncryptedText(ciphertext, iv)
        msg.certificate = self.certificate
        msg.gen_signature(self.private_key)
        self.client_socket.send(msg.serialize())

    # ---------------------------
    # SECURE SESSION KEY ESTABLISHMENT
    # ---------------------------

    def obtain_session_key(self):
        """
        Initiates the full key establishment protocol:

        Step 1) Ask the server for certificates of the other entities we plan 
                to communicate with (B and C, if we are A, etc.).
        Step 2) The server responds with MsgCertResponse (handled in _handle_cert_response).
        Step 3) We then send a MsgNonceRequest to each target, containing a random challenge 
                that they must re-encrypt to prove identity.
        Step 4) We await the MsgNonceResponse from each target. 
        Step 5) Once we collect all nonces from the other entities, we combine them with 
                our own to derive the session key Kabc.

        After these steps, self.session_key will be set and can be used for encryption/decryption.
        """
        print(f"[CLIENT {self.identity}] Requesting certificates for: {self.entities}")
        # Create a MsgCertRequest listing the identities for which we want certificates
        cert_req_msg = MsgCertRequest(self.entities)
        cert_req_msg.certificate = self.certificate
        cert_req_msg.gen_signature(self.private_key)

        # Send the certificate request to the server
        self.client_socket.send(cert_req_msg.serialize(MESSAGE_BUFFER_SIZE))
        # We'll wait for the server to respond in _handle_cert_response()

    def _send_nonce_request(self, targets: list):
        """
        Step 3 of the protocol:
        We generate a random integer challenge (nonce_challenge).
        For each target, we encrypt that challenge with the target's public key.
        We then bundle those encrypted challenges into a MsgNonceRequest 
        and send it to the server, which forwards to each target.

        :param targets: A list of entity IDs (e.g. ['B','C']) to challenge
        """
        # Generate a random integer challenge
        self.nonce_challenge = randint(1000000, 9999999)
        challenge_bytes = self.nonce_challenge.to_bytes(4, 'little')  # 4 bytes in little-endian

        # Prepare a map of target_id => RSA-encrypted challenge
        challenge_map = {}
        for target in targets:
            pub_key = self.public_keys[target]  # The target's RSA public key
            challenge_map[target] = encrypt(challenge_bytes, pub_key)

        # Construct the MsgNonceRequest with all the encrypted challenges
        nr_msg = MsgNonceRequest(targets, self.certificate, challenge_map)
        nr_msg.certificate = self.certificate
        nr_msg.gen_signature(self.private_key)

        # Send it to the server. The server will forward to each target individually.
        self.client_socket.send(nr_msg.serialize(MESSAGE_BUFFER_SIZE))

    def _finalize_session_key(self):
        """
        Once we have collected all nonces from each entity 
        (including our own nonce in self.nonces), we combine them 
        to form the final session key.

        This example code performs a bitwise OR over all the nonces 
        to get a combined value, then takes the SHA-256 hash of that value, 
        and finally uses the first 16 bytes of that hash as Kabc.

        This ensures each participant's nonce influences the final key, 
        and the server has no knowledge of these nonces.
        """
        combined_value = 0
        # Combine all known nonces (our own + others)
        for ent, nonce in self.nonces.items():
            combined_value |= int.from_bytes(nonce, 'big')

        # Hash the combined value with SHA-256
        hashed = sha256(combined_value.to_bytes(16, 'big')).digest()
        # Truncate the hash to 16 bytes (128 bits) for the AES key
        self.session_key = hashed[:16]

        # Update the chat window to indicate the session key is now established
        self._update_terminal(">> Session key established! All future messages are end-to-end encrypted <<", 'SYSTEM')

    # ---------------------------
    # REQUIRED ABSTRACT METHOD OVERRIDES (from Entity.py)
    # For handling different message types
    # ---------------------------

    def _handle_connection(self, message, socket_ref):
        """
        Handler for an incoming CONNECTION message.
        In a client, we generally do not expect to handle other entities' 
        connection messages. The server handles that.

        So here, we do nothing. It's just required by the abstract interface.
        """
        pass

    def _handle_disconnection(self, message, socket_ref):
        """
        Handler for an incoming DISCONNECT message from another client 
        or possibly from the server. 
        We display a notification in our chat window.

        :param message: The incoming MsgDisconnect
        :param socket_ref: The socket from which it originated (not used here).
        """
        disc_id = message.certificate.identity
        self._update_terminal(f"[CLIENT {self.identity}] Received disconnection notice from {disc_id}.", 'SYSTEM')

    def _handle_encrypted_text(self, message):
        """
        Handler for an incoming ENCRYPTED_TEXT message. 
        We decrypt it with the session key (Kabc) and display in our console.

        :param message: The incoming MsgEncryptedText
        """
        # If we don't yet have a session key, we can't decrypt; ignore
        if not self.session_key:
            return

        ciphertext = message.body['encrypted_text']
        iv = message.body['iv']
        # Decrypt the message using AES in CBC mode
        plaintext = aes_decrypt(ciphertext, iv, self.session_key).decode('utf-8')
        sender = message.certificate.identity
        # Display it in the chat
        self._update_terminal(f"{sender} > {plaintext}", sender)

    def _handle_cert_request(self, message, socket_ref):
        """
        Handler for CERT_REQUEST messages.
        Clients do not handle certificate requests. 
        Only the server is expected to handle these.
        So we do nothing here.
        """
        pass

    def _handle_cert_response(self, message):
        """
        Handler for CERT_RESPONSE messages (step 2 in the key setup).
        The server is sending us the certificates for the requested entities.

        We extract each certificate from the response, store the public key in 
        self.public_keys for each entity, then move on to step 3 
        (sending a NonceRequest).
        """
        # Extract the list of certificates from the message body
        certs = message.body['certificates']
        for c in certs:
            # Store the certificate's public key in a dictionary
            self.public_keys[c.identity] = c.public_key

        print(f"[CLIENT {self.identity}] Certificates received from server. Proceeding with nonce requests.")
        
        # Now that we have the necessary public keys, send the NonceRequest
        self._send_nonce_request(self.entities)

    def _handle_nonce_request(self, message, socket_ref):
        """
        Handler for NONCE_REQUEST messages from another entity (via the server).
        This means some other client is requesting that we prove we are real by 
        re-encrypting their challenge. We also share our own nonce in the response.

        Steps:
        1) Check if our identity is in the requestIDs
        2) Decrypt the challenge from the requesting entity with our private key
        3) Re-encrypt that challenge with their public key
        4) Send back our own nonce, also encrypted with their public key
        5) Construct and send a MsgNonceResponse to the server, which will forward it
        """
        req_ids = message.body['requestIDs']
        # If this request isn't actually for us, ignore
        if self.identity not in req_ids:
            return

        # The request for our identity is in message.body[self.identity]
        info = message.body[self.identity]
        origin_cert = info['originCert']             # The requesting entity's cert
        their_challenge = info['nonceChallenge']     # RSA-encrypted challenge from them

        # Decrypt their challenge with our private key
        decrypted_challenge = decrypt(their_challenge, self.private_key)

        # Re-encrypt the challenge with the requesting entity's public key
        # to prove we decrypted it successfully
        re_encrypted_challenge = encrypt(decrypted_challenge, origin_cert.public_key)

        # Also encrypt our own nonce (self.nonces[self.identity]) 
        # with the requester's public key to share our nonce
        from Core_Functions.MessageProtocol import MsgNonceResponse
        enc_my_nonce = encrypt(self.nonces[self.identity], origin_cert.public_key)

        # Build the MsgNonceResponse that includes:
        # - The target's identity (who should receive this)
        # - Our certificate
        # - Our nonce, encrypted
        # - The re-encrypted challenge
        nrsp = MsgNonceResponse(
            target=origin_cert.identity,
            origin_cert=self.certificate,
            encrypted_nonce=enc_my_nonce,
            nonce_challenge_response=re_encrypted_challenge
        )
        nrsp.certificate = self.certificate
        nrsp.gen_signature(self.private_key)

        # Send the response back to the server, which forwards it
        self.client_socket.send(nrsp.serialize(MESSAGE_BUFFER_SIZE))
        print(f"[CLIENT {self.identity}] Responded to nonce request from {origin_cert.identity} with my nonce.")

    def _handle_nonce_response(self, message, socket_ref):
        """
        Handler for NONCE_RESPONSE messages sent by other entities 
        in response to our NonceRequest (step 4 in the protocol).

        We:
        1) Verify the re-encrypted challenge matches our nonce_challenge.
        2) Decrypt the other entity's nonce and store it.
        3) If we've collected all nonces from all entities, finalize the session key.
        """
        origin_cert = message.body['originCert']
        origin_id = origin_cert.identity

        # The RSA-encrypted nonce from the responding entity
        enc_nonce = message.body['encrypted_nonce']
        # The re-encrypted version of our original challenge
        challenge_resp = message.body['nonce_challenge_response']

        # 4a) Verify the challenge by decrypting with our private key
        decrypted_challenge = decrypt(challenge_resp, self.private_key)
        numeric_challenge = int.from_bytes(decrypted_challenge, 'little')
        if numeric_challenge != self.nonce_challenge:
            print(f"[CLIENT {self.identity}] WARNING: Challenge mismatch from {origin_id}!")
            return

        # 4b) Decrypt the entity's nonce with our private key
        entity_nonce = decrypt(enc_nonce, self.private_key)

        # Store the other entity's nonce
        self.nonces[origin_id] = entity_nonce
        print(f"[CLIENT {self.identity}] Received and stored nonce from {origin_id}.")

        # Check if we have nonces from all entities (including ourselves)
        if len(self.nonces) == len(self.entities) + 1:
            # +1 for ourselves
            print(f"[CLIENT {self.identity}] All nonces collected. Finalizing session key...")
            self._finalize_session_key()


def main():
    """
    Entry point if this script is run directly.
    Expects a command-line argument for the identity: python ChatClient.py <ID>
    Where <ID> is 'A', 'B', or 'C'.

    Creates a ChatClient instance and connects to the server.
    """
    if len(sys.argv) < 2:
        print("Usage: python ChatClient.py <ID>")
        print("Where <ID> = A, B, or C.")
        sys.exit(0)

    client_id = sys.argv[1].upper()
    if client_id not in ['A', 'B', 'C']:
        print("Error: Identity must be 'A', 'B', or 'C'.")
        sys.exit(0)

    # Instantiate the client and connect
    client = ChatClient(client_id)
    client.connect_to_server(HOST, PORT)

# If run as a script, call main()
if __name__ == "__main__":
    main()
