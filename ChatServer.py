"""
ChatServer.py

This file implements the Secure Chat Server (S).
All communication between A, B, and C goes through this server.
The server does NOT have knowledge of the session key (Kabc). 
It merely forwards messages from one client to the others.

====================================================
HOW TO RUN:
    1) Make sure you have already generated certificates 
       and keys via GenerateCertificates.py
    2) Start the server:
          python ChatServer.py
    3) The server listens for connections. Then start
       ChatClient.py for A, B, C in separate terminals.

To stop the server:
    Press CTRL + C
    (You will be prompted to confirm server shutdown.)

====================================================
"""

import os
import sys
import threading
import signal

from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR

# Dynamically allow importing modules from the "Core_Functions" folder
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(SCRIPT_DIR, "Core_Functions"))

from Core_Functions.Entity import Entity, MESSAGE_BUFFER_SIZE
from Core_Functions.CertificateManager import Certificate
from Core_Functions.MessageProtocol import (
    MessageType, MsgCertResponse, MsgNonceRequest
)

# ---------------------------
# Server Configuration
# ---------------------------
HOST = '127.0.0.1'   # loopback address (localhost)
PORT = 6032          # The port number the server listens on


class ChatServer(Entity):
    """
    The ChatServer class extends from the abstract Entity class
    to provide server-specific functionality. The server acts as
    a central relay node:
    - Accepts client connections (A, B, C).
    - Does NOT hold or know the session key (Kabc).
    - Forwards messages among the connected clients.
    - Manages certificates, storing them and returning them on request.
    """
    def __init__(self, host: str, port: int):
        """
        Initialize the ChatServer by:
         1) Setting identity to 'S' (for server).
         2) Calling super().__init__() to load the server's private key from file.
         3) Preparing the TCP socket to listen on the specified host and port.
         4) Creating dictionaries to track active connections and client IDs.
         5) Loading known certificates (A, B, C, S) from the filesystem.

        :param host: The hostname or IP address where the server will listen.
        :param port: The port number on which the server will accept connections.
        """
        # The server's recognized identity is 'S'
        self.identity = 'S'
        # Load the server's private key (inherited from Entity)
        super().__init__()

        # Create a TCP socket for the server
        self.host = host
        self.port = port
        self.server_socket = socket(AF_INET, SOCK_STREAM)

        # Allow reuse of the address/port if the server is restarted quickly
        self.server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

        # Bind the socket to the host and port
        self.server_socket.bind((self.host, self.port))

        # Dictionaries to manage client connections:
        #   - connections: maps file descriptor => actual socket object
        #   - connection_ids: maps client ID ('A','B','C') => file descriptor
        self.connections = {}
        self.connection_ids = {}

        # A dictionary to store all known certificates for 'A', 'B', 'C', 'S'
        # so they can be provided to clients upon request
        self.certificates = {}
        # Load certificates from the "Certs" folder
        self.load_all_certificates()

    def load_all_certificates(self):
        """
        Loads the certificates for A, B, C, and S from disk,
        storing them in the self.certificates dictionary
        keyed by their identity.
        """
        for entity in ['A', 'B', 'C', 'S']:
            cert = Certificate()
            cert.load(file_path=f"Certs/Certificate_{entity}.cer")
            # e.g., self.certificates['A'] = <Certificate object for A>
            self.certificates[entity] = cert

    def start(self):
        """
        Starts the main server loop:
          1) Puts the server socket into listening mode.
          2) Enters an infinite loop accepting new connections.
          3) For each new connection, spawns a worker thread 
             to handle that client's messages.

        Pressing Ctrl+C triggers a signal_handler that asks 
        for confirmation before shutting down gracefully.
        """
        print(f"[SERVER] Secure Chat Server starting on {self.host}:{self.port}")
        print("[SERVER] Press CTRL + C to initiate server shutdown.\n")
        self.server_socket.listen()

        while True:
            try:
                # Accept a new client connection
                conn, addr = self.server_socket.accept()
            except OSError:
                # This occurs if the socket was closed or interrupted
                break

            print(f"[SERVER] New connection from {addr}")

            # Store the connection in self.connections keyed by the fileno
            self.connections[conn.fileno()] = conn

            # Create a new thread to handle messages from this connected client
            client_thread = threading.Thread(
                target=self.handle_client,
                args=(conn, addr),
                daemon=True
            )
            client_thread.start()

    def handle_client(self, conn: socket, addr):
        """
        The worker thread function for handling a single client connection.
        Continually receives messages from the client until disconnection.

        :param conn: The TCP socket for this client.
        :param addr: The address (host, port) from which the client connected.
        """
        connected = True  # Tracks whether the client is still connected

        while connected:
            try:
                # Receive raw data from the client
                message_bytes = conn.recv(MESSAGE_BUFFER_SIZE)
                if not message_bytes:
                    # An empty bytes object means the client disconnected
                    connected = False
                    break
                # Use the Entity.read_message() method to parse & route the message
                return_val = self.read_message(message_bytes, conn)

                # If return_val is a tuple from _handle_disconnection => (False, client_id)
                if isinstance(return_val, tuple):
                    connected = return_val[0]
                    client_id = return_val[1]

            except ConnectionResetError:
                # This indicates the client process crashed or forcibly closed
                print(f"[SERVER] ConnectionResetError: Client {addr} forcibly disconnected.")
                connected = False
                break
            except Exception as e:
                # Catch general exceptions to keep the server running
                print(f"[SERVER] Exception while reading from client {addr}: {e}")
                connected = False
                break

        # Cleanup when the client is no longer connected
        conn_fileno = conn.fileno()
        # Remove from the connections dictionary if present
        if conn_fileno in self.connections:
            del self.connections[conn_fileno]

        # Also remove the client ID mapping if known
        if 'client_id' in locals() and client_id in self.connection_ids:
            del self.connection_ids[client_id]

        # Close the socket
        conn.close()
        print(f"[SERVER] Connection closed for {addr}.")

    # ----------------------------------------------------------------------
    # IMPLEMENTATION OF THE ABSTRACT METHODS FROM THE PARENT ENTITY CLASS
    # Each of these is how the server handles specific types of messages.
    # ----------------------------------------------------------------------

    def _handle_connection(self, message, socket_ref):
        """
        Called when a client sends a CONNECTION message.
        This message body includes the client's identity (A, B, or C).

        The server:
        - Records the client's ID in connection_ids[client_id] => socket.fileno()
        - Logs a message indicating the client has joined.

        :param message: The incoming MsgConnection
        :param socket_ref: The socket object from the client
        """
        client_id = message.body['identity']
        self.connection_ids[client_id] = socket_ref.fileno()
        print(f"[SERVER] Client {client_id} has identified and joined.")

    def _handle_disconnection(self, message, socket_ref):
        """
        Called when a client sends a DISCONNECT message.
        We then return (False, client_id) so handle_client() can break its loop 
        and finish cleaning up that client connection.
        
        Also broadcasts the disconnection to other connected clients 
        so they can display a "User X disconnected" message in their chat.

        :param message: The incoming MsgDisconnect
        :param socket_ref: The socket object from the disconnecting client
        :return: (False, client_id) to signal the calling thread to end.
        """
        client_id = message.certificate.identity
        print(f"[SERVER] Client {client_id} has requested disconnection.")

        # Broadcast this DISCONNECT message to all other clients
        for cid, fileno in self.connection_ids.items():
            # Skip sending back to the client that is disconnecting
            if cid != client_id:
                self.connections[fileno].send(message.serialize(MESSAGE_BUFFER_SIZE))

        # Returning this tuple signals handle_client() to wrap up
        return False, client_id

    def _handle_encrypted_text(self, message):
        """
        Called when a client sends an ENCRYPTED_TEXT message.
        The server simply forwards this message (still encrypted with Kabc) 
        to all other connected clients.

        The server itself cannot decrypt the message since it doesn't know Kabc.

        :param message: The incoming MsgEncryptedText
        """
        sender_id = message.certificate.identity
        # Just for logging, we take a short preview of the raw ciphertext (first 20 bytes)
        short_text_preview = message.body['encrypted_text'][:20]

        print(f"[SERVER] Forwarding encrypted message from {sender_id}. Preview: {short_text_preview}...")

        # Forward to all other clients except the sender
        for cid, fileno in self.connection_ids.items():
            if cid != sender_id:
                conn = self.connections[fileno]
                conn.send(message.serialize())

    def _handle_cert_request(self, message, socket_ref):
        """
        Called when a client requests certificates for specified entities.
        The server responds with a MsgCertResponse containing those certificates.

        :param message: The incoming MsgCertRequest
        :param socket_ref: The socket object from the requesting client
        """
        request_ids = message.body['requestIDs']
        # Gather the requested certificates from our store
        requested_certs = [self.certificates[rid] for rid in request_ids]

        # Build a response message
        from Core_Functions.MessageProtocol import MsgCertResponse
        response_msg = MsgCertResponse(requested_certs)
        # The server certificate is used as 'certificate' for the response
        response_msg.certificate = self.certificates[self.identity]
        response_msg.gen_signature(self.private_key)

        print(f"[SERVER] Sending certificate response to {message.certificate.identity} "
              f"for requested IDs: {request_ids}")

        # Send the response back to the requesting client
        socket_ref.send(response_msg.serialize(MESSAGE_BUFFER_SIZE))

    def _handle_cert_response(self, message):
        """
        The server should never receive a CERT_RESPONSE in normal flow, 
        because only the server issues certificate responses to clients.

        This method is included only to satisfy the interface and to log unexpected usage.

        :param message: The incoming MsgCertResponse (unexpected)
        """
        print("[SERVER] Received a certificate response unexpectedly. Ignoring.")

    def _handle_nonce_request(self, message, socket_ref):
        """
        Called when a client wants another client to prove identity by responding 
        to a nonce challenge. This is part of the multi-party key establishment.

        The server extracts the relevant data for each target 
        and forwards that portion to the respective target client.

        :param message: The incoming MsgNonceRequest
        :param socket_ref: The socket from the requesting client
        """
        request_ids = message.body['requestIDs']

        # We will forward an individual (sub) MsgNonceRequest to each entity in request_ids
        from Core_Functions.MessageProtocol import MsgNonceRequest
        for rid in request_ids:
            # rid => 'B' or 'C' or whomever is being challenged
            target_socket = self.connections[self.connection_ids[rid]]

            # Create a stripped-down MsgNonceRequest with just the portion relevant to 'rid'
            sub_msg = MsgNonceRequest(
                [rid],
                message.body[rid]['originCert'],
                {rid: message.body[rid]['nonceChallenge']}
            )
            # The server's certificate is used in the forwarded message
            sub_msg.certificate = self.certificates[self.identity]
            sub_msg.gen_signature(self.private_key)

            print(f"[SERVER] Forwarding nonce request to {rid}.")
            # Forward to the target client
            target_socket.send(sub_msg.serialize(MESSAGE_BUFFER_SIZE))

    def _handle_nonce_response(self, message, socket_ref):
        """
        Called when a client responds to a nonce request. 
        The server simply forwards this nonce response to the intended target client.

        :param message: The incoming MsgNonceResponse
        :param socket_ref: The socket from the responding client
        """
        target_id = message.body['target']
        # Ensure the target is still connected
        if target_id not in self.connection_ids:
            print(f"[SERVER] ERROR: Target {target_id} not connected.")
            return

        target_socket = self.connections[self.connection_ids[target_id]]
        msg_bytes = message.serialize(MESSAGE_BUFFER_SIZE)

        print(f"[SERVER] Forwarding nonce response to {target_id}")
        # Forward the nonce response to the client who initiated the challenge
        target_socket.send(msg_bytes)

    # ----------------------------------
    # SIGNAL HANDLER FOR CTRL + C
    # ----------------------------------

    def signal_handler(self, signum, frame):
        """
        Catches CTRL + C (SIGINT), then asks the console user 
        whether to shut down the server or continue.

        If user confirms, we close all client connections, stop the socket, and exit.

        :param signum: The signal number caught (SIGINT).
        :param frame: Stack frame at the point of signal (unused here).
        """
        print("\n[SERVER] CTRL + C caught. Do you want to shut down the server? (Y/N)")
        choice = input().strip().lower()
        if choice == 'y':
            print("[SERVER] Shutting down now. Closing all client connections.")
            # Close all connected clients
            for fileno, conn in list(self.connections.items()):
                conn.close()
            # Close the server socket
            self.server_socket.close()
            # Terminate the process
            os._exit(0)
        else:
            print("[SERVER] Resuming operation. Server continues running.")
            return


def main():
    """
    The main entry point when running this file directly:
      1) Create a ChatServer instance.
      2) Register the signal handler for SIGINT (Ctrl+C).
      3) Call server.start() to begin listening and accepting clients.
    """
    # Instantiate the server
    server = ChatServer(HOST, PORT)
    # Attach a signal handler for graceful shutdown on Ctrl+C
    signal.signal(signal.SIGINT, server.signal_handler)
    # Begin listening for new client connections
    server.start()

# If the file is invoked directly, run main()
if __name__ == "__main__":
    main()
