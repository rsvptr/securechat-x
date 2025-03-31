"""
GenerateCertificates.py

Generates fresh RSA keys and self-signed public-key certificates
for entities A, B, C, and Server S.

Run this file once (only if you wish to generate new certificates 
and keys). The result will be:
  - PrivateKey_<Entity>.pem  (in Keys folder)
  - Certificate_<Entity>.cer (in Certs folder)

After generation, use these certificates and keys in 
ChatServer.py and ChatClient.py to run the secure chat.
"""

import os
import sys

# Make sure we can import from Core_Functions
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(SCRIPT_DIR, "Core_Functions"))

from Core_Functions.CertificateManager import Certificate

from rsa import newkeys

def create_directories():
    """
    Utility function to ensure that the 'Certs' and 'Keys' directories exist.
    If they don't, this function creates them. This prevents errors when 
    writing certificate or key files.
    """
    if not os.path.exists("Certs"):
        os.makedirs("Certs")
    if not os.path.exists("Keys"):
        os.makedirs("Keys")

def main():
    """
    Main function that:
      1) Creates the necessary directories ('Certs' and 'Keys').
      2) Iterates over the identities ['S', 'A', 'B', 'C'] to generate RSA key pairs.
      3) Creates a certificate object (Certificate) for each entity.
      4) Self-signs or server-signs each certificate. 
      5) Writes the private keys to 'Keys/PrivateKey_<Entity>.pem'.
      6) Writes the certificates to 'Certs/Certificate_<Entity>.cer'.

    This procedure simulates a lightweight PKI: 
    - 'S' is treated as a CA that signs the certificates for 'A','B','C'.
    - 'S' itself can self-sign or consider itself the root authority.
    """
    print("============================================")
    print("   Generate Certificates & RSA Key Pairs")
    print("============================================\n")

    # Ensure output folders exist
    create_directories()

    # Define the identities (including the server 'S')
    entities = ['A', 'B', 'C', 'S']
    
    # Step 1: Generate the server's certificate and private key
    #         This also simulates the server acting as a CA for demonstration.
    print("[*] Generating keys and certificate for Server (S)...")
    cert_s = Certificate(identity='S')
    # newkeys(2048) -> returns (pub_key, priv_key)
    pub_key_s, priv_key_s = newkeys(2048)   # 2048-bit RSA key pair
    cert_s.public_key = pub_key_s
    # Self-sign the certificate (or treat it as root)
    cert_s.gen_signature(priv_key_s)

    # Write the server's private key to file
    with open("Keys/PrivateKey_S.pem", "wb") as f:
        f.write(priv_key_s.save_pkcs1('PEM'))

    # Save the server's certificate (pickled format)
    cert_s.save("Certs/Certificate_S.cer")

    print("    -> Server's certificate and private key created.\n")

    # Step 2: Generate certificates for A, B, and C
    #         The server's private key (priv_key_s) is used to sign them.
    for entity in ['A', 'B', 'C']:
        print(f"[*] Generating keys and certificate for Entity {entity}...")
        cert = Certificate(identity=entity)
        # Generate a new 2048-bit RSA key pair
        pub_key, priv_key = newkeys(2048)
        cert.public_key = pub_key
        
        # Here, we simulate the server signing the client's certificate
        cert.gen_signature(priv_key_s)
        
        # Write the private key
        with open(f"Keys/PrivateKey_{entity}.pem", "wb") as f:
            f.write(priv_key.save_pkcs1('PEM'))

        # Write the certificate
        cert.save(f"Certs/Certificate_{entity}.cer")
        print(f"    -> {entity}'s certificate and private key created.\n")

    print("All certificates and keys have been generated and saved.")
    print("Certificates => 'Certs/' directory")
    print("Private Keys => 'Keys/' directory\n")
    print("[Done]")

# If this file is run directly (instead of being imported), call main()
if __name__ == "__main__":
    main()
