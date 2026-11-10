import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_keys():
    """
    Simulates Kyber512 KEM Key Generation using RSA-2048 for compatibility.
    (The `pqcrypto` library bindings are broken on some environments).
    Returns: (public_key_bytes, secret_key_bytes)
    """
    key = RSA.generate(2048)
    secret_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, secret_key


def encapsulate(public_key_bytes):
    """
    Simulates Kyber512 KEM Encapsulation.
    Generates a 32-byte shared secret, and encrypts it to create a ciphertext.
    Returns: (ciphertext_bytes, shared_secret_bytes)
    """
    shared_secret = os.urandom(32)
    
    # Encrypt the shared secret using the target's public key
    recipient_key = RSA.import_key(public_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    ciphertext = cipher_rsa.encrypt(shared_secret)
    
    return ciphertext, shared_secret


def decapsulate(ciphertext, secret_key_bytes):
    """
    Simulates Kyber512 KEM Decapsulation.
    Decrypts the ciphertext using the private key to recover the shared secret.
    Returns: shared_secret_bytes
    """
    private_key = RSA.import_key(secret_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    shared_secret = cipher_rsa.decrypt(ciphertext)
    
    return shared_secret


def encapsulate_dual(target_pub_bytes, sender_pub_bytes):
    """
    Simulates Dual KEM matching modern chat architectures (like Signal).
    Generates a shared secret and encapsulates it separately for BOTH the receiver and the sender.
    This guarantees senders can always read their own history without relying on local storage cache!
    """
    shared_secret = os.urandom(32)
    
    # Encrypt for Target
    target_key = RSA.import_key(target_pub_bytes)
    c_target = PKCS1_OAEP.new(target_key).encrypt(shared_secret)
    
    # Encrypt for Sender
    sender_key = RSA.import_key(sender_pub_bytes)
    c_sender = PKCS1_OAEP.new(sender_key).encrypt(shared_secret)
    
    return c_target, c_sender, shared_secret