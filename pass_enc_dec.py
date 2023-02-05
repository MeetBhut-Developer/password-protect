import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac

key = os.urandom(16) # Generate a random 128-bit key

def encrypt_password(password):
    padder = padding.PKCS7(128).padder()
    password = padder.update(password.encode('utf-8')) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.GCM(b'\x00' * 12), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(password) + encryptor.finalize()
    return (ciphertext + encryptor.tag).hex()

def decrypt_password(encrypted_password):
    encrypted_password = bytes.fromhex(encrypted_password)
    tag = encrypted_password[-16:]
    encrypted_password = encrypted_password[:-16]
    cipher = Cipher(algorithms.AES(key), modes.GCM(b'\x00' * 12, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    password = decryptor.update(encrypted_password) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    password = unpadder.update(password) + unpadder.finalize()
    return password.decode('utf-8')

enc = encrypt_password('simple_password')
print(enc)

dec = decrypt_password(input("Enter encrypted password: "))
print(dec)
