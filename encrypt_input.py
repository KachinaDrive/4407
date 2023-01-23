from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from cryptography.hazmat.primitives.padding import PKCS7

from datetime import datetime



with open("public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(
        f.read(),
        backend=default_backend()
    )

# generate a random AES key
aes_key = os.urandom(32)
iv = os.urandom(16)

val = input("what to encode: ")
val = val.encode('ascii')    

cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()

# Padding the plaintext
padder = PKCS7(128).padder()
padded_data = padder.update(val) + padder.finalize()
ciphertext = encryptor.update(padded_data) + encryptor.finalize()

now = datetime.now()
dt_string = now.strftime("%m-%d-%Y at %H-%M-%S")


file_name = dt_string+".bin"


# Encrypt the AES key with the RSA public key
rsa_cipher = public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

    
    
with open(file_name, "wb") as f:
    f.write(iv)
    f.write(rsa_cipher)
    f.write(ciphertext)
    


