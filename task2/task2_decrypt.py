#!/usr/bin/env python3
# task2_decrypt.py
# გაშვი: python3 task2_decrypt.py

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad
import hashlib

ENC_FILE = "encrypted_file.bin"
ENC_AES = "aes_key_encrypted.bin"
PRIVKEY = "private.pem"
OUT_DECRYPTED = "decrypted_message.txt"

# Load encrypted AES key and decrypt with RSA private key
with open(PRIVKEY, "rb") as f:
    priv = RSA.import_key(f.read())

with open(ENC_AES, "rb") as f:
    enc_aes_key = f.read()

rsa_cipher = PKCS1_OAEP.new(priv)
aes_key = rsa_cipher.decrypt(enc_aes_key)

# Read encrypted file: first 16 bytes IV
with open(ENC_FILE, "rb") as f:
    filedata = f.read()
iv = filedata[:16]
ciphertext = filedata[16:]

# Decrypt AES-CBC
cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv=iv)
plaintext_padded = cipher_aes.decrypt(ciphertext)
plaintext = unpad(plaintext_padded, AES.block_size)

with open(OUT_DECRYPTED, "wb") as f:
    f.write(plaintext)

# Compute SHA-256 and compare
sha256_new = hashlib.sha256(plaintext).hexdigest()
with open("sha256_original.txt","r") as f:
    sha256_orig = f.read().strip()

print("Decrypted written to:", OUT_DECRYPTED)
print("SHA-256 original:", sha256_orig)
print("SHA-256 decrypted:", sha256_new)
if sha256_new == sha256_orig:
    print("Integrity check: PASS")
else:
    print("Integrity check: FAIL")
