#!/usr/bin/env python3
# task2_encrypt.py
# გაშვი: python3 task2_encrypt.py

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib

# ფაილები
PLAINTEXT = "alice_message.txt"
OUT_ENC = "encrypted_file.bin"
OUT_KEY_ENC = "aes_key_encrypted.bin"
PUBKEY = "public.pem"

# Step: generate AES-256 key + IV
aes_key = get_random_bytes(32)   # 256-bit
iv = get_random_bytes(16)        # 128-bit IV for CBC

# Read plaintext
with open(PLAINTEXT, "rb") as f:
    data = f.read()

# Compute original SHA-256 and save for later check
sha256_orig = hashlib.sha256(data).hexdigest()
with open("sha256_original.txt", "w") as f:
    f.write(sha256_orig + "\n")

# Encrypt using AES-CBC with PKCS7 padding
cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv=iv)
ciphertext = cipher_aes.encrypt(pad(data, AES.block_size))

# Save encrypted file: store IV||ciphertext
with open(OUT_ENC, "wb") as f:
    f.write(iv + ciphertext)

# Encrypt AES key with Bob's RSA public key
with open(PUBKEY, "rb") as f:
    pub = RSA.import_key(f.read())
rsa_cipher = PKCS1_OAEP.new(pub)
enc_aes_key = rsa_cipher.encrypt(aes_key)

with open(OUT_KEY_ENC, "wb") as f:
    f.write(enc_aes_key)

print("Encryption done.")
print("Outputs:", OUT_ENC, OUT_KEY_ENC, "sha256_original.txt")
