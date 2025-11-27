from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

# -------------------------------
# User A generates RSA keys
# -------------------------------
print("[+] Generating RSA keys for User A...")
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

open("private.pem", "wb").write(private_key)
open("public.pem", "wb").write(public_key)

print("[+] Keys created: private.pem, public.pem")


# -------------------------------
# User B reads the public key
# -------------------------------
print("[+] Loading public key...")
recipient_key = RSA.import_key(open("public.pem").read())
cipher_rsa = PKCS1_OAEP.new(recipient_key)

# Load message
message = open("message.txt", "rb").read()


# -------------------------------
# AES Encryption (User B)
# -------------------------------
print("[+] Encrypting message using AES-256...")
aes_key = get_random_bytes(32)  # AES-256 key
cipher_aes = AES.new(aes_key, AES.MODE_GCM)
ciphertext, tag = cipher_aes.encrypt_and_digest(message)

open("encrypted_message.bin", "wb").write(ciphertext)
print("[+] Encrypted message saved as encrypted_message.bin")

# Encrypt AES key using RSA
enc_aes_key = cipher_rsa.encrypt(aes_key)
open("aes_key_encrypted.bin", "wb").write(enc_aes_key)
print("[+] AES key encrypted using RSA and saved as aes_key_encrypted.bin")


# -------------------------------
# User A decrypts AES key (RSA)
# -------------------------------
print("[+] Decrypting AES key using private RSA key...")
priv_key = RSA.import_key(open("private.pem").read())
cipher_rsa_dec = PKCS1_OAEP.new(priv_key)
dec_aes_key = cipher_rsa_dec.decrypt(enc_aes_key)


# -------------------------------
# AES decrypt message
# -------------------------------
print("[+] Decrypting message with recovered AES key...")
cipher_aes_dec = AES.new(dec_aes_key, AES.MODE_GCM, nonce=cipher_aes.nonce)
decrypted_message = cipher_aes_dec.decrypt(ciphertext)

open("decrypted_message.txt", "wb").write(decrypted_message)
print("[+] Decrypted message saved as decrypted_message.txt")

print("[✔] Task 1 Completed Successfully!")
