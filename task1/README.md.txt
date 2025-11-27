# Task 1 – Encrypted Messaging App (RSA + AES)

This task implements a hybrid encryption messaging prototype using RSA and AES.



### 1. User A generates RSA keys
- A 2048-bit RSA key pair is created.
- `public.pem` – shared with User B
- `private.pem` – kept secret by User A

### 2. User B encrypts the message
- Reads the plaintext from `message.txt`
- Generates a random AES-256 key
- Encrypts the message using AES (GCM mode)
- Encrypts the AES key using User A’s RSA public key
- Saves:
  - `encrypted_message.bin`
  - `aes_key_encrypted.bin`

### 3. User A decrypts the message
- Decrypts the AES key with his RSA private key
- Decrypts the message with the recovered AES key
- Stores output in `decrypted_message.txt`

## Files Generated Automatically
- `encrypted_message.bin`
- `aes_key_encrypted.bin`
- `decrypted_message.txt`
- `private.pem`
- `public.pem`

## Summary
This demonstrates hybrid encryption:
- RSA is used to securely exchange the AES key.
- AES is used for fast and secure bulk message encryption.
