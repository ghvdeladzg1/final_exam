Task 2 — Hybrid RSA+AES

Flow:
1. Bob generates RSA key pair (private.pem, public.pem)
2. Alice writes alice_message.txt
3. Alice runs task2_encrypt.py:
   - generates AES-256 key and IV
   - encrypts alice_message.txt with AES-CBC (IV||ciphertext saved to encrypted_file.bin)
   - encrypts AES key with RSA public.pem (saved to aes_key_encrypted.bin)
4. Bob runs task2_decrypt.py:
   - uses private.pem to decrypt AES key
   - uses AES key + IV to decrypt encrypted_file.bin -> decrypted_message.txt
   - computes SHA-256 and compares to original (sha256_original.txt) for integrity

AES vs RSA:
- AES (symmetric): very fast, suited for encrypting large files/stream data. Key sizes: 128/192/256 bits.
- RSA (asymmetric): much slower; used to securely transport small pieces of data (like AES keys) and for digital signatures. Typical RSA sizes: 2048/3072 bits.
- Security: AES-256 is considered secure for symmetric encryption; RSA-2048 is commonly used but for very long term security RSA-3072+ recommended.
