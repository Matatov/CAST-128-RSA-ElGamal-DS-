import random
from hashlib import sha256
import idea_cbc
import elgamal

import rsa_encrypt

""" 
    1. Generate a pair of ELGamal keys, public and private  V
    2. Generate a pair of RSA keys, public and private key  V
        2.1 Sign on RsSA keys 
    3. Initialize the IDEA     
    4. Promt user for message to be encrypted and signed    V
    5. Use RSA public key to encrypt the message using IDEA in CBC mode  
    6. Use the ElGamal private key to sign the encrypted message    V
    7. Send the encrypted message and signed message to recipient V
    8. Recipient uses the ElGamal public key to verify   V
    9. If not valid display Error message   V
    10. Otherwise Recipient uses their RSA private key to decrypt the message  
    11. DIspaly the decrypted message  V
"""
hash_function = sha256()
key_length = 128

# 1. Generate a pair of ELGamal keys, public and private and ElGamal sytems
alice_elgsys = elgamal.generate_system(key_length, hash_function)
bob_elgsys = elgamal.generate_system(key_length, hash_function)
alice_sig_keys = elgamal.generate_keys(alice_elgsys)
bob_sig_keys = elgamal.generate_keys(bob_elgsys)


# 2. Generate a pair of RSA keys, public and private key
bit_length = 256
q = rsa_encrypt.getRandomPrime(bit_length)
p = rsa_encrypt.getRandomPrime(bit_length)
while p == q:
    q = rsa_encrypt.getRandomPrime(bit_length)
public, private = rsa_encrypt.getKeys(p, q)


key = random.getrandbits(128)
iv = random.getrandbits(64)

# Encrypt the key and iv
encrypted_key = rsa_encrypt.encrypt(str(key), public)
encrypted_iv = rsa_encrypt.encrypt(str(iv), public)


# 3. Initialize the IDEA
encryptor_alice = idea_cbc.IDEA(key=key)

# 4. Prompt user for message to be encrypted and signed
print("Alice writes the email...")
message = "Hello, Bob! Happy New Year! Learn Data Security and Cryptology!"
print('The message is - ' + message)


# 5. Use RSA public key to encrypt the message using IDEA in CBC mode
hex_blocks_after_split = encryptor_alice.split_plaintext_to_hex_blocks(plaintext=message)
cipher_text = encryptor_alice.encrypt(hex_blocks_after_split, iv, 0)

cipher_text_as_string = [str(block) for block in cipher_text]
# 6. Use the ElGamal private key to sign the encrypted message
signatureOnCipher = elgamal.sign(alice_elgsys, ''.join(cipher_text_as_string), alice_sig_keys[0])
print(''.join(cipher_text_as_string))

# 7. Send the encrypted message and signed message to recipient
print('Alice sends the encrypted email and the digital signature')
print('Bob receives the encrypted email and the digital signature')


# 8. Recipient uses the ElGamal public key to verify
isVerified = elgamal.verify(alice_elgsys, ''.join(cipher_text_as_string), signatureOnCipher, alice_sig_keys[1])
if not isVerified:
    print("ERROR")
else:
    # decrypting

    decrypted_key = int(rsa_encrypt.decrypt(encrypted_key, private))
    decrypted_iv = int(rsa_encrypt.decrypt(encrypted_iv, private))
    decryptor_bob = idea_cbc.IDEA(key=decrypted_key) # noqa

    decryptedMessage = decryptor_bob.encrypt(cipher_text, decrypted_iv, 1)
    decryptedMessage = decryptor_bob.from_hex_to_string(decryptedMessage)
    print(decryptedMessage)




# The same process but from Bob to Alice

key = random.getrandbits(128)
iv = random.getrandbits(64)

# Encrypt the key and iv
encrypted_key = rsa_encrypt.encrypt(str(key), public)
encrypted_iv = rsa_encrypt.encrypt(str(iv), public)


# 3. Initialize the IDEA
encryptor_bob = idea_cbc.IDEA(key=key)

# 4. Prompt user for message to be encrypted and signed
print("Alice writes the email...")
message = "Hello, Alice, I have got your message, Thank you"
print('The message is - ' + message)


# 5. Use RSA public key to encrypt the message using IDEA in CBC mode
hex_blocks_after_split = encryptor_bob.split_plaintext_to_hex_blocks(plaintext=message)
cipher_text = encryptor_bob.encrypt(hex_blocks_after_split, iv, 0)

cipher_text_as_string = [str(block) for block in cipher_text]
# 6. Use the ElGamal private key to sign the encrypted message
signatureOnCipher = elgamal.sign(bob_elgsys, ''.join(cipher_text_as_string), bob_sig_keys[0])
print(''.join(cipher_text_as_string))

# 7. Send the encrypted message and signed message to recipient
print('Alice sends the encrypted email and the digital signature')
print('Bob receives the encrypted email and the digital signature')


# 8. Recipient uses the ElGamal public key to verify
isVerified = elgamal.verify(bob_elgsys, ''.join(cipher_text_as_string), signatureOnCipher, bob_sig_keys[1])
if not isVerified:
    print("ERROR")
else:
    # decrypting

    decrypted_key = int(rsa_encrypt.decrypt(encrypted_key, private))
    decrypted_iv = int(rsa_encrypt.decrypt(encrypted_iv, private))
    decryptor_alice = idea_cbc.IDEA(key=decrypted_key) # noqa

    decryptedMessage = decryptor_alice.encrypt(cipher_text, decrypted_iv, 1)
    decryptedMessage = decryptor_alice.from_hex_to_string(decryptedMessage)
    print(decryptedMessage)


