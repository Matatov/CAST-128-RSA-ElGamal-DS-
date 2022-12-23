import sys
from hashlib import sha256
import blowfish
import elgamal
import rsa
from random import randint

""" 
    1. Generate a pair of ELGamal keys, public and private  V
    2. Generate a pair of RSA keys, public and private key  V
        2.1 Sign on RsSA keys 
    3. Promt user for message to be encrypted and signed    V
    4. Use RSA public key to encrypt the message using CAST 128 in CBC mode  
    5. Use the ElGamal private key to sign the encrypted message    V
    6. Send the encrypted message and signed message to recipient V
    7. Recipient uses the ElGamal public key to verify   V
    8. If not valid display Error message   V
    9. Otherwise Recipient uses their RSA private key to decrypt the message  
    10. DIspaly the decrypted message  V
"""
hash_function = sha256()
key_length = 128

# Generate a pair of ELGamal keys, public and private and ElGamal sytems
alice_elgsys = elgamal.generate_system(key_length, hash_function)
bob_elgsys = elgamal.generate_system(key_length, hash_function)

alice_sig_keys = elgamal.generate_keys(alice_elgsys)
bob_sig_keys = elgamal.generate_keys(bob_elgsys)

# 2. Generate a pair of RSA keys, public and private key
primeSize = 512
p = rsa.getRandomPrime(primeSize)  # getting random prime number
q = rsa.getRandomPrime(primeSize)

while p == q:
    q = rsa.getRandomPrime(primeSize)
n, e, d = rsa.getKeys(p, q)

# 3. Prompt user for message to be encrypted and signed
print("Alice writes the email...")
message = "Hello, Bob! Happy New Year! Learn Data Security and Cryptology!"
print('The message is - ' + message)

# encrypting
cipher_text = 'fajkhfhyewuefhs'
# signing on message
signatureOnCipher = elgamal.sign(alice_elgsys, cipher_text, alice_sig_keys[0])


print('Alice sends the encrypted email and the digital signature')
print('Bob receives the encrypted email and the digital signature')

# 7. Recipient uses the ElGamal public key to verify

isVerified = elgamal.verify(alice_elgsys, cipher_text, signatureOnCipher, alice_sig_keys[1])
if not isVerified:
    print("ERROR")
else:
    # decrypting
    decryptedMessage = ''
    print(decryptedMessage)

# Bob answers to Alice

message = input("Bob writes the email...")
print('The message is - ' + message)
# encrypting
cipher_text = 'f54548974w89e74r8w4e'
# signing on message
signatureOnCipher = elgamal.sign(bob_elgsys, cipher_text, bob_sig_keys[0])
print('Bob sends the encrypted email and the digital signature')
print('Alice receives the encrypted email and the digital signature')

isVerified = elgamal.verify(bob_elgsys, cipher_text, signatureOnCipher, bob_sig_keys[1])
if not isVerified:
    print("ERROR")
else:
    # decrypting
    decryptedMessage = ''
    print(decryptedMessage)
