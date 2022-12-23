# -*- coding: utf-8 -*-
"""
Created on Tue Jun  1 18:20:09 2021

@author: Netanel
"""
import sys
from hashlib import sha256
import blowfish
import elgamal
import rsa
from random import randint

hfun = sha256()
N = 64

# Creating digital signature
alice_elgsys = elgamal.generate_system(N, hfun)
bob_elgsys = elgamal.generate_system(N, hfun)

alice_sig_keys = elgamal.generate_keys(alice_elgsys)
bob_sig_keys = elgamal.generate_keys(bob_elgsys)

print("Alice and Bob delivered both their ElGamal signature systems securely and can validate messages using the signatures....\n")

# ALICE-RSA
primeSize = 512
p = rsa.getRandomPrime(primeSize)  # getting random prime number
q = rsa.getRandomPrime(primeSize)
while p == q:
    q = rsa.getRandomPrime(primeSize)
n, e, d = rsa.getKeys(p, q)

print("Sending Bob RSA public keys \n n = ", n, "    \ne = ", e, " ")
print("\nSigning on hash(n+e) and sending signature to Bob\n")
signatureOnRSAPublicKeys = elgamal.sign(alice_elgsys, str(hash(str(n + e))), alice_sig_keys[0])
print("Sent signature = ", signatureOnRSAPublicKeys, "\n")

print("Bob recieved message and signature,validating signature:\n")
if elgamal.verify(alice_elgsys, str(hash(str(n + e))), signatureOnRSAPublicKeys, alice_sig_keys[1]):
    print("Signature is OK, Alice sent the message")
else:
    print("Error! it was not Alice --ABORTING--")
    sys.exit(0)

print("Bob generating random key of max 448 bits...\n")
k = randint(pow(2, 32), pow(2, 448) - 1)
while k % 2 == 0:
    k = randint(pow(2, 32), pow(2, 448) - 1)
print("Key is ", k)
print("Bob encrypts the key..\n")
encryptedK = pow(k, e, n)
print("Encrypted Key is ", encryptedK, "\n")
signatureOnKey = elgamal.sign(bob_elgsys, str(hash(str(k))), bob_sig_keys[0])
print("Bob signed on the hash of the original key-signature is: ", signatureOnKey,
      "\nBob sends the encrypted key and the signature to Alice..\n")

print("Alice decrypts the key validates that Bob sent the message..\n")
decryptedK = pow(encryptedK, d, n)
if elgamal.verify(bob_elgsys, str(hash(str(decryptedK))), signatureOnKey, bob_sig_keys[1]) and decryptedK == k:
    print("Message verified and now Alice and Bob share the same symmetric key..\n")
else:
    print("Error! it was not Alice --ABORTING--")
    sys.exit(0)

iv = randint(2, pow(2, 64) - 1)
bytes_iv = iv.to_bytes(8, byteorder='big')
signatureOnIV = elgamal.sign(bob_elgsys, str(hash(str(iv))), bob_sig_keys[0])
encryptedIV = pow(iv, e, n)

print(
    "Bob generates an IV for the blowfish algorithm, encrypts it with RSA and signs on the hash of the original IV and sends to Alice...\n")
print("Alice now recieved the encrypted IV.... trying to decrypt it, then validate the signature...\n")
decryptedIV = pow(encryptedIV, d, n)
if (elgamal.verify(bob_elgsys, str(hash(str(decryptedIV))), signatureOnIV, bob_sig_keys[1])):
    print("IV verified,continuing to decrypt email")
else:
    print("Error! it was not Bob --ABORTING--")
    sys.exit(0)

blowfishKey = k.to_bytes(56, byteorder='big')

# email=input("Please enter your mail text:\n")d
email = "The fact of the matter is that although you may have numerous valid facts or descriptions related to your paragraph's core idea, you may lose a reader's attention if your paragraphs are too long. What's more, if all of your paragraphs are long, you may lose opportunities to draw your reader in. Journalists, for example, know that their readers respond better to short paragraphs. News readers generally lose interest with long descriptions and even one-sentence paragraphs are considered both acceptable and impactful.When it comes to maintaining a reader's attention, a good rule of thumb might be to avoid writing more than five or six sentences in a paragraph before finding a logical place to break. That said, remember that the idea behind a paragraph might be short and sweet, or it might merit deeper explanation. There are no strict rules about how many words or lines your paragraphs should be, and there's no need to lock your doors if you occasionally write long or short ones. The grammar police aren't coming for you."
length = len(email) % 8
if (length != 0):
    email1 = email + " " * (8 - length)
else:
    email1 = email

blowfishSys = blowfish.Cipher(blowfishKey)

# Bob writes an email,encrypts and signs it then sends to Alice
encryptedEmail = blowfishSys.encrypt_cbc(str.encode(email1), bytes_iv)
signatureOnEmail = elgamal.sign(bob_elgsys, str(hash(email1)), bob_sig_keys[0])
encryptedEmail = b"".join(encryptedEmail)

print("Bob wrote an email to Alice, and signed on the hash of the email\nEncrypted mail: ", encryptedEmail,
      "\nSignature: ", signatureOnEmail, "\n")
print("Alice recieved the email, decrypts it and then validates if Bob really sent it... \n")
bytes_decryptedIV = decryptedIV.to_bytes(8, byteorder='big')
decryptedEmail = blowfishSys.decrypt_cbc(encryptedEmail, bytes_decryptedIV)
decryptedEmail = b"".join(decryptedEmail).decode()
if (elgamal.verify(bob_elgsys, str(hash(decryptedEmail)), signatureOnEmail, bob_sig_keys[1])):
    print("Email verified\n")
else:
    print("Error! it was not Alice --ABORTING--")
    sys.exit(0)

print("Decrypted email is:\n", decryptedEmail)

# print(b"".join(blowfishSys.decrypt_cbc(b"".join(encryptedEmail),bytes_decryptedIV)).decode())
