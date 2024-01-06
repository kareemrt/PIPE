# Name : Encrypt.py
# Auth : Kareem T (5/30/23)
# Desc : Encrypt module - Perform 3 layer encryption on an image and store necessary credentials in the DB
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
import rsa
import uuid
import secrets
import Security

def Generate_uuid(file): 
    '''Generates EFName (Encrypted File Name) for use as primary key in DB storage'''
    return str(uuid.uuid5(uuid.UUID(Security.UUID_Key()), str(file)))

def sha256_hash(key):
    '''HASH (SHA-256) user key (str) to retrieve symmetric AES encryption key (bytes)'''
    sha256_hasher = hashes.Hash(hashes.SHA256()) # Create a SHA-256 hash object
    sha256_hasher.update(key)    
    return sha256_hasher.finalize() 

def pad_image(img):
    '''Pad an image with extra bits to achieve necessary 256-bit size for AES encryption'''
    padder = padding.PKCS7(256).padder()                # Pad to 256 bits
    return padder.update(img) + padder.finalize()       # Return hashed string in bytes

def OUR_encrypt(img, hkey):
    '''Encrypt an image (bytes) by performing 2 XOR operations on it: 1st w/ the key's hash (bytes), 2nd w/ a random string'''
    if(type(img) != bytearray): img = bytearray(img)
    bob = "bob".encode()
    lkey = len(hkey)
    for i, val in enumerate(img): img[i] = val ^ hkey[i%lkey] ^ bob[i%3]
    return img

def AES_encrypt(hkey, image, iv):
    '''AES encrypt an image file (after our proprietary encryption has already been performed)'''
    encryptor = Cipher(algorithms.AES(hkey), modes.CBC(iv), backend=default_backend()).encryptor()  # Create an AES cipher object
    AES_encrypted = encryptor.update(image) + encryptor.finalize()                 # Encrypt the image data
    return AES_encrypted

def RSA_encrypt(key):
    '''RSA encrypt an AES key'''
    RSA_encrypted = rsa.encrypt(key,Security.RSA_Keys('public'))
    return RSA_encrypted

def encrypt(image, key, owner, permissions, name, iv=secrets.token_bytes(16)):
    '''USER function to encrypt an image and store it in the database, using the methods above'''
    # Key Encryption
    hashed_key = sha256_hash(key.encode())                     # Hash user key (SHA-256) (32 bytes)
    superkey = RSA_encrypt(hashed_key)                      # | LAYER 3 | RSA Encrypt: STORE RSA privately signed AES encryption key
    # Image Encryption
    usrenc = OUR_encrypt(image, hashed_key)                 # | LAYER 1 | Double XOR Encrypt: using inputted user key & its hash(user key)
    AESenc = AES_encrypt(hashed_key, pad_image(usrenc), iv) # | LAYER 2 | AES Encrypt: using the user_encrypted(img) and private_signed(key)
    # File-name Encryption
    EFName = Generate_uuid(AESenc)
    with open(f'usr/monkeys/{EFName}.Monkey', 'wb') as f: f.write(AESenc)
    # Storage
    Security.encrypt(EFName, superkey, sha256_hash(AESenc), owner, permissions, name, iv)
    return EFName 


