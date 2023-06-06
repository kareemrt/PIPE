# Name : Encrypt.py
# Auth : Kareem T (5/30/23)
# Desc : Encrypt module - Perform 3 layer encryption on an image and store necessary credentials in the DB
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.backends import default_backend
import secrets
import rsa
import uuid
import Security
#iv = secrets.token_bytes(16)                    # Generate a random AES initialization vector (IV) (16 bytes)
def generate_uuid(file): return str(uuid.uuid5(uuid.UUID('12345678-9876-5432-1234-567898765432'), str(file)))

def RSA_keys(create = False):
    if create:
        publicKey, privateKey = rsa.newkeys(1024)       # Generate RSA public/private keys
        # Save the private key to a file
        pem = privateKey.save_pkcs1(format='PEM')
        with open("src/private_key.pem", "wb") as f: f.write(pem)
        pem = publicKey.save_pkcs1(format='PEM')
        with open("src/public_key.pem", "wb") as f: f.write(pem)
    else: 
        with open("src/public_key.pem", "rb") as f: publicKey = rsa.key.PublicKey.load_pkcs1(f.read())
        with open('src/private_key.pem', "rb") as f: privateKey = rsa.key.PrivateKey.load_pkcs1(f.read())
    return publicKey, privateKey

def get_image(dir = 'src/img/myimage.png'):
    '''RETRIEVE an Image file in (bytes)'''
    with open(dir, 'rb') as file: return bytearray(file.read())

def pad_image(img):
    '''Pad an image with extra bits to achieve necessary size for encryption'''
    padder = padding.PKCS7(256).padder()                # Pad to 256 bits
    return padder.update(img) + padder.finalize()       

def sha256_hash(key):
    '''HASH (SHA-256) user key (str) to retrieve symmetric encryption key (bytes)'''
    sha256_hasher = hashes.Hash(hashes.SHA256()) # Create a SHA-256 hash object
    sha256_hasher.update(key)    
    return sha256_hasher.finalize()              # Return hashed string in bytes

def OUR_encryption(img, hkey):
    '''Encrypt an image (bytes) by performing 2 XOR operations on it: 1st w/ the raw key (bytes), 2nd w/ the key's SHA-256 hash (bytes)'''
    if(type(img) != bytearray): img = bytearray(img)
    bob = "bob".encode()
    lkey, lbob = len(hkey), len(bob)
    for i, val in enumerate(img): img[i] = val ^ hkey[i%lkey] ^ bob[i%lbob]
    return img

def AES_encryption(hkey, image, iv):
    '''AES encrypt an image, then save it'''
    encryptor = Cipher(algorithms.AES(hkey), modes.CBC(iv), backend=default_backend()).encryptor()  # Create an AES cipher object
    AES_encrypted = encryptor.update(image) + encryptor.finalize()                 # Encrypt the image data
    return AES_encrypted

def RSA_encryption(text):
    '''RSA encrypt an image, then save it'''
    RSA_encrypted = rsa.encrypt(text,RSA_keys()[0])
    return RSA_encrypted

def encrypt(image, key, owner, permissions, name, iv=secrets.token_bytes(16)):
    # Key Encryption
    hashed_key = sha256_hash(key.encode())            # Hash user key (SHA-256) (32 bytes)
    superkey = RSA_encryption(hashed_key)             # | LAYER 3 | RSA Encrypt: STORE privately signed AES encryption key
    # Image Encryption
    usrenc = OUR_encryption(image, hashed_key)    # | LAYER 1 | Double XOR Encrypt: using inputted user key & its hash(user key)
    AESenc = AES_encryption(hashed_key, pad_image(usrenc), iv) # | LAYER 2 | AES Encrypt: using the user_encrypted(img) and private_signed(key)
    # File-name Encryption
    EFName = generate_uuid(AESenc)
    with open(f'usr/monkeys/{EFName}.Monkey', 'wb') as f: f.write(AESenc)
    # Storage
    Security.encrypt(EFName, superkey, sha256_hash(AESenc), owner, permissions, name, iv) # TODO : GET key, file name, owner, perms, image from flask
    return EFName 

def check_perms_exist(users):
    for user in users: 
        if not Security.login(user, cred_check=True): return False
    return True
