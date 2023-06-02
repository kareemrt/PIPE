# Name : Encrypt.py
# Auth : Kareem T (5/30/23)
# Desc : Perform 3 layer encryption on an image and store necessary credentials in the DB
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
import secrets
import rsa
import uuid
import Security
publicKey, privateKey = rsa.newkeys(1024)       # Generate RSA public/private keys
iv = secrets.token_bytes(16)                    # Generate a random AES initialization vector (IV) (16 bytes)

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

def user_encryption(img, key):
    '''Encrypt an image (bytes) by performing 2 XOR operations on it: 1st w/ the raw key (bytes), 2nd w/ the key's SHA-256 hash (bytes)'''
    bob = "bob".encode()
    hkey = sha256_hash(key)
    lkey, lhkey,lbob = len(key), len(hkey),len(bob)
    for i, val in enumerate(img): img[i] = ((val ^ key[i%lkey]) ^ hkey[i%lhkey]) ^ bob[i%lbob]
    with open('myimage_USER_encrypted.png', 'wb') as f: f.write(img)
    return img

def AES_encryption(hkey, image, iv):
    '''AES encrypt an image, then save it'''
    encryptor = Cipher(algorithms.AES(hkey), modes.CBC(iv), backend=default_backend()).encryptor()  # Create an AES cipher object
    AES_encrypted = encryptor.update(image) + encryptor.finalize()                 # Encrypt the image data
    with open('myimage_AES_encrypted.png', 'wb') as f: f.write(AES_encrypted)    # Write the encrypted image data to a new file
    return AES_encrypted

def RSA_encryption(text):
    '''RSA encrypt an image, then save it'''
    RSA_encrypted = rsa.encrypt(text,publicKey)
    with open('myimage_RSA_encrypted.png', 'wb') as f: f.write(RSA_encrypted)    # Write the encrypted image data to a new file
    return RSA_encrypted

def encrypt_image(key, image, name, owner, permissions):
# Sample example user
    user_key = key.encode()           # Sample user input encryption key
    encryption_key = sha256_hash(user_key)            # Hash user key (SHA-256) (32 bytes)
    usrenc = user_encryption(image, user_key)           # | LAYER 1 | Double XOR Encrypt: using inputted user key & its hash(user key)
    padded_img = pad_image(usrenc)                    # Pad the image to have necessary bits/length required for AES
    superkey = RSA_encryption(encryption_key)         # | LAYER 2 | RSA Encrypt: privately sign the hash(user key) to use for AES encryption
    AESenc = AES_encryption(encryption_key, padded_img, iv) # | LAYER 3 | AES Encrypt: using the user_encrypted(img) and private_signed(key)
    # generate unique file names
    namespace_uuid = uuid.UUID('12345678-9876-5432-1234-567898765432')  # RANDOM SEED for UUID GENERATION
    EFName = str(uuid.uuid5(namespace_uuid, str(usrenc))) # 
    print(EFName)
    Security.encrypt(EFName, name, superkey, owner, sha256_hash(AESenc), permissions) # TODO : GET key, file name, owner, perms, image from flask