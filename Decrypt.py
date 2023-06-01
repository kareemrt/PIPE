# Name : Decrypt.py
# Auth : Kareem T (5/31/23)
# Desc : Perform 3 layer decryption on an encrypted image
from Encrypt import *

def RSA_decryption(ciphertext):
    RSA_decrypted = rsa.decrypt(ciphertext, privateKey)
    with open(f'myimage_RSA_decrypted.png', 'wb') as f: f.write(RSA_decrypted)       # Write the encrypted image data to a new file
    return RSA_decrypted

def AES_decryption(hkey, img, iv):
    '''AES decrypt an image, then save it'''
    decryptor = Cipher(algorithms.AES(hkey), modes.CBC(iv), backend=default_backend()).decryptor()    # Create an AES cipher object
    AES_decrypted = decryptor.update(img) + decryptor.finalize()                   # Decrypt image
    with open(f'myimage_AES_decrypted.png', 'wb') as f: f.write(AES_decrypted)       # Write the encrypted image data to a new file
    return AES_decrypted

def user_decryption(img, key):
    '''Encrypt an image by performing 2 XOR operations, one with the key, one with the key's SHA-256 hash'''
    img = bytearray(img)
    bob = "bob".encode()
    hashkey = sha256_hash(key)
    lkey, lhkey, lbob = len(key), len(hashkey), len(bob)
    for i, val in enumerate(img): img[i] = ((val ^ key[i%lkey]) ^ hashkey[i%lhkey]) ^ bob[i%lbob]
    with open(f'myimage_USER_decrypted.png', 'wb') as f: f.write(img)       # Write the encrypted image data to a new file
    return img

def unpad_image(img): 
    unpadder = padding.PKCS7(256).unpadder()                      # Create un-padder object
    return unpadder.update(img) + unpadder.finalize()             # Unpad the 256-bit padding


# sample decryption
RSAdec = RSA_decryption(superkey)
AESdec = AES_decryption(RSAdec, AESenc, iv)
unpadded = unpad_image(AESdec)
USERenc = user_decryption(unpadded, user_key)
