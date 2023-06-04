# Name : Decrypt.py
# Auth : Kareem T (5/31/23)
# Desc : Perform 3 layer decryption on an encrypted image
from Encrypt import *
import Security

def RSA_decryption(ciphertext):
    RSA_decrypted = rsa.decrypt(ciphertext, RSA_keys()[1])
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
    if(type(img) != bytearray): img = bytearray(img)
    bob = "bob".encode()
    lkey, lbob = len(key), len(bob)
    for i, val in enumerate(img): img[i] = val ^ key[i%lkey] ^ bob[i%lbob]
    with open(f'myimage_USER_decrypted.png', 'wb') as f: f.write(img)       # Write the encrypted image data to a new file
    return img

def unpad_image(img): 
    unpadder = padding.PKCS7(256).unpadder()                      # Create un-padder object
    return unpadder.update(img) + unpadder.finalize()             # Unpad the 256-bit padding

def decrypt(EFName, key, user, fhash, EFile):
    # check privs
    valid = Security.decrypt(EFName, user, key, fhash)
    if valid: superkey, iv, oname = valid
    # sample decryption
    hashed_key = RSA_decryption(superkey)
    AESdec = AES_decryption(hashed_key, EFile, iv)
    unpadded = unpad_image(AESdec)
    decrypted = user_decryption(unpadded, hashed_key)
    return decrypted

# sample decrypt
#EFName, superkey, fhash, owner, perm, OName, iv = encrypt(get_image(), 'monkey', 'jon', 'ron', 'markimage')
#with open(f'{EFName}.Monkey', 'rb') as f: encf = f.read()
#d = decrypt(EFName, superkey, "ron", sha256_hash(encf), encf)
#with open('dec.png', 'wb') as f: f.write(bytearray(d))

# user test
#hkey = sha256_hash('monkey'.encode())
#img = get_image()
#uenc = OUR_encryption(img, 'monkey'.encode())
#tiv = secrets.token_bytes(16)
#pd = pad_image(uenc)
#aenc = AES_encryption(hkey, pd, tiv)
#denc = AES_decryption(hkey, aenc, tiv)
#un = unpad_image(denc)
#de = user_decryption(un, 'monkey'.encode())
#with open('test.png', 'wb') as f: f.write(de)