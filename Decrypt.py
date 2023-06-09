# Name : Decrypt.py
# Auth : Kareem T (5/31/23)
# Desc : Decrypt module - Perform 3 layer decryption on an encrypted image, alongside communicate with security module to ensure valid constraints
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import Security
import re
import rsa

def RSA_decrypt(ciphertext): # RSA
    '''System function: RSA Decrypt superkey -> Hash key (AES)'''
    RSA_decrypted = rsa.decrypt(ciphertext, Security.RSA_Keys('private')) # Decrypt using RSA private key
    return RSA_decrypted

def AES_decrypt(hkey, img, iv): # AES
    '''System function: AES decrypt an image (using hkey, iv), return bytes'''
    decryptor = Cipher(algorithms.AES(hkey), modes.CBC(iv), backend=default_backend()).decryptor()    # Create an AES cipher object
    AES_decrypted = decryptor.update(img) + decryptor.finalize()                   # Decrypt image
    return AES_decrypted

def unpad_image(img):  # AES
    '''System function: PAD image to appropriate size for AES encryption'''
    unpadder = padding.PKCS7(256).unpadder()                      # Create un-padder object
    return unpadder.update(img) + unpadder.finalize()             # Unpad the 256-bit padding

def OUR_decrypt(img, key): # Proprietary
    '''System function: Proprietary encrypt an image by performing 2 XOR operations with the key's SHA-256 hash and bob'''
    if(type(img) != bytearray): img = bytearray(img)
    bob = "bob".encode()
    lkey = len(key)
    for i, val in enumerate(img): img[i] = val ^ key[i%lkey] ^ bob[i%3]
    return img
# database functions
def check_conditions(EFile, EFName, User, key = None, check_owner = False): # pre-decryption
    '''System function: Check user inputs for appropriate decryption conditions'''
    # Check file format, then DB existence
    end_monkey = re.search(".Monkey$", EFName)
    if end_monkey == False: return 'Sorry, This file is not in the appropriate format (.MONKEY)'
    EFName = (re.sub('\.Monkey$', '', EFName))
    if Security.get_parameter(EFName, 'hash') != EFile: return 'Sorry, This file has either been modified or does not exist'
    # Check owner permissions (if intention is permissions modify)
    if check_owner: return User in Security.get_parameter(EFName, 'Owner')
    # Check user decryptor permissions (if intention is to decrypt)
    perm_str = Security.get_parameter(EFName, 'Perms')
    users_withperm_list = re.findall(r'\b\S+\b', perm_str)
    if User not in users_withperm_list: return 'Sorry, you do not have permission to decrypt this file'
    # Check decryption key (if intention is to decrypt)
    if key:
        skey = Security.get_parameter(EFName, 'Superkey')
        hashkey = RSA_decrypt(skey)
        if key != hashkey: return 'Sorry, this passkey is incorrect'
        return True
    return False

def update_permissions(usrFILE, EFName, user, permissions): 
    '''Update an existings encrypted file's decrypt permissions'''
    valid = check_conditions(usrFILE, EFName, user, check_owner = True)
    if valid: Security.update_permissions(EFName, permissions)
    return valid

def decrypt(EFName, user, fhash, EFile): # decryption
    '''User function: Decrypt a .MONKEY file'''
    # check privs
    EFName = (re.sub('\.Monkey$', '', EFName))
    print(f'DECRYPTION: Decrypting encrypted file {EFName}')
    valid = Security.decrypt(EFName, user, fhash)
    if valid: 
        superkey, iv, oname = valid
        # sample decryption
        hashed_key = RSA_decrypt(superkey)
        AESdec = AES_decrypt(hashed_key, EFile, iv)
        unpadded = unpad_image(AESdec)
        decrypted = OUR_decrypt(unpadded, hashed_key)
        with open(f'usr/plain/{oname}', 'wb') as f: f.write(decrypted); f.close()
        return oname
    print(f'ERROR: Decryption - COULD NOT DECRYPT FILE ( NO FILE FOUND )')
    return False