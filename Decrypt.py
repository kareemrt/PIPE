# Name : Decrypt.py
# Auth : Kareem T (5/31/23)
# Desc : Decrypt module - Perform 3 layer decryption on an encrypted image, alongside communicate with security module to ensure valid constraints
import Security
import re
from Encrypt import *
# encryption functions
def RSA_decrypt(ciphertext): # RSA
    '''System function: RSA Decrypt superkey -> Hash key (AES)'''
    RSA_decrypted = rsa.decrypt(ciphertext, RSA_keys()[1]) # Decrypt using RSA private key
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
def check_conditions(EFile, EFName, User, key): # pre-decryption
    '''System function: Check user inputs for appropriate decryption conditions'''
    # Check file existence
    end_monkey = re.search(".Monkey$", EFName)
    if end_monkey == False: return 'Sorry, This file is not in the appropriate format (.MONKEY)'
    EFName = (re.sub('\.Monkey$', '', EFName))
    if Security.get_parameter(EFName, 'hash') != sha256_hash(EFile): 
        return 'Sorry, This file has either been modified or does not exist'
    
    print()
    print('db key', Security.get_parameter(EFName, 'hash'))
    print('upload key', sha256_hash(EFile))
    # Check user permissions
    perm_str = Security.get_parameter(EFName, 'Perms')
    users_withperm_list = re.findall(r'\b\S+\b', perm_str)
    if User not in users_withperm_list: return 'Sorry, you do not have permission to decrypt this file'
    # Check key
    skey = Security.get_parameter(EFName, 'Superkey')
    hashkey = RSA_decrypt(skey)
    if key != hashkey: return 'Sorry, this passkey is incorrect'
    return True

def decrypt(EFName, user, fhash, EFile): # decryption
    '''User function: Decrypt a .MONKEY file'''
    # check privs
    EFName = (re.sub('\.Monkey$', '', EFName))
    print('our key', fhash)
    valid = Security.decrypt(EFName, user, fhash)
    if valid: superkey, iv, oname = valid
    # sample decryption
    hashed_key = RSA_decrypt(superkey)
    AESdec = AES_decrypt(hashed_key, EFile, iv)
    unpadded = unpad_image(AESdec)
    decrypted = OUR_decrypt(unpadded, hashed_key)
    with open(f'usr/plain/{oname}', 'wb') as f: f.write(decrypted)
    return oname

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