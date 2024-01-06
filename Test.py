
import unittest
import Encrypt
import Decrypt
import Security
import rsa
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend

def sha256_hash(key):
    '''HASH (SHA-256) user key (str) to retrieve symmetric AES encryption key (bytes)'''
    sha256_hasher = hashes.Hash(hashes.SHA256()) # Create a SHA-256 hash object
    sha256_hasher.update(key)    
    return sha256_hasher.finalize() 

class TestEncryption(unittest.TestCase):

    def test_our_enc(self):
        with open('src/test/img/myimage.png', 'rb') as file: img = bytearray(file.read())    # Read the image file
        key = 'mysecretkey123456'.encode()         # Sample user's input key on the website
        hkey = sha256_hash(key)
        bob = "bob".encode()
        lhkey, limg = len(hkey), len(img)  
        test_enc = bytearray(limg)        # get key lengths
        for i, val in enumerate(img): test_enc[i] = val ^ hkey[i%lhkey] ^ bob[i%3]
        self.assertEqual(test_enc, Encrypt.OUR_encrypt(img, hkey))

    def test_AES_enc(self):
        with open('src/test/img/myimage.png', 'rb') as file: img = bytearray(file.read())    # Read the image file
        key = 'mysecretkey123456'.encode()         # Sample user's input key on the website
        hkey = sha256_hash(key)
        iv = secrets.token_bytes(16)
        padder = padding.PKCS7(256).padder()                # Pad to 256 bits
        img = padder.update(img) + padder.finalize() 
        encryptor = Cipher(algorithms.AES(hkey), modes.CBC(iv), backend=default_backend()).encryptor()  # Create an AES cipher object
        test_enc = encryptor.update(img) + encryptor.finalize()                 # Encrypt the image data
        self.assertEqual(test_enc, Encrypt.AES_encrypt(hkey, img, iv))

    
class TestDecryption(unittest.TestCase):

    def test_our_enc(self):
        with open('src/test/img/myimage.png', 'rb') as file: img = bytearray(file.read())    # Read the image file
        key = 'mysecretkey123456'.encode()         # Sample user's input key on the website
        hkey = sha256_hash(key)
        enc = Encrypt.OUR_encrypt(img, hkey)
        bob = "bob".encode()
        lhkey, limg = len(hkey), len(img)  
        test_dec = bytearray(limg)        # get key lengths
        for i, val in enumerate(enc): test_dec[i] = val ^ hkey[i%lhkey] ^ bob[i%3]
        self.assertEqual(test_dec, Decrypt.OUR_decrypt(enc, hkey), img)

    def test_AES_dec(self):
        with open('src/test/img/myimage.png', 'rb') as file: img = bytearray(file.read())    # Read the image file
        key = 'mysecretkey123456'.encode()         # Sample user's input key on the website
        hkey = sha256_hash(key)
        iv = secrets.token_bytes(16)
        enc = Encrypt.AES_encrypt(hkey, Encrypt.pad_image(img), iv)                # Encrypt the image data
        decryptor = Cipher(algorithms.AES(hkey), modes.CBC(iv), backend=default_backend()).decryptor()    # Create an AES cipher object
        test_dec = decryptor.update(enc) + decryptor.finalize()                   # Decrypt image
        unpadder = padding.PKCS7(256).unpadder()                      # Create un-padder object
        test_dec = unpadder.update(test_dec) + unpadder.finalize()             # Unpad the 256-bit padding
        self.assertEqual(test_dec, Decrypt.unpad_image(Decrypt.AES_decrypt(hkey, enc, iv)), img) # test decryption == module decryption == img

    def test_RSA_dec(self):
        key = 'mysecretkey123456'.encode()         # Sample user's input key on the website
        hkey = sha256_hash(key)
        enc = rsa.encrypt(hkey, Security.RSA_Keys('public'))
        dec = rsa.decrypt(enc, Security.RSA_Keys('private'))
        self.assertEqual(dec, Decrypt.RSA_decrypt(Encrypt.RSA_encrypt(hkey)))

class TestLogin(unittest.TestCase):

# these test cases were incomplete

    def test_login(self):
        with open('src/test/img/myimage.png', 'rb') as file: img = bytearray(file.read())    # Read the image file
        key = 'mysecretkey123456'.encode()         # Sample user's input key on the website
        hkey = sha256_hash(key)
        bob = "bob".encode()
        lhkey, limg = len(hkey), len(img)  
        test_enc = bytearray(limg)        # get key lengths
        for i, val in enumerate(img): test_enc[i] = val ^ hkey[i%lhkey] ^ bob[i%3]
        self.assertEqual(test_enc, Encrypt.OUR_encrypt(img, hkey))

    def test_register(self):
        with open('src/test/img/myimage.png', 'rb') as file: img = bytearray(file.read())    # Read the image file
        key = 'mysecretkey123456'.encode()         # Sample user's input key on the website
        hkey = sha256_hash(key)
        iv = secrets.token_bytes(16)
        padder = padding.PKCS7(256).padder()                # Pad to 256 bits
        img = padder.update(img) + padder.finalize() 
        encryptor = Cipher(algorithms.AES(hkey), modes.CBC(iv), backend=default_backend()).encryptor()  # Create an AES cipher object
        test_enc = encryptor.update(img) + encryptor.finalize()                 # Encrypt the image data
        self.assertEqual(test_enc, Encrypt.AES_encrypt(hkey, img, iv))
if __name__ == '__main__':
    unittest.main()