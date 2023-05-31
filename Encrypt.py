from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
import secrets

def sha256_hash(key):
    '''HASH (SHA-256) user key (str) to retrieve symmetric encryption key (bytes)'''
    sha256_hasher = hashes.Hash(hashes.SHA256()) # Create a SHA-256 hash object
    sha256_hasher.update(key.encode('utf-8'))    # Convert the string to bytes and update the hash object
    return sha256_hasher.finalize()              # Return hashed string in bytes

def retrieve_image(name = 'src/img/myimage.png'):
    '''RETRIEVE an Image file in (bytes), padded to 256 bits for AES-256 encryption'''
    with open(name, 'rb') as file: image_data = file.read()    # Read the image file
    padder = padding.PKCS7(256).padder()                       # Pad to 256 bits
    return padder.update(image_data) + padder.finalize()       # Return

def encrypt(key, image, iv):
    '''AES encrypt an image, then save it'''
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())        # Create an AES cipher object
    encryptor = cipher.encryptor()                                                        # Create an encryptor object
    encrypted_image_data = encryptor.update(image) + encryptor.finalize()                 # Encrypt the image data
    with open('myimage_encrypted.png', 'wb') as file: file.write(encrypted_image_data)    # Write the encrypted image data to a new file
    return encrypted_image_data

# user example
user_key = 'mysecretkey123456'          # Generate a random encryption key
encryption_key = sha256_hash(user_key)  # Hash it (SHA-256) (32 bytes)
iv = secrets.token_bytes(16)            # Generate a random initialization vector (IV) (16 bytes)
img = retrieve_image()                  # Retrieve padded image (32 bytes)

encrypted_img = encrypt(encryption_key, img, iv)        # Test encryption

def decrypt(key, image, iv):
    '''AES decrypt an image, then save it'''
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())    # Create an AES cipher object
    decryptor = cipher.decryptor()                                                    # Create a decryptor object
    decrypted_data = decryptor.update(image) + decryptor.finalize()                   # Decrypt image
    unpadder = padding.PKCS7(256).unpadder()                                          # Create un-padder object
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()             # Unpad the 256-bit padding
    with open('myimage_decrypted.png', 'wb') as file: file.write(unpadded_data)       # Write the encrypted image data to a new file

decrypt(encryption_key, encrypted_img, iv)        # Test decryption

