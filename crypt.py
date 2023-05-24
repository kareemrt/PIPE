from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Read the image file
with open('myimage.png', 'rb') as file:
    image_data = file.read()

# Generate a random encryption key
encryption_key = b'mysecretkey123456'

# Generate a random initialization vector (IV)
iv = b'myrandomiv7890123'

# Create an AES cipher object
cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())

# Create an encryptor object
encryptor = cipher.encryptor()

# Encrypt the image data
encrypted_image_data = encryptor.update(image_data) + encryptor.finalize()

# Write the encrypted image data to a new file
with open('myimage_encrypted.png', 'wb') as file:
    file.write(encrypted_image_data)