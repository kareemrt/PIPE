from Encrypt import sha256_hash
with open('src/img/myimage.png', 'rb') as file: img = bytearray(file.read())    # Read the image file
key = 'mysecretkey123456'.encode()         # Sample user's input key on the website
hkey = sha256_hash(key.encode())
bob = "bob".encode()
lhkey, lbob = len(hkey), len(bob)          # get key lengths
for i, val in enumerate(img): img[i] = (val ^ hkey[i%lhkey]) ^ bob[i%lbob]
with open(f'myimage_enc_test.png','wb') as f: f.write(img)               # Write the encrypted image data to a new file
for i, val in enumerate(img): img[i] = val ^ key[i%lhkey] ^ bob[i%lbob]
with open(f'myimage_dec_test.png', 'wb') as file: file.write(img)       # Write the decrypted image data to a new file

import unittest
