with open('src/img/myimage.png', 'rb') as file: img = bytearray(file.read())    # Read the image file
key = 'mysecretkey123456'.encode()         # Sample user's input key on the website
hkey = bytes(bin(hash(key)), 'utf-8')      # hash the key
lkey, lhkey = len(key), len(hkey)          # get key lengths
for i, val in enumerate(img):              # encryption: perform double XOR using key, hash(key)
    img[i] = val ^ key[i%lkey]
    img[i] = img[i] ^ hkey[i%lhkey]
with open(f'myimage_enc_test.png','wb') as f: f.write(img)               # Write the encrypted image data to a new file
for i, val in enumerate(img):              # decryption: perform double XOR using key, hash(key)
    img[i] = val ^ key[i%lkey]
    img[i] = img[i] ^ hkey[i%lhkey]
with open(f'myimage_dec_test.png', 'wb') as file: file.write(img)       # Write the decrypted image data to a new file
