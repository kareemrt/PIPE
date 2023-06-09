# Name : Security.py
# Auth : Hannah S & Kareem T (6/5/23)
# Desc : Security module - Perform security checks for all other module functions
# - Security retrieves client hashes/keys/permissions, alongside server RSA keys, UUID-generation keys, and User-Cookie encryption keys
import sqlite3
import rsa
import os
DATABASE = 'src/Crypto.db'

def login(user, password):
    '''True/False Login a user'''
    db = sqlite3.connect(DATABASE)
    c = db.cursor()
    print(f'SECURITY: attempting to log in {user}')
    return c.execute('SELECT COUNT(*) FROM login WHERE user = ? AND pass = ?', (user, password)).fetchone()[0] != 0

def register(user, password):
    '''Register a user'''
    db = sqlite3.connect(DATABASE)
    c = db.cursor()  
    print(f'SECURITY: attempting to register {user}')  
    c.execute('INSERT INTO login (user, pass) VALUES (?, ?)', (user, password))
    db.commit(); db.close()

def user_exists(user):
    '''Check to see whether a user exists'''
    db = sqlite3.connect(DATABASE)
    c = db.cursor()  
    print(f'SECURITY: attempting to check whether {user} ecists')  
    return c.execute('SELECT COUNT(*) FROM login WHERE user = ?', (user,)).fetchone()[0] > 0

def encrypt(EName, Superkey, Hash, Owner, Permissions, OName, iv):
    '''Executes a DB insertion of encrypted information'''
    db = sqlite3.connect(DATABASE)
    c = db.cursor()
    print(f'SECURITY: Encrypting {OName} into {EName}...')
    c.execute('INSERT INTO perm (EFName, Superkey, IV, Hash, Owner, Perms, OName) VALUES (?, ?, ?, ?, ?, ?, ?)', (EName, Superkey, iv, Hash, Owner, Permissions, OName))
    db.commit(); db.close()
    return True

def decrypt(EName, user, fhash):
    '''Executes a DB read of encrypted information if the EFile is found and the keys, hash, and permissions match'''
    db = sqlite3.connect(DATABASE)
    c = db.cursor()
    if c.execute('SELECT COUNT(*) FROM perm WHERE EFName = ? AND Hash = ? AND Perms = ?', (EName, fhash, user)).fetchone()[0] > 0: 
        print(f'SECURITY: Performing decryption on {EName}...')
        c.execute('SELECT * FROM perm WHERE EFName = ?', (EName,))
        data = c.fetchall()[0]
        superkey, iv, oname = data[1], data[2], data[6]
        return (superkey, iv, oname)
    print(f'WARNING!: SECURITY - Decryption file not found!')
    db.close()
    return False 

def get_parameter(Efile, parameter):
    '''Retrieve a given paramter from the file encryption table'''
    db = sqlite3.connect(DATABASE)
    c = db.cursor()
    if parameter == 'hash': query = 'select hash'
    elif parameter == 'Superkey': query = 'select Superkey'
    elif parameter == 'Perms': query = 'select Perms'
    elif parameter == 'Owner': query = 'select Owner'
    query = query + " from perm where EFName = ?"
    pstr = c.execute(query, (Efile,)).fetchone()[0]
    print(f'SECURITY: Getting {parameter} from File {Efile}')
    db.close()
    return pstr

def update_permissions(Efile, permissions):
    '''Update an existings encrypted file's decrypt permissions'''
    db = sqlite3.connect(DATABASE)
    c = db.cursor()
    c.execute('UPDATE perm SET Perms = ? WHERE EFName = ?', (permissions, Efile))
    print(f'SECURITY: Updating {Efile} permissions to include {permissions}')
    db.commit(); db.close()

def Generate_RSA():
    '''Saves RSA private/public keys used to encrypt AES keys for DB storage'''
    publicKey, privateKey = rsa.newkeys(1024)       # Generate RSA public/private keys
    # Save the private key to a file
    pem = privateKey.save_pkcs1(format='PEM')
    with open("src/keys/private_key.pem", "wb") as f: f.write(pem)
    pem = publicKey.save_pkcs1(format='PEM')
    with open("src/keys/public_key.pem", "wb") as f: f.write(pem)
    print(f'SECURITY: Generating RSA (1024) keys....')

def RSA_Keys(key):
    '''Retrieves RSA private/public keys used to encrypt AES keys for DB storage'''
    print(f'SECURITY: Retrieving RSA {key} key...')    
    if key == 'public': 
        with open("src/keys/public_key.pem", "rb") as f: return rsa.key.PublicKey.load_pkcs1(f.read())
    if key == 'private': 
        with open('src/keys/private_key.pem', "rb") as f: return rsa.key.PrivateKey.load_pkcs1(f.read())

def UUID_Key(): 
    '''Retrieves the key for the Generate_uuid function, to prevent from known-PT attack'''
    print(f'SECURITY: Retrieving UUID keys...')    
    with(open('src/keys/uuid.key', 'rb')) as f: return f.read().decode('utf-8')

def Generate_cookies(): 
    '''Generate unique key for storing user cookies (prevents forgery attacks)'''
    random_bytes = os.urandom(32)    # Generate random bytes
    secret_key = ''.join('%02x' % byte for byte in random_bytes)    # Convert bytes to hexadecimal string
    print(f'SECURITY: Generating cookies\' keys...')    
    with(open('src/keys/cookies.key', 'wb')) as f: return f.write(secret_key.encode())

def Cookies_Key():
    '''Retrieves the key for cookie signatures, to prevent from signature-forgery attack'''
    with(open('src/keys/cookies.key', 'rb')) as f: return f.read().decode('utf-8')
