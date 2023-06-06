# Name : Security.py
# Auth : Hannah S & Kareem T (6/5/23)
# Desc : Security module - Perform DB operations
import sqlite3
from cryptography.hazmat.primitives import hashes
DATABASE = 'src/Crypto.db'

def sha256_hash(key):
    '''HASH (SHA-256) user key (bytes) to retrieve symmetric encryption key (bytes)'''
    sha256_hasher = hashes.Hash(hashes.SHA256()) # Create a SHA-256 hash object
    sha256_hasher.update(key)    
    return sha256_hasher.finalize()              # Return hashed string in bytes

def login(user, password = None, cred_check = False):
    '''True/False whether login credentials exist'''
    db = sqlite3.connect(DATABASE)
    c = db.cursor()
    print(f'logging in {user}')
    hashuser = sha256_hash(user.encode())
    if cred_check: return c.execute('SELECT COUNT(*) FROM login WHERE user = ?', (hashuser,)).fetchone()[0] != 0
    hashpass = sha256_hash(password.encode())
    return c.execute('SELECT COUNT(*) FROM login WHERE user = ? AND pass = ?', (hashuser, hashpass)).fetchone()[0] != 0

def register(user, password):
    '''Executes a DB insertion if the username is not taken, returns True/False depending on status'''
    db = sqlite3.connect(DATABASE)
    c = db.cursor()    
    hashuser, hashpass = sha256_hash(user.encode()), sha256_hash(password.encode())
    if c.execute('SELECT COUNT(*) FROM login WHERE user = ?', (hashuser,)).fetchone()[0] > 0: return False # Fail
    c.execute('INSERT INTO login (user, pass) VALUES (?, ?)', (hashuser, hashpass))
    db.commit()
    db.close()
    return True

def encrypt(EName, Superkey, Hash, Owner, Permissions, OName, iv):
    '''Executes a DB insertion of encrypted information'''
    db = sqlite3.connect(DATABASE)
    c = db.cursor()
    c.execute('INSERT INTO perm (EFName, Superkey, IV, Hash, Owner, Perms, OName) VALUES (?, ?, ?, ?, ?, ?, ?)', (EName, Superkey, iv, Hash, Owner, Permissions, OName))
    db.commit()
    db.close()
    return True

def decrypt(EName, user, fhash):
    '''Executes a DB read of encrypted information if the EFile is found and the keys, hash, and permissions match'''
    db = sqlite3.connect(DATABASE)
    c = db.cursor()
    print(fhash)
    if c.execute('SELECT COUNT(*) FROM perm WHERE EFName = ? AND Hash = ? AND Perms = ?', (EName, fhash, user)).fetchone()[0] > 0: 
        print('found')
        c.execute('SELECT * FROM perm WHERE EFName = ?', (EName,))
        data = c.fetchall()[0]
        superkey, iv, oname = data[1], data[2], data[6]
        return (superkey, iv, oname)
    print('not found')
    db.close()
    return False 

#hannah:function to check if inputted users for 'decryption permission' exist during encrypt metadata
#check if current user has decryption permission for uploaded monkey file
def get_parameter(Efile, parameter):
    db = sqlite3.connect(DATABASE)
    c = db.cursor()
    match parameter:
        case 'hash': query = 'select hash'
        case 'Superkey': query = 'select Superkey'
        case 'Perms': query = 'select Perms'
    query = query + " from perm where EFName = ?"
    pstr = c.execute(query, (Efile,)).fetchone()[0]
    print(f'Getting {parameter} from File {Efile}, value = {pstr}')
    db.close()
    return pstr


#print(check_passkey('Tree', '6e22ab16-1607-509e-a4ae-69e8b28f883e'))
    
