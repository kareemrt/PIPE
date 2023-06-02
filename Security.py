import sqlite3
from cryptography.hazmat.primitives import hashes
DATABASE = 'src/Crypto.db'

def sha256_hash(key):
    '''HASH (SHA-256) user key (str) to retrieve symmetric encryption key (bytes)'''
    sha256_hasher = hashes.Hash(hashes.SHA256()) # Create a SHA-256 hash object
    sha256_hasher.update(key)    
    return sha256_hasher.finalize()              # Return hashed string in bytes

def login(user, password):
    db = sqlite3.connect(DATABASE)
    c = db.cursor()
    hashuser, hashpass = sha256_hash(user.encode()), sha256_hash(password.encode())
    if c.execute('SELECT COUNT(*) FROM login WHERE user = ? AND pass = ?', (hashuser, hashpass)).fetchone()[0] == 0: return False
    return True

def register(user, password):
    db = sqlite3.connect(DATABASE)
    c = db.cursor()    
    hashuser, hashpass = sha256_hash(user.encode()), sha256_hash(password.encode())
    if c.execute('SELECT COUNT(*) FROM login WHERE user = ?', (hashuser,)).fetchone()[0] > 0: return False # Fail
    c.execute('INSERT INTO login (user, pass) VALUES (?, ?)', (hashuser, hashpass))
    db.commit()
    db.close()
    return True

def encrypt(EName, OName, Superkey, Owner, Hash, Permissions):
    db = sqlite3.connect(DATABASE)
    c = db.cursor()
    c.execute('INSERT INTO perm (EFName, Superkey, Hash, Owner, Perms, OName) VALUES (?, ?, ?, ?, ?, ?)', (EName, Superkey, Hash, Owner, Permissions, OName))
    db.commit()
    db.close()
    return True