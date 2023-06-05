import sqlite3
from cryptography.hazmat.primitives import hashes
DATABASE = 'src/Crypto.db'
import re

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

def encrypt(EName, Superkey, Hash, Owner, Permissions, OName, iv):
    db = sqlite3.connect(DATABASE)
    c = db.cursor()
    c.execute('INSERT INTO perm (EFName, Superkey, IV, Hash, Owner, Perms, OName) VALUES (?, ?, ?, ?, ?, ?, ?)', (EName, Superkey, iv, Hash, Owner, Permissions, OName))
    db.commit()
    db.close()
    return True

def decrypt(EName, user, key, fhash):
    db = sqlite3.connect(DATABASE)
    c = db.cursor()
    if c.execute('SELECT COUNT(*) FROM perm WHERE EFName = ? AND Superkey = ? AND Hash = ? AND Perms = ?', (EName, key, fhash, user)).fetchone()[0] > 0: 
        print('found')
        c.execute('SELECT * FROM perm WHERE EFName = ? AND Superkey = ?', (EName, key))
        data = c.fetchall()[0]
        print(len(data), data)
        superkey, iv, oname = data[1], data[2], data[6]
        return (superkey, iv, oname)
    print('not found')
    db.close()
    return False 


#hannah:function to check if inputted users for 'decryption permission' exist during encrypt metadata
def check_perms_exist(perms):

    db = sqlite3.connect(DATABASE)
    c = db.cursor() 

    list_of_users = re.findall(r'\b\S+\b', perms)

    for user in list_of_users:

        hashed_decrypt_users = sha256_hash(user.encode())
        if c.execute('SELECT COUNT(*) FROM login WHERE user = ?', (hashed_decrypt_users,)).fetchone()[0] == 0:
            return  False

    return True

def retrieve_last_Efile():
    #returns most recently added encrypted file_name string from perm database database

    #fetches last entry in EFName from DB
    db = sqlite3.connect(DATABASE)
    c = db.cursor()
    c.execute(f"SELECT EFName FROM perm")
    Efile_col = c.fetchall()
    db.close()
    Efile_name = Efile_col[-1]
    #converts to string for file reading
    Efile_str = Efile_name[0]
    return Efile_str

#check if current user has decryption permission for uploaded monkey file
def user_has_perm(current_user, Efile):
    print(current_user)
    print(Efile)

    db = sqlite3.connect(DATABASE)
    c = db.cursor()
    c.execute("SELECT Perms FROM perm WHERE EFName = ?", (Efile,))
    perm_str = c.fetchone()[0]
    users_withperm_list = re.findall(r'\b\S+\b', perm_str)
    db.close()

    for valid_user in users_withperm_list:
        if current_user == valid_user:
            return True
        
    return False

def check_file_exists(file_str):
    end_monkey = re.search(".Monkey$", file_str)

    if end_monkey == False:
        return False
    Efile= (re.sub('\.Monkey$', '', file_str))
    db = sqlite3.connect(DATABASE)
    c = db.cursor()
    if c.execute('SELECT COUNT(*) FROM perm WHERE EFName = ?', (Efile,)).fetchone()[0] == 0:
            return  False

    return True



#check if passkey is correct
def check_passkey(temp_super_key, Efile):
    print(Efile)

    db = sqlite3.connect(DATABASE)
    c = db.cursor()
    c.execute("SELECT Superkey FROM perm WHERE EFName = ?", (Efile,))
    superkey_str= c.fetchone()[0]
    db.close()
    print(superkey_str, '\n')
    print(temp_super_key)

    if superkey_str == temp_super_key:
        return True
    
    return False

#print(check_passkey('Tree', '6e22ab16-1607-509e-a4ae-69e8b28f883e'))
    
