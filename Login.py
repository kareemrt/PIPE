# Name : Login.py
# Auth : Kareem T (6/8/23)
# Desc : Login module - Communicate with Security module (& DB) to control access-control functionality
import Security
from cryptography.hazmat.primitives import hashes

def sha256_hash(key):
    '''HASH (SHA-256) user key (bytes) to retrieve symmetric encryption key (bytes)'''
    sha256_hasher = hashes.Hash(hashes.SHA256()) # Create a SHA-256 hash object
    sha256_hasher.update(key)    
    return sha256_hasher.finalize()              # Return hashed string in bytes

def login(user, password): 
    '''Login a user'''
    return Security.login(sha256_hash( user.encode() ), sha256_hash( password.encode() ))

def register(user, password): 
    '''Register a user if username untaken'''
    if(not Security.user_exists(sha256_hash( user.encode() ))):
        Security.register(sha256_hash( user.encode() ), sha256_hash( password.encode() ))
        return True
    return False

def check_perms_exist(users):
    '''Ensure all users are valid'''
    for user in users: 
        if not Security.user_exists(sha256_hash( user.encode() )): return False
    return True

def retrieve_cookies_key(): 
    '''Generate unique key for storing user cookies (prevents forgery attacks)'''
    return Security.Cookies_Key()