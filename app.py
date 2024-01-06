# Name : app.py
# Auth : Hannah S & Kareem T (6/5/23)
# Desc : Web app frameworks
from flask import Flask, render_template, request, redirect, url_for, session, send_file
from waitress import serve
import Encrypt
import Decrypt
import Login
import logging
import re
import os
import io

app = Flask(__name__, static_folder = 'src/static', template_folder = 'src/templates')
app.secret_key = Login.retrieve_cookies_key()
logging.basicConfig(filename='src/logs/app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
hash = Encrypt.sha256_hash

# HOME
@app.route('/')
def home(): 
    msg = 'Login Below!' if session.get('msg') == None else session.get('msg')
    session.pop('msg', None)
    return render_template('home.html', message = msg)
#
# LOGIN MODULE
@app.route('/login', methods=['POST'])
def authenicate():
    '''User is attempting to login/register'''
    user, passw, action = request.form['user'], request.form['passw'], request.form['button'] # Retrieve user credentials / action
    if action == 'Login':
        if Login.login(user, passw): # Success
            logging.info(f'LOGIN: User LOGGED IN as {user}')
            session['user'], session['logged_in'] = user, "True"
            return render_template('ev.html', message = 'Logged in!')
        logging.warning(f'ERROR: Login - User failed to log in as: {user}')
        session['msg'] = 'False credentials' # Failure
        return redirect(url_for('home')) 
    if action == 'Sign-Up':       # User pressed register
        if Login.register(user, passw): # Success
            logging.info(f'LOGIN: User REGISTERED as {user}')
            session['msg'], session['logged_in'] = 'Registered successfully!', "True"
            return render_template('ev.html', message = 'Registered!')
        logging.warning(f'ERROR: Login - User failed to register as: {user}')
        session['msg'] = 'Username taken!' # Failure
        return redirect(url_for('home'))

@app.route('/logout', methods=["GET","POST"]) 
def logout():
    '''Log a user out via cookie removal'''
    session.pop('logged_in', None)
    return redirect(url_for('home'))

@app.route('/ev', methods=['POST', 'GET'])
def choose() -> render_template:
    '''Logged in user choice (Encrypt/Decrypt)'''
    if session.get('logged_in') != "True": # Ensure they logged in
        logging.warning(f'ERROR: User attempted encryption/decryption without logging in')
        session['msg'] = 'You must be logged in to encrypt/decrypt!'
        return redirect(url_for('home'))
    if request.method == 'POST':
        action = request.form['button']
        if action == 'Encrypt': return render_template('encrypt_metadata.html')#user chooses encrypt
        if action == 'Decrypt': return render_template('decrypt_metadata.html') #user chooses decrypt
    return render_template('ev.html')

#ENCRYPT MODULE
@app.route('/encrypt_metadata', methods=['POST', 'GET'])
def accept_metadata() -> render_template:
    '''User is attempting to encrypt a file'''
    if request.method == 'POST':
        current_user = session.get('user') # web-page parameters and user
        pass_key = request.form['passkey']
        decrypt_users = request.form['decrypt_users']
        image_upload = request.files['image_upload']
        file_name = request.form['file_name']

        list_of_users = re.findall(r'\b\S+\b', decrypt_users) # string parsing from web input
        logging.debug(f'ENCRYPTION: {current_user}')

        if image_upload: logging.info(f"ENCRYPTION: Image Upload - We got something from {current_user}") # check image uploaded
        if Login.check_perms_exist(list_of_users) == False: # check share users exist
            logging.warning(f'ERROR: Encryption - {current_user} tried to give permissions to 1+ non-existing users!')
            return render_template("encrypt_metadata.html", msg = "One or more of these users do not exist! please try again") #Tried to give decrypt permission to users that do not exist
        EFName = Encrypt.encrypt(image_upload.read(), pass_key, current_user, decrypt_users, file_name) # encrypt

        return render_template('download_encrypted.html', msg = "File Successfully secured!", EFName = EFName)
    return render_template('encrypt_metadata.html')

@app.route('/download_encrypted/<EFname>', methods=["GET","POST"])
def download_file(EFname):
    '''User is downloading encrypted file'''
    path = f'usr/monkeys/{EFname}.Monkey'
    logging.info(f'ENCRYPTION: user downloaded {path}')
    ret_file = io.BytesIO()
    # Perform the file deletion after sending it
    with(open(path, 'rb')) as f: ret_file.write(f.read())
    ret_file.seek(0)
    os.remove(path) # If you seek to store the encrypted files, comment this line out
    return send_file(ret_file, as_attachment=True, download_name=f'{EFname}.Monkey')

#DECRYPT MODULE
@app.route('/decrypt_metadata', methods=['POST', 'GET'])
def authorize_decryption() -> render_template:
    '''User is attempting to decrypt a file'''

    if request.method == 'POST':

        pass_key = request.form['passkey'] # webpage parameters
        Efile = request.files['Monkey_upload']
        current_user = session.get('user')
        
        temp_key = hash(pass_key.encode()) # hash the key, get the file in bytes
        usrFILE = bytearray(Efile.read())
        error = Decrypt.check_conditions(hash(usrFILE), Efile.filename, current_user, temp_key) # check if conditions valid
        decryption = Decrypt.decrypt(Efile.filename, current_user, hash(usrFILE), usrFILE) # try decryption, it will return a file name if it works
        logging.debug(f'DECRYPTION: {current_user}')

        if(type(error) != str and decryption): return render_template('decrypted_download.html', fname = decryption) # render download if works
        logging.warning(f'ERROR: Decryption - Failed due to invalid conditions, error message: {error}')
        return render_template('decrypt_metadata.html', msg = error) # and error msg if it doesnt
    return render_template('decrypt_metadata.html')

@app.route('/download_decrypted/<fname>', methods=["GET","POST"])
def download_decrypt_file(fname):
    '''User is downloading decrypted file'''
    path = f'usr/plain/{fname}'
    logging.info(f'DECRYPTION: user downloaded {path}')
    # Perform the file deletion after sending it
    ret_file = io.BytesIO()
    with(open(path, 'rb')) as f: ret_file.write(f.read())
    ret_file.seek(0)
    os.remove(path) # If you seek to store the decrypted files, comment this line out. this deletes the downloaded file from the server.
    return send_file(ret_file, as_attachment=True, download_name=fname)

@app.route('/update_permission', methods=["GET","POST"]) # update decryption permissions for a monkey file 
def update_perms() -> render_template:
    '''User is updating decryption permissions'''
    if request.method == 'POST':

        current_user = session.get('user') # webpage parameters
        file_upload = request.files['image_upload']
        new_decrypt_users = request.form['decrypt_users']

        EFName = (re.sub('\.Monkey$', '', file_upload.filename)) # clean filename and file (to bytes)
        usrFILE = bytearray(file_upload.read())
        
        update_status = Decrypt.update_permissions(usrFILE, EFName, current_user, new_decrypt_users) # try updating
        logging.info(f'DECRYPTION: updating permissions completion status for {EFName}: {update_status}')
    return render_template('update_permission.html')

if __name__ == '__main__':
    #serve(app, host='0.0.0.0', port=5000)
    # if the above function is buggy (servee is a function of waitress module, our wsgi server), use below instead
    app.run(debug=True)