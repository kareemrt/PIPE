# Name : app.py
# Auth : Hannah S & Kareem T (6/5/23)
# Desc : Web app frameworks
from flask import Flask, render_template, g, request, redirect, url_for, session, send_file
import Encrypt
import Security
import Decrypt
import re

app = Flask(__name__, static_folder = 'src/static', template_folder = 'src/templates')
DATABASE = 'src/Crypto.db'
app.secret_key = 'your_secret_key'

@app.route('/') # Login Module
def home(): 
    msg = 'Login Below!' if session.get('msg') == None else session.get('msg')
    session.pop('msg', None)
    return render_template('home.html', message = msg)

@app.route('/login', methods=['POST']) # Login Module
def authenicate():
    '''User account authentication (register/login) via 'username' and 'password' entry boxes'''
    user, passw, action = request.form['user'], request.form['passw'], request.form['button'] # Retrieve user credentials / action
    # User pressed login
    if action == 'Login':   
        if Security.login(user, passw): # Success
            print(f'User logged in as {user}')
            session['user'], session['logged_in'] = user, "True"
            return render_template('ev.html', message = 'Logged in!')
        print(f'User failed to log in as: {user}')
        session['msg'] = 'False credentials' # Failure
        return redirect(url_for('home')) 
    # User pressed register
    if action == 'Sign-Up':   
        if Security.register(user, passw): # Success
            print(f'User registered as {user}')
            session['msg'], session['logged_in'] = 'Registered successfully!', "True"
            return render_template('ev.html', message = 'Registered!')
        print(f'User failed to register as: {user}')
        session['msg'] = 'Username taken!' # Failure
        return redirect(url_for('home'))

#connects buttons on ev to metadata pages ask hannah
"""
@app.route('/ev', methods=['POST', 'GET'])
def choose() -> render_template:

    if request.method == 'POST':

        action = request.form['button']

        if action == 'Encrypt': #user chooses encrypt
            return render_template('encrypt_metadata.html')
        if action == 'Decrypt': #user chooses decrypt
            return render_template('decrypt_metadata.html')
    return render_template('ev.html')

"""
@app.route('/ev', methods=['POST', 'GET']) # Encrypt / Decrypt module
def choose() -> render_template:

    if session.get('logged_in') != "True": # Ensure they logged in
        print(f'User attempted encryption/decryption without logging in')
        session['msg'] = 'You must be logged in to encrypt/decrypt!'
        return redirect(url_for('home'))
    print(session.get('user'), 'is choosing to encrypt/decrypt')
    #session.pop('logged_in', None)

    if request.method == 'POST':

        action = request.form['button']

        if action == 'Encrypt': #user chooses encrypt
            return render_template('encrypt_metadata.html')
        if action == 'Decrypt': #user chooses decrypt
            return render_template('decrypt_metadata.html')
    return render_template('ev.html')
#Hannah's updates

@app.route('/encrypt_metadata', methods=['POST', 'GET']) # Encrypt module
def accept_metadata() -> render_template:

    if request.method == 'POST':
        current_user = session.get('user')
        file_name = request.form['file_name']
        pass_key = request.form['passkey']
        decrypt_users = request.form['decrypt_users']
        image_upload = request.files['image_upload']
        print(file_name, pass_key, decrypt_users)

        list_of_users = re.findall(r'\b\S+\b', decrypt_users)

        if image_upload: print("UPLOAD: we got something")
        if Encrypt.check_perms_exist(list_of_users) == False: return render_template("encrypt_metadata.html", msg = "One or more of these users do not exist! please try again") #Tried to give decrypt permission to users that do not exist
        EFName = Encrypt.encrypt(image_upload.read(), pass_key, current_user, decrypt_users, file_name)      

        return render_template('download_encrypted.html', msg = "File Successfully secured!", EFName = EFName)
    return render_template('encrypt_metadata.html')

@app.route('/download_encrypted/<EFname>', methods=["GET","POST"]) # Encrypt module
def download_file(EFname):
    path = f'usr/monkeys/{EFname}.Monkey'
    return send_file(path, as_attachment=True)

@app.route('/decrypt_metadata', methods=['POST', 'GET']) # Decrypt module
def authorize_decryption() -> render_template:

    if request.method == 'POST':

        name = request.form['file_name']
        pass_key = request.form['passkey']
        Efile = request.files['Monkey_upload']
        current_user = session.get('user')
        
        temp_key = Encrypt.sha256_hash(pass_key.encode())
        usrFILE = bytearray(Efile.read())
        status = Decrypt.check_conditions(usrFILE, Efile.filename, current_user, temp_key)
        if(type(status) != str): 
            fname = Decrypt.decrypt(Efile.filename, current_user, Encrypt.sha256_hash(usrFILE), usrFILE)
            return render_template('decrypted_download.html', fname = fname)
        else: return render_template('decrypt_metadata.html', msg = status)
        
    
    return render_template('decrypt_metadata.html')

@app.route('/download_decrypted/<fname>', methods=["GET","POST"]) # Decrypt module
def download_decrypt_file(fname):
    path = f'usr/plain/{fname}'
    return send_file(path, as_attachment=True)


@app.route('/update_permission', methods=["GET","POST"]) # update decryption permissions for a monkey file 
def update_perms() -> render_template:

    if request.method == 'POST':

        current_user = session.get('user')
        file_upload = request.files['image_upload']
        new_decrypt_users = request.form['decrypt_users']
        EFName = (re.sub('\.Monkey$', '', file_upload.filename))
        usrFILE = bytearray(file_upload.read())

        if Decrypt.check_conditions(usrFILE, EFName, current_user, check_owner = True):
            Security.update_permissions(EFName, new_decrypt_users)

 
    return render_template('update_permission.html')


@app.route('/logout', methods=["GET","POST"]) # update decryption permissions for a monkey file 
def logout():
        session.pop('logged_in', None)

        return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)