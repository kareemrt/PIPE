from flask import Flask, render_template, g, request, redirect, url_for, session, send_file
import Encrypt
import Security
import re
#import sqlite for temp funtion get_db
import sqlite3

app = Flask(__name__, static_folder = 'src/static', template_folder = 'src/templates')

#for temp function
DATABASE = 'src/Crypto.db'


app.secret_key = 'your_secret_key'


#temp funtion to test query in accept_metadata
def get_db():
    '''Connect to SQLite DB (returns DB)'''
    db = getattr(g, '_database', None)
    if db is None: db = g._database = sqlite3.connect(DATABASE)
    return db
#end of temp funtion

@app.route('/')
def home(): 
    msg = 'Login Below!' if session.get('msg') == None else session.get('msg')
    session.pop('msg', None)
    return render_template('home.html', message = msg)

@app.route('/login', methods=['POST'])
def authenicate():
    '''User account authentication (register/login) via 'username' and 'password' entry boxes'''
    user, passw, action = request.form['user'], request.form['passw'], request.form['button'] # Retrieve user credentials / action
    # User pressed login
    if action == 'Login':   
        if Security.login(user, passw): # Success
            session['user'], session['logged_in'] = user, "True"
            return redirect(url_for('choice')) 
        session['msg'] = 'False credentials' # Failure
        return redirect(url_for('home')) 
    # User pressed register
    if action == 'Sign-Up':   
        if Security.register(user, passw): # Success
            session['msg'], session['logged_in'] = 'Registered successfully!', "True"
            return redirect(url_for('choice'))
        session['msg'] = 'Username taken!' # Failure
        return redirect(url_for('home'))

@app.route('/choice', methods=['GET', 'POST'])
def choice():
    '''User account authentication (register/login) via 'username' and 'password' entry boxes'''
    if session.get('logged_in') != "True": # Ensure they logged in
        session['msg'] = 'You must be logged in to encrypt/decrypt!'
        return redirect(url_for('home'))
    print(session.get('user'))
    #session.pop('logged_in', None)

    return render_template('ev.html', message = 'Registered!')



#connects buttons on ev to metadata pages ask hannah

@app.route('/ev', methods=['POST'])
def choose() -> render_template:
    action = request.form['button']

    if action == 'Encrypt': #user chooses encrypt
        return render_template('encrypt_metadata.html')
    if action == 'Decrypt': #user chooses decrypt
        return render_template('decrypt_metadata.html')
    


    #connects buttons on ev to metadata pages
    
   
#Hannah's updates



@app.route('/encrypt_metadata', methods=['POST', 'GET'])
def accept_metadata() -> render_template:

    if request.method == 'POST':
        current_user = session.get('user')
        file_name = request.form['file_name']
        pass_key = request.form['passkey']
        decrypt_users = request.form['decrypt_users']
        image_upload = request.files['image_upload']

        print(file_name, pass_key, decrypt_users)

        if image_upload:
            print("we got something")

        if Security.check_perms_exist(decrypt_users) == False:
            return render_template("encrypt_metadata.html", msg = "One or more of these users do not exist! please try again") #Tried to give decrypt permission to users that do not exist


        Encrypt.encrypt(image_upload.read(), pass_key, current_user, decrypt_users, file_name)      

        return render_template('download_encrypted.html', msg = "File Successfully secured!")

    return render_template('encrypt_metadata.html')


@app.route('/download_encrypted', methods=["GET","POST"])
def download_file():
    Efile = Security.retrieve_last_Efile()
    #print(Efile) 
    path = f'{Efile}.Monkey'
    return send_file(path, as_attachment=True)

@app.route('/decrypt_metadata', methods=['POST', 'GET'])
def authorize_decryption() -> render_template:

    if request.method == 'POST':

        name = request.form['file_name']
        pass_key = request.form['passkey']
        Efile = request.files['Monkey_upload']
        current_user = session.get('user')
        


        temp_key = Encrypt.sha256_hash(pass_key.encode())
        super_temp_key = Encrypt.RSA_encryption(temp_key)
        
        if Security.check_file_exists(str(Efile.filename)) == False:
            return render_template('decrypt_metadata.html', msg = 'Sorry, This file has either been modified or does not exist')
        else:
            Efile_name= re.sub('\.Monkey$', '', str(Efile.filename))
            print(Efile_name)
        
        if Security.user_has_perm(current_user, Efile_name) == False:
            return render_template('decrypt_metadata.html', msg = 'Sorry, you do not have permission to decrypt this file')

        if Security.check_passkey(super_temp_key, Efile_name) == True:
            return render_template('decrypt_metadata.html', msg = 'Sorry, this passkey is incorrect')
        
        
        return render_template('decrypted_download.html')

    
    return render_template('decrypt_metadata.html')

#this route currently does nothing
@app.route('/download_decrypted', methods=["GET","POST"])
def download_decrypt_file():
    #Efile = Security.retrieve_last_Efile()
    #print(Efile) 
    path = ''
    return send_file(path, as_attachment=True)








if __name__ == '__main__':
    app.run(debug=True)