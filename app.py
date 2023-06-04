from flask import Flask, render_template, g, request, redirect, url_for, session
import Security
#import Encrypt
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



@app.route('/encrypt_metadata', methods=['POST'])
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
            return render_template("download_encrypted.html", msg = "These Users do not exist!") #Tried to give decrypt permission to users that do not exist


        #print(Encrypt.encrypt(image_upload, pass_key, current_user, decrypt_users, file_name))      

        return render_template('download_encrypted.html', msg = "data committed success")





if __name__ == '__main__':
    app.run(debug=True)