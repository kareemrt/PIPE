from flask import Flask, render_template, g, request, redirect, url_for, session
import Security
app = Flask(__name__, static_folder = 'src/static', template_folder = 'src/templates')
app.secret_key = 'your_secret_key'

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



#connects buttons on ev to metadata pages

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
        file_name = request.form['file_name']
        pass_key = request.form['passkey']
        decrypt_users = request.form['decrypt_users']

        print(file_name, pass_key, decrypt_users)


    return render_template('download_encrypted.html', msg = "data committed exist")





if __name__ == '__main__':
    app.run(debug=True)