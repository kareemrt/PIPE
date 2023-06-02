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
def authenicate() -> render_template:
    '''User account authentication (register/login) via 'username' and 'password' entry boxes'''
    user, passw, action = request.form['user'], request.form['passw'], request.form['button'] # Retrieve user credentials / action
    # User pressed login
    if action == 'Login':   
        if Security.login(user, passw): # Success
            session['user'], session['logged_in'] = user, "True"
            return redirect(url_for('encrypt_decrypt')) 
        session['msg'] = 'False credentials' # Failure
        return redirect(url_for('home')) 
    # User pressed register
    if action == 'Sign-Up':   
        if Security.register(user, passw): # Success
            session['msg'], session['logged_in'] = 'Registered successfully!', "True"
            return redirect(url_for('encrypt_decrypt'))
        session['msg'] = 'Username taken!' # Failure
        return redirect(url_for('home'))

@app.route('/encrypt_decrypt', methods=['GET'])
def encrypt_decrypt() -> render_template:
    '''User account authentication (register/login) via 'username' and 'password' entry boxes'''
    if session.get('logged_in') != "True": # Ensure they logged in
        session['msg'] = 'You must be logged in to encrypt/decrypt!'
        return redirect(url_for('home'))
    print(session.get('user'))
    session.pop('logged_in', None)
    return render_template('ev.html') # Show page / give users choice


if __name__ == '__main__':
    app.run(debug=True)