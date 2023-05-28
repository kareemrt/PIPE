from flask import Flask, render_template, g, request
import sqlite3

app = Flask(__name__, static_folder = 'src/static', template_folder = 'src/templates')
DATABASE = 'src/Crypto.db'

def get_db():
    '''Connect to SQLite DB (returns DB)'''
    db = getattr(g, '_database', None)
    if db is None: db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    '''Close SQLite connection'''
    db = getattr(g, '_database', None)
    if db is not None: db.close()

@app.route('/')
def home() -> render_template:
    '''HOME PAGE'''
    return render_template('home.html', message = 'Login/Register Below!')

@app.route('/login', methods=['POST'])
def authenicate() -> render_template:
    '''User account authentication (register/login) via 'username' and 'password' entry boxes'''
    user = request.form['user']     # Retrieve credentials from user
    passw = request.form['passw']
    action = request.form['button']
    db = get_db()       # Connect to DB
    c = db.cursor()
    if action == 'Login':     # User pressed login
        if c.execute('SELECT COUNT(*) FROM login WHERE user = ? AND pass = ?', (user, passw)).fetchone()[0] == 0: return render_template('home.html', message = 'Account does not exist!') # Fail
        else:
            g.user, g.passw = user, passw
            return render_template('ev.html', message = 'Logged in!') # Success
    if action == 'Sign-Up':   # User pressed sign-up
        if c.execute('SELECT COUNT(*) FROM login WHERE user = ?', (user,)).fetchone()[0] > 0: return render_template('home.html', message = 'Username taken!') # Fail
        else: # Success
            c.execute('INSERT INTO login (user, pass) VALUES (?, ?)', (user, passw))
            db.commit()
            return render_template('ev.html', message = 'Registered!')
    db.commit()    # Commit
    db.close()

if __name__ == '__main__':
    app.run(debug=True)