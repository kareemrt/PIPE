from flask import Flask, render_template

app = Flask(__name__, static_folder = '/src/static', template_folder = '/src/templates')

@app.route('/')
def hello():
    return render_template('index.html')

@app.route('/login')
def authenicate():
    return 'Hello World'


if __name__ == '__main__':
    app.run(debug=True)