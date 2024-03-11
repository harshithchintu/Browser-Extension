from flask import Flask, request, render_template, redirect, url_for, session
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

# Dummy database to store encrypted passwords
passwords = {}

# Dummy database to store user data
users = {'user1': 'password1'}  # In practice, use a secure method to store passwords


# Function to encrypt passwords
def encrypt_password(password):
    key = app.secret_key
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(password.encode())


# Function to decrypt passwords
def decrypt_password(encrypted_password):
    key = app.secret_key
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(encrypted_password).decode()


# Route to handle saving passwords
@app.route('/save_password', methods=['POST'])
def save_password():
    data = request.json
    url = data['url']
    username = data['username']
    password = encrypt_password(data['password'])
    passwords[url] = {'username': username, 'password': password}
    return 'Password saved successfully'


# Route to handle retrieving passwords
@app.route('/get_password', methods=['GET'])
def get_password():
    url = request.args.get('url')
    if url in passwords:
        password = decrypt_password(passwords[url]['password'])
        return {'username': passwords[url]['username'], 'password': password}
    else:
        return 'Password not found'


# Route to render login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            session['username'] = username
            print('login')
            return redirect(url_for('dashboard'))
        else:
            print('Login')
            return 'Invalid username or password'
    return render_template('login.html')


# Route to render dashboard
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html')
    else:
        print('dashboard')
        return redirect(url_for('login'))


# Route to handle logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
