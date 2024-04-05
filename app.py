from flask import Flask, render_template, request, redirect, url_for, session
from flask_talisman import Talisman
import sqlite3  
import re
import html

app = Flask(__name__)
app.secret_key = 'cTf5_aR3_fUn'


# Content Security Policy taken from geeksforgeeks (reference can be found in the paper)
talisman = Talisman(app)
# Content Security Policy (CSP) Header
csp = {
    'default-src': [
        '\'self\''
    ]
}
# HTTP Strict Transport Security (HSTS) Header
hsts = {
    'max-age': 31536000,
    'includeSubDomains': True
}
# Enforce HTTPS and other headers   
talisman.force_https = True
talisman.force_file_save = True
talisman.x_xss_protection = True
talisman.session_cookie_secure = True
talisman.session_cookie_samesite = 'Lax'
talisman.frame_options_allow_from = 'https://www.google.com'
 
# Add the headers to Talisman
talisman.content_security_policy = csp
talisman.strict_transport_security = hsts


def create_tables():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS feedbacks (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, feedback TEXT)''')
    conn.commit()
    conn.close()

create_tables()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not is_valid_username(username):
            return render_template('error.html', error_message="Invalid username format. Please choose a different username.")
        if not is_password_strong(password):
            return render_template('error.html', error_message="Password does not meet the strength criteria. Please choose a stronger password.")
        try:
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('error.html', error_message="Username already exists. Please choose a different username.")
        except sqlite3.OperationalError as e:
            return render_template('error.html', error_message="An error occurred while processing your request. Please try again later.")
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # input validation
        if not is_valid_username(username):
            return render_template('error.html', error_message="Invalid username format.")
        conn = sqlite3.connect('database.db')
        
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            session['username'] = user[0]
            return redirect(url_for('feedback'))
        else:
            return 'Invalid username or password'
    return render_template('login.html')

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        feedback_text = request.form['feedback']
        username = session['username']
        
        # escape user input before inserting it into the database for xss protection
        feedback_text = html.escape(feedback_text)
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("INSERT INTO feedbacks (username, feedback) VALUES (?, ?)", (username, feedback_text))
        conn.commit()
        conn.close()
        message = 'Feedback submitted successfully!'
        return render_template('feedback.html', message=message)
    return render_template('feedback.html')
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = session['username']
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        

        if not is_password_strong(new_password):
            return render_template('error.html', error_message="New password does not meet the strength criteria. Please choose a stronger password.")
        
        # check if the current password provided matches the one in the database
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        stored_password = c.fetchone()[0]
        conn.close()
        
        if current_password != stored_password:
            return "Incorrect current password"
        
        # update the password in the database
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("UPDATE users SET password = ? WHERE username = ?", (new_password, username))
        conn.commit()
        conn.close()

        session.pop('username', None)
        return redirect(url_for('login'))
    
    return render_template('login.html')   
@app.route('/change_password_form')
def change_password_form():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('change_password.html', feedback_url=url_for('feedback'))

def is_password_strong(password):
    # password should be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[!@#$%^&*()-_+=]', password):
        return False
    return True
def is_valid_username(username):
    # username must contain valid characters and be atleast 5-15 characters long
    return re.match(r'^[a-zA-Z0-9_-]{5,15}$', username) is not None

if __name__ == '__main__':
    app.run(debug=True)
