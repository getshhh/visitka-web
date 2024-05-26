from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from db import get_db_connection, init_db  
from db import sqlite3

app = Flask(__name__)

@app.route("/")
@app.route("/index")
def index():
    if 'user_id' in session:
        return render_template("index_logged_in.html", username=session['user_name'])
    else:
        return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', (name, email, hashed_password))
            conn.commit()
            flash('You were successfully registered!')
            session['user_id'] = email
            session['user_name'] = name
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            flash('Email address already registered.')
            return redirect(url_for('register'))
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user is None:
            flash('Incorrect email.')
        elif not check_password_hash(user['password'], password):
            flash('Incorrect password.')
        else:
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            return redirect(url_for('index'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route("/cards")
def cards():
     return render_template("cards_html.html")



if __name__ == '__main__':
    init_db()  # Инициализация базы данных при запуске приложения
    app.run(debug=True)
