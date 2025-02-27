from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail, Message
from flask_session import Session  # Add for server-side sessions
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
from psycopg2 import pool
import os
import random
import string
import logging
import redis  # For session storage
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Email configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')
mail = Mail(app)

# Server-side sessions with Redis
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379'))
Session(app)

# PostgreSQL connection pool
db_config = {
    'dbname': os.getenv('DB_NAME'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'host': os.getenv('DB_HOST'),
    'port': os.getenv('DB_PORT', '5432')
}
db_pool = psycopg2.pool.SimpleConnectionPool(1, 20, **db_config)

# Logging setup
logging.basicConfig(level=logging.INFO, filename='app.log', format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

def init_db():
    conn = db_pool.getconn()
    try:
        with conn.cursor() as c:
            c.execute('''CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY, 
                email TEXT UNIQUE NOT NULL, 
                password TEXT NOT NULL)''')
            c.execute('''CREATE TABLE IF NOT EXISTS reset_codes (
                email TEXT, 
                code TEXT, 
                FOREIGN KEY(email) REFERENCES users(email))''')
            conn.commit()
            logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        conn.rollback()
    finally:
        db_pool.putconn(conn)

def generate_reset_code(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

@app.route('/')
def home():
    if 'email' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', email=session['email'])

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        if not email or not password:  # Basic validation
            flash('Email and password are required!')
            return render_template('register.html')
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        conn = db_pool.getconn()
        try:
            with conn.cursor() as c:
                c.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (email, hashed_password))
                conn.commit()
                logger.info(f"User registered: {email}")
                flash('Registration successful! Please log in.')
                return redirect(url_for('login'))
        except psycopg2.IntegrityError:
            conn.rollback()
            flash('Email already exists!')
            logger.warning(f"Registration failed: Email {email} already exists.")
            return render_template('register.html')
        except Exception as e:
            conn.rollback()
            logger.error(f"Error during registration: {e}")
            flash('An error occurred. Please try again.')
            return render_template('register.html')
        finally:
            db_pool.putconn(conn)
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        if not email or not password:
            flash('Email and password are required!')
            return render_template('login.html')

        conn = db_pool.getconn()
        try:
            with conn.cursor() as c:
                c.execute("SELECT password FROM users WHERE email = %s", (email,))
                user = c.fetchone()
                if user and check_password_hash(user[0], password):
                    session['email'] = email
                    logger.info(f"User logged in: {email}")
                    return redirect(url_for('home'))
                else:
                    flash('Invalid email or password!')
                    logger.warning(f"Login failed for email: {email}")
        except Exception as e:
            logger.error(f"Error during login: {e}")
            flash('An error occurred. Please try again.')
        finally:
            db_pool.putconn(conn)
    return render_template('login.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'email' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        email = session['email']
        if not old_password or not new_password:
            flash('Both passwords are required!')
            return render_template('change_password.html')

        conn = db_pool.getconn()
        try:
            with conn.cursor() as c:
                c.execute("SELECT password FROM users WHERE email = %s", (email,))
                stored_password = c.fetchone()
                if stored_password and check_password_hash(stored_password[0], old_password):
                    hashed_new_password = generate_password_hash(new_password, method='pbkdf2:sha256')
                    c.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_new_password, email))
                    conn.commit()
                    logger.info(f"Password changed for: {email}")
                    flash('Password changed successfully!')
                    return redirect(url_for('home'))
                else:
                    flash('Incorrect old password!')
                    logger.warning(f"Password change failed for {email}: Incorrect old password")
        except Exception as e:
            conn.rollback()
            logger.error(f"Error during password change: {e}")
            flash('An error occurred. Please try again.')
        finally:
            db_pool.putconn(conn)
    return render_template('change_password.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        if not email:
            flash('Email is required!')
            return render_template('forgot_password.html')
        
        conn = db_pool.getconn()
        try:
            with conn.cursor() as c:
                c.execute("SELECT id FROM users WHERE email = %s", (email,))
                user = c.fetchone()
                if user:
                    reset_code = generate_reset_code()
                    c.execute("DELETE FROM reset_codes WHERE email = %s", (email,))
                    c.execute("INSERT INTO reset_codes (email, code) VALUES (%s, %s)", (email, reset_code))
                    conn.commit()
                    
                    msg = Message("Password Reset Code", recipients=[email])
                    msg.body = f"Your password reset code is: {reset_code}. Use it to reset your password."
                    mail.send(msg)
                    
                    logger.info(f"Reset code sent to: {email}")
                    flash('A reset code has been sent to your email.')
                    return redirect(url_for('reset_password'))
                else:
                    flash('Email not found!')
                    logger.warning(f"Reset password failed: Email {email} not found")
        except Exception as e:
            conn.rollback()
            logger.error(f"Error during forgot password: {e}")
            flash('An error occurred. Please try again.')
        finally:
            db_pool.putconn(conn)
    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        reset_code = request.form['reset_code']
        new_password = request.form['new_password']
        if not all([email, reset_code, new_password]):
            flash('All fields are required!')
            return render_template('reset_password.html')

        conn = db_pool.getconn()
        try:
            with conn.cursor() as c:
                c.execute("SELECT code FROM reset_codes WHERE email = %s", (email,))
                stored_code = c.fetchone()
                if stored_code and stored_code[0] == reset_code:
                    hashed_new_password = generate_password_hash(new_password, method='pbkdf2:sha256')
                    c.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_new_password, email))
                    c.execute("DELETE FROM reset_codes WHERE email = %s", (email,))
                    conn.commit()
                    logger.info(f"Password reset for: {email}")
                    flash('Password reset successfully! Please log in.')
                    return redirect(url_for('login'))
                else:
                    flash('Invalid reset code or email!')
                    logger.warning(f"Reset failed for {email}: Invalid code")
        except Exception as e:
            conn.rollback()
            logger.error(f"Error during reset password: {e}")
            flash('An error occurred. Please try again.')
        finally:
            db_pool.putconn(conn)
    return render_template('reset_password.html')

@app.route('/logout')
def logout():
    session.pop('email', None)
    logger.info("User logged out")
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))