import os
import random
import string
import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail, Message
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
from psycopg2 import pool
import redis
from dotenv import load_dotenv
from urllib.parse import urlparse

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
app.config['SESSION_REDIS'] = redis.from_url(os.getenv('REDIS_URL'))
Session(app)

# Heroku PostgreSQL connection setup
DATABASE_URL = os.getenv('DATABASE_URL')

# Parse DATABASE_URL
url = urlparse(DATABASE_URL)

# PostgreSQL connection pool
db_pool = psycopg2.pool.SimpleConnectionPool(
    1, 20,
    user=url.username,
    password=url.password,
    host=url.hostname,
    port=url.port,
    database=url.path[1:],  # Remove the leading '/' from the database name
    sslmode='require'
)

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
        if not email or not password:
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

# Additional routes for login, change_password, forgot_password, etc.

@app.route('/logout')
def logout():
    session.pop('email', None)
    logger.info("User logged out")
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()  # Initialize the database when the app starts
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))