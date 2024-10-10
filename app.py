from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from itsdangerous import URLSafeTimedSerializer
from models import db, User  # Import User model from models.py
from dotenv import load_dotenv
from functools import wraps
# from flask_login import login_required
load_dotenv()  # Load environment variables from .env file

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  # Change to MySQL later
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')  # Ensure to set this
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT')  # Used for token generation
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')  # Your email
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')  # Your email password
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('EMAIL_USER')  # Default sender for emails

db.init_app(app)
mail = Mail(app)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You need to log in first.', 'danger')
            return redirect(url_for('login'))  # Redirect to login page if not authenticated
        return f(*args, **kwargs)
    return decorated_function


# Token Serializer
def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=expiration)
    except:
        return False
    return email

# Email verification route
@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first_or_404()

    if user.is_confirmed:
        flash('Account already confirmed. Please login.', 'success')
    else:
        user.is_confirmed = True
        user.confirmed_at = datetime.utcnow()
        db.session.commit()
        flash('Your account has been confirmed. Thanks!', 'success')

    return redirect(url_for('login'))

# Send verification email function
def send_verification_email(user_email):
    token = generate_confirmation_token(user_email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = f'<p>Hi!</p><p>Click the link to verify your email:</p><a href="{confirm_url}">Verify your email</a>'
    msg = Message('Confirm Your Email', recipients=[user_email], html=html)
    mail.send(msg)

@app.route('/')
def home():
    return render_template('home.html')  # Create a home.html template

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        roll_or_faculty_id = request.form['roll_or_faculty_id']
        email = request.form['email']
        password = request.form['password']
        phone = request.form['phone']

        is_student = 'is_student' in request.form
        is_faculty = 'is_faculty' in request.form

        if not (is_student or is_faculty):
            flash('You must select a role (Student or Faculty).', 'danger')
            return redirect(url_for('register'))

        new_user = User(
            name=name,
            roll_or_faculty_id=roll_or_faculty_id,
            email=email,
            phone=phone,
            is_student=is_student,
            is_faculty=is_faculty,
            is_confirmed=False  # Initially not confirmed
        )
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        send_verification_email(new_user.email)  # Send email verification
        flash('Registration successful! Please verify your email.', 'success')
        return redirect(url_for('home'))

    return render_template('register.html')  # Create a register.html template

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['identifier']  # Get the input for email or roll_no/faculty_id
        password = request.form['password']

        # Check if the input is an email
        if '@' in identifier:
            user = User.query.filter_by(email=identifier).first()
        else:
            # Assuming roll_no and faculty_id are unique and can be checked against the same column
            user = User.query.filter((User.roll_or_faculty_id == identifier) ).first()

        if user and user.check_password(password):
            if user.is_confirmed:  # Ensure the email is confirmed
                session['user_id'] = user.id
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))  # Create a dashboard route
            else:
                flash('Please confirm your email before logging in.', 'danger')
                return redirect(url_for('login'))

        flash('Login failed. Check your credentials.', 'danger')
        return redirect(url_for('login'))

    return render_template('login.html')  # Create a login.html template


@app.route('/dashboard')
@login_required  # Assuming you have a login_required decorator for authentication
def dashboard():
    user = User.query.get(session['user_id'])  # Fetch the user from the database

    if user.is_faculty:
        return render_template('dashboard.html', user=user)
    elif user.is_student:
        return render_template('dashboard.html', user=user)
    else:
        flash('You do not have access to this page.', 'danger')
        return redirect(url_for('login'))  # Redirect to login or an access denied page


@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Remove user_id from session
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))  # Redirect to login page


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(debug=True)
