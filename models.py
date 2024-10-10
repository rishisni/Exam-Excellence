from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    roll_or_faculty_id = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_confirmed = db.Column(db.Boolean, default=False)  # For email verification
    confirmed_at = db.Column(db.DateTime)  # Time of email confirmation
    is_student = db.Column(db.Boolean, default=False)
    is_faculty = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        """Hash and set the password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check if the provided password matches the hashed password."""
        return check_password_hash(self.password_hash, password)

    def confirm(self):
        """Mark the user as confirmed and set the confirmation timestamp."""
        self.is_confirmed = True
        self.confirmed_at = datetime.utcnow()

    def is_valid_role(self):
        """Ensure the user has one role, either student or faculty, but not both."""
        return self.is_student != self.is_faculty
