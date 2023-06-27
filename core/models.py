from core import db
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


class ShortUrls(db.Model):
    __tablename__ = 'shorturls'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    original_url = db.Column(db.String(2048), nullable=False)
    short_id = db.Column(db.String(16), nullable=False, unique=True)
    short_url = db.Column(db.String(100))
    click_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    clicks = db.relationship('Click', backref='shorturls', lazy=True)
    shorturls_user = db.relationship('User', backref='shorturls')

    def __init__(self, user_id, original_url, short_id, short_url, click_count, created_at):
        self.user_id = user_id
        self.original_url = original_url
        self.short_id = short_id
        self.short_url = short_url
        self.click_count = click_count
        self.created_at = datetime.now()


class Click(db.Model):
    __tablename__ = 'clicks'
    id = db.Column(db.Integer, primary_key=True)
    short_url_id = db.Column(db.Integer, db.ForeignKey('shorturls.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(255))
    referral_source = db.Column(db.String(2048))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, short_url_id, ip_address, user_agent, referral_source):
        self.short_url_id = short_url_id
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.referral_source = referral_source
        self.created_at = datetime.now()


class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    company_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    job_title = db.Column(db.String(100), nullable=False)
    company_size = db.Column(db.String(50))
    primary_use_case = db.Column(db.String(100), nullable=False)
    country = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(150))
    created_at = db.Column(db.DateTime(), default=datetime.now(), nullable=False)

    short_urls = db.relationship('ShortUrls', backref='users')


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
