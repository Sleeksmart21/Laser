from core import db
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


class UrlAnalytics(db.Model):
    __tablename__ = 'urlanalytics'
    id = db.Column(db.Integer, primary_key=True)
    shortened_url = db.Column(db.String(255))
    timestamp = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp())
    ip_address = db.Column(db.String(255))
    user_agent = db.Column(db.String(255))
    referral_source = db.Column(db.String(255))

    def __init__(self, shortened_url, ip_address, user_agent, referral_source):
        self.shortened_url = shortened_url
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.referral_source = referral_source


class ShortUrls(db.Model):
    __tablename__ = 'shorturls'
    id = db.Column(db.Integer, primary_key=True)
    original_url = db.Column(db.String(2048), nullable=False)
    short_id = db.Column(db.String(16), nullable=False, unique=True)
    click_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    clicks = db.relationship('Click', backref='url', lazy=True)

    def __init__(self, original_url, short_id, click_count, created_at):
        self.original_url = original_url
        self.short_id = short_id
        self.click_count = click_count
        self.created_at = datetime.now()


class Click(db.Model):
    __tablename__ = 'clicks'
    id = db.Column(db.Integer, primary_key=True)
    shorturl_id = db.Column(db.Integer, db.ForeignKey('shorturls.id'), nullable=False)
    location = db.Column(db.String(128), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


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
    # password = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(150))
    created_at = db.Column(db.DateTime(), default=datetime.now(), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
