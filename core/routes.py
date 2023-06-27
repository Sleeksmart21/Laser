from datetime import datetime
from core.models import ShortUrls, User, Contact, Click
from core import app, db
from random import choice
import string
from flask import render_template, request, flash, redirect, url_for, send_file, abort, session
import base64
import qrcode
from io import BytesIO
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
import re
from plotly.subplots import make_subplots
import plotly.graph_objects as go
import sqlite3
import psycopg2
from psycopg2 import sql
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from core import limiter
from core import cache
from flask_caching import Cache
import phonenumbers


# Flask-Login configuration
login_manager = LoginManager(app)
login_manager.login_view = 'login'


DB_NAME = 'Linksnip'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Custom filter for base64 encoding
@app.template_filter('b64encode')
def base64_encode(value):
    return base64.b64encode(value).decode('utf-8')


def generate_short_id(num_of_chars: int):
    """Function to generate short_id of specified number of characters"""
    return ''.join(choice(string.ascii_letters + string.digits) for _ in range(num_of_chars))


def validate_email(email):
    # """Validate email format using regular expression"""
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email)


    # """Validate phone number format using python phonenumbers library"""
def validate_phone(phone):
    try:
        parsed_number = phonenumbers.parse(phone, None)
        return phonenumbers.is_valid_number(parsed_number)
    except phonenumbers.phonenumberutil.NumberParseException:
        return False


@app.route('/', methods=['GET', 'POST'])
@cache.cached(timeout=60)
def index():
    qr_image_data = b'My QR Code Data'
    return render_template('index.html')


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')

        # Create a new contact instance
        new_contact = Contact(name=name, email=email, message=message)

        # Save the contact to the database
        db.session.add(new_contact)
        db.session.commit()

        # Redirect or render a success page
        return render_template('contact_success.html')

    return render_template('contact.html')


@app.route('/about')
@cache.cached(timeout=60)
def about():
    return render_template('about.html')


@app.route('/shortenit')
@cache.cached(timeout=60)
def shortenit():
    return render_template('shortenit.html')


@app.route('/shortenedURL')
@cache.cached(timeout=60)
def shortenedURL():
    return render_template('shortenedURL.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        # Redirect to the homepage or another route
        return redirect(url_for('index'))

    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        company_name = request.form.get('company_name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        job_title = request.form.get('job_title')
        company_size = request.form.get('company_size')
        primary_use_case = request.form.get('primary_use_case')
        country = request.form.get('country')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Validate email
        if not validate_email(email):
            flash(f'Invalid email address.')
            return redirect(url_for('register'))

        # Validate phone number
        if not validate_phone(phone):
            flash(f'Invalid phone number.')
            return redirect(url_for('register'))

        # Check if the user already exists in the database
        user = User.query.filter_by(email=email).first()
        if user:
            flash(f'Email address already registered.')
            return redirect(url_for('register'))

        # Check if the passwords match
        if password != confirm_password:
            flash(f'Passwords do not match.')
            return redirect(url_for('register'))

        # Create a new user
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            company_name=company_name,
            email=email,
            phone=phone,
            job_title=job_title,
            company_size=company_size,
            primary_use_case=primary_use_case,
            country=country
        )
        new_user.set_password(password)

        # Save the new user to the database
        db.session.add(new_user)
        db.session.commit()

        flash(f'Registration successful. Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
@cache.cached(timeout=60)
def login():
    if current_user.is_authenticated:
        # Redirect to the homepage or another route
        return redirect(url_for('shortenit'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Find the user by email address
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            # Log in the user
            login_user(user)

            # Store user ID in the session
            session['user_id'] = user.id
            
            # Redirect to the homepage or another route
            return redirect(url_for('shortenit'))
        
        flash(f'Invalid email or password.')
        return redirect(url_for('login'))
    
    return render_template('login.html')


# The URL shortening route and function...
@app.route('/shorten', methods=['GET', 'POST'])
@limiter.limit("10/day", key_func=get_remote_address)
@cache.cached(timeout=60)
@login_required
def shorten():
    qr_image_data = b''
    short_url = ''  # Initialize the variable with a default value
    if request.method == 'POST':
        url = request.form['url']
        short_id = request.form['custom_id']

        # Get the authenticated user's ID
        user_id = current_user.id

        if short_id and ShortUrls.query.filter_by(short_id=short_id).first():
            flash(f'Please enter a different custom ID!')
            return redirect(url_for('shortenit'))

        if not url:
            flash(f'The URL is required!')
            return redirect(url_for('shortenit'))

        if not short_id:
            short_id = generate_short_id(8)

        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=5, border=4)
        qr.add_data(url)
        qr.make(fit=True)

        qr_stream = BytesIO()
        qr.make_image(fill_color='black', back_color='white').save(qr_stream, 'PNG')
        qr_stream.seek(0)


        new_link = ShortUrls(
            user_id=user_id,
            original_url=url,
            short_id=short_id,
            short_url=short_url,
            click_count=0,
            created_at=datetime.now()
        )
        db.session.add(new_link)
        db.session.commit()

        short_url = request.host_url + short_id
        if qr_image_data is not None:
            return render_template('shortenedURL.html', short_url=short_url, qr_image_data=qr_stream.getvalue())
        else:
            flash(f'No image generated')
    return render_template('shortenedURL.html', qr_image_data=qr_image_data)

# The redirection route and function
@app.route('/<short_id>')
@cache.cached(timeout=60)
@login_required
def redirect_url(short_id):
    link = ShortUrls.query.filter_by(short_id=short_id).first()

    if link:
        link.click_count += 1
        db.session.commit()
        return redirect(link.original_url)
    else:
        flash(f'Invalid URL')
        return redirect(url_for('shortenit'))


@app.route('/download_qr/<qr_image_data>')
def download_qr(qr_image_data):
    # Convert the base64-encoded QR code image data back to bytes
    qr_bytes = base64.b64decode(qr_image_data)

    if qr_bytes:
        qr_filename = 'qr_code.png'
        return send_file(BytesIO(qr_bytes), attachment_filename=qr_filename, as_attachment=True)
    else:
        flash('No image generated')
        return redirect(url_for('index'))


def get_current_user():
    # Using a session-based authentication system
    user_id = session.get('user_id')  # Retrieve the user ID from the session
    if user_id:
        # Querying of the User model
        user = User.query.get(user_id)  # Retrieve the user from the database based on the user ID
        return user

    # If user_id is not found in the session or the user doesn't exist, return None
    return None


def get_user_short_urls(user_id):
    user = User.query.get(user_id)
    if user:
        return ShortUrls.query.filter_by(user_id=user.id).all()
    else:
        return []   


@app.route('/dashboard')
def dashboard():
    # Retrieve the necessary data for the user dashboard
    user = get_current_user()  # Example function to get the current user
    short_urls = get_user_short_urls(user.id)  # Example function to get the user's short URLs

    # Fetch click analytics for each short URL
    click_analytics = {}
    for short_url in short_urls:
        click_analytics[short_url.id] = get_click_analytics(short_url.id)

    # Render the dashboard template and pass the necessary data
    return render_template('dashboard.html', user=user, short_urls=short_urls, click_analytics=click_analytics)


@app.route('/history')
def history():
    url_activities = ShortUrls.query.all()
    return render_template('history.html', url_activities=url_activities)

def get_click_analytics(short_url_id):
    clicks = Click.query.filter_by(short_url_id=short_url_id).all()
    return clicks


def populate_clicks(short_url_id, ip_address, user_agent, referral_source):
    click = Click(short_url_id=short_url_id, ip_address=ip_address, user_agent=user_agent, referral_source=referral_source)
    db.session.add(click)
    db.session.commit()


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
