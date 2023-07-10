from flask import Flask, send_file, render_template, request, flash, redirect, url_for, abort, session
from datetime import datetime
from flask_migrate import Migrate
from random import choice
import string 
import base64
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
import phonenumbers
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import Column, Integer, String
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import qrcode
from io import BytesIO
from flask_sqlalchemy import SQLAlchemy
import re

cache = Cache()

app = Flask(__name__)
cache.init_app(app, config={'CACHE_TYPE': 'simple'})
limiter = Limiter(app, default_limits=["10/day"])
app.secret_key = 'SECRET_KEY'

# Flask-Login configuration
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)


class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)


# Define the models
class ShortUrls(db.Model):
    __tablename__ = 'shorturls'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    original_url = db.Column(db.String(2048), nullable=False)
    short_id = db.Column(db.String(16), nullable=False, unique=True)
    short_url = db.Column(db.String(100))
    click_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    latest_click_date = db.Column(db.DateTime)

	# A ShortURL Can Have Many clicks 
    clickers = db.relationship('Click', backref='shorturl', lazy=True)
    # user = db.relationship('User', backref='shorturls', overlaps="shorturls,shorturls_user")

    def __init__(self, user_id, original_url, short_id, short_url, click_count=0, created_at=None, latest_click_date=None):
        self.user_id = user_id
        self.original_url = original_url
        self.short_id = short_id
        self.short_url = short_url
        self.click_count = click_count
        self.latest_click_date = latest_click_date
 

class Click(db.Model):
    __tablename__ = 'clicks'
    id = db.Column(db.Integer, primary_key=True)
    short_url_id = db.Column(db.Integer, db.ForeignKey('shorturls.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(255))
    referral_source = db.Column(db.String(2048))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    shortened_url = db.relationship('ShortUrls', backref='click', lazy=True)

    def __init__(self, short_url_id, ip_address, user_agent, referral_source):
        self.short_url_id = short_url_id
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.referral_source = referral_source
        # self.created_at = datetime.utcnow()


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
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

	# User Can Have Many ShortURLs 
    short_urls = db.relationship('ShortUrls', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


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

@app.route('/about')
@cache.cached(timeout=60)
def about():
    return render_template('about.html')


@app.route('/shortenit')
@cache.cached(timeout=60)
def shortenit():
    return render_template('shortenit.html')


@app.route('/readmore')
@cache.cached(timeout=60)
def readmore():
    return render_template('readmore.html')


@app.route('/shortenedURL')
@cache.cached(timeout=60)
def shortenedURL():
    return render_template('shortenedURL.html')


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


@app.route('/analytics')
def analytics():
    total_urls = ShortUrls.query.count()
    return render_template('analytics.html', total_urls=total_urls)

def get_latest_click_date(clicks):
    if clicks:
        latest_click = max(clicks, key=lambda x: x.created_at)
        return latest_click.created_at
    return None


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
            flash('Please enter a different custom ID!')
            return redirect(url_for('shortenit'))

        if not url:
            flash('The URL is required!')
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
            short_url='',
            click_count=0,
            created_at=datetime.utcnow()
        )
        db.session.add(new_link)
        db.session.commit()

        # Update the short URL with the host URL and short ID
        short_url = request.host_url + short_id
        new_link.short_url = short_url
        db.session.commit()

        # Fetch the updated short URL with its database ID
        new_link = ShortUrls.query.filter_by(short_id=short_id).first()

        # short_url = request.host_url + short_id
        return render_template('shortenedURL.html', short_url=short_url, qr_image_data=qr_stream.getvalue(),
                               new_link=new_link)
        # if qr_image_data is not None:
            # return render_template('shortenedURL.html', short_url=short_url, qr_image_data=qr_stream.getvalue())
        # else:
            # flash('No image generated')
    return render_template('shortenedURL.html', qr_image_data=qr_image_data)


@app.route('/delete_url/<int:url_id>', methods=['POST'])
@login_required
def delete_url(url_id):
    url = ShortUrls.query.get(url_id)

    if url:
        # Check if the URL belongs to the current user
        if url.user_id == current_user.id:
            # Delete the URL from the database
            db.session.delete(url)
            db.session.commit()
            flash('URL deleted successfully.')
        else:
            flash('You are not authorized to delete this URL.')
    else:
        flash('URL not found.')

    return redirect(url_for('dashboard'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        # Redirect to the login page or another route
        return redirect(url_for('admin_login'))

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully.')
    else:
        flash('User not found.')

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        # Redirect to the login page
        return redirect(url_for('admin_login'))

    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)


def get_current_user():
    # Using a session-based authentication system
    user_id = session.get('user_id')  # Retrieve the user ID from the session
    if user_id:
        # Querying of the User model
        user = User.query.get(user_id)  # Retrieve the user from the database based on the user ID
        return user

    # If user_id is not found in the session or the user doesn't exist, return None
    return None


@app.route('/history')
def history():
    url_activities = ShortUrls.query.all()
    return render_template('history.html', url_activities=url_activities)

def get_click_analytics(short_url_id):
    clicks = Click.query.filter_by(short_url_id=short_url_id).all()
    return clicks


def get_user_short_urls(user_id):
    user = User.query.get(user_id)
    if user:
        return ShortUrls.query.filter_by(user_id=user.id).all()
    else:
        return []   


@app.route('/dashboard')
def dashboard():
    # Retrieve the necessary data for the user dashboard
    user = get_current_user()  # function to get the current user
    short_urls = get_user_short_urls(user.id)  # function to get the user's short URLs

    # Fetch click analytics for each short URL
    click_analytics = {}
    for short_url in short_urls:
        click_analytics[short_url.id] = get_click_analytics(short_url.id)
        short_url.latest_click_date = get_latest_click_date(click_analytics[short_url.id])

    db.session.commit()

    # Render the dashboard template and pass the necessary data
    return render_template('dashboard.html', user=user, short_urls=short_urls, click_analytics=click_analytics)


def populate_clicks(short_url_id, ip_address, user_agent, referral_source):
    click = Click(short_url_id=short_url_id, ip_address=ip_address, user_agent=user_agent, referral_source=referral_source)
    db.session.add(click)
    db.session.commit()


# User registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        # Redirect to the homepage or another route
        return redirect(url_for('index'))

    else:
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

            # Check if this is the first user
            if User.query.count() == 1:
                # Assign the admin role to the first user
                new_user.is_admin = True
                db.session.commit()
    
            flash(f'Registration successful. Please log in.')
            return redirect(url_for('login'))
    
        return render_template('register.html')


# Create Admin Acount
@app.route('/create_admin', methods=['GET', 'POST'])
@login_required
def create_admin():
    if not current_user.is_admin:
        return 'Unauthorized'

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Check if admin account already exists
        admin = User.query.filter_by(email=email).first()
        if admin:
            return 'Admin account already exists'

        # Create a new admin user
        new_admin = User(email=email, password_hash=generate_password_hash(password), is_admin=True)
        db.session.add(new_admin)
        db.session.commit()

        return 'Admin account created successfully'

    return '''
        <form method="post">
            <label for="email">Email:</label>
            <input type="email" name="email" required><br>
            <label for="password">Password:</label>
            <input type="password" name="password" required><br>
            <input type="submit" value="Create Admin Account">
        </form>
    '''

    
# Route for User login
@app.route('/login', methods=['GET', 'POST'])
@cache.cached(timeout=60)
def login():
    if current_user.is_authenticated:
        # Redirect to the homepage or another route
        return redirect(url_for('shortenit'))
    
    else:  
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
            else:
                flash('Invalid email or password.')
                return redirect(url_for('login'))
        
        return render_template('login.html')


# Route for admin login
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated:
        # Redirect to the admin dashboard or another route
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Find the user by email address
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password) and user.is_admin:
            # Log in the admin user
            login_user(user)
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid email or password.')

    return render_template('admin_login.html')



# The redirection route and function
@app.route('/<short_id>')
@cache.cached(timeout=60)
@login_required
def redirect_url(short_id):
    link = ShortUrls.query.filter_by(short_id=short_id).first()

    if link:
        link.click_count += 1
        db.session.commit()

        # Populate the Clicks table with the click details
        click = Click(short_url_id=link.id, ip_address=request.remote_addr, user_agent=request.user_agent.string, referral_source=request.referrer)
        db.session.add(click)
        db.session.commit()

        return redirect(link.original_url)
    else:
        flash('Invalid URL')
        return redirect(url_for('shortenit'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))



if __name__ == '__main__':
    app.run(debug=True)
