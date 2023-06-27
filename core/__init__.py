from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String
from flask_migrate import Migrate
from decouple import config
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache


app = Flask(__name__)
app.config['CACHE_TYPE'] = 'simple'
cache = Cache(app)
limiter = Limiter(app, default_limits=["10/day"])
app.config.from_object(config("APP_SETTINGS"))

app.config['SESSION_COOKIE_NAME'] = 'LAZER_SESSION'
app.config['PERMANENT_SESSION_LIFETIME'] = 60 * 60  # Session expiration time in seconds

# Set the session permanent attribute to False
app.config['SESSION_PERMANENT'] = False


db = SQLAlchemy(app)

migrate = Migrate(app, db)

from core import routes
from core.models import ShortUrls
