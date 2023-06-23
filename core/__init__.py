from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String
from flask_migrate import Migrate
from decouple import config
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


app = Flask(__name__)
limiter = Limiter(app, default_limits=["1/day"])
# limiter = Limiter(app)
app.config.from_object(config("APP_SETTINGS"))

db = SQLAlchemy(app)

migrate = Migrate(app, db)

from core import routes
from core.models import ShortUrls
