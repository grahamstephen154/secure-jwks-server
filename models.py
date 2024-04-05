
from app import db
from datetime import datetime

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    date_registered = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

class AuthLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_ip = db.Column(db.String(15), nullable=False)
    request_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
