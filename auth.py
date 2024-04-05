
from flask import request, jsonify, abort
from models import User, AuthLog, db
from uuid import uuid4
from argon2 import PasswordHasher
from datetime import datetime
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

ph = PasswordHasher()

def encrypt_aes(data, key):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data.encode(), None)
    return base64.urlsafe_b64encode(nonce + ct)

def decrypt_aes(encrypted_data, key):
    encrypted_data = base64.urlsafe_b64decode(encrypted_data)
    nonce = encrypted_data[:12]
    ct = encrypted_data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None).decode()

def register_user():
    data = request.get_json()
    username = data['username']
    email = data['email']
    password = str(uuid4())
    hashed_password = ph.hash(password)
    new_user = User(username=username, email=email, password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'password': password}), 201

def authenticate_user():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and ph.verify(user.password_hash, data['password']):
        log_auth_request(user_id=user.id)
        return jsonify({'message': 'Authentication successful'}), 200
    else:
        log_auth_request()
        abort(401)

def log_auth_request(user_id=None):
    auth_log = AuthLog(request_ip=request.remote_addr, user_id=user_id)
    db.session.add(auth_log)
    db.session.commit()
