
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
import auth

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', '')
db = SQLAlchemy(app)

@app.route('/register', methods=['POST'])
def register():
    return auth.register_user(request)

@app.route('/auth', methods=['POST'])
def authenticate():
    return auth.authenticate_user(request)

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
