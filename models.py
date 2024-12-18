# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import os

load_dotenv()

#加載加密密鑰
encryption_key = os.getenv('ENCRYPTION_KEY')
if encryption_key is None:
    raise ValueError("ENCRYPTION_KEY未定義！")

try:
    cipher = Fernet(encryption_key.encode())
except ValueError:
    raise ValueError("提供的 ENCRYPTION_KEY 無效！")

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)  # 新增 email 欄位
    salt = db.Column(db.String(32), nullable=False)  # 專屬鹽值

# 新增的密碼儲存 Model
class PasswordEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    site_name = db.Column(db.String(150), nullable=False)
    site_username = db.Column(db.String(150), nullable=False)
    site_password = db.Column(db.String(300), nullable=False)  # 加密後存儲
    strength_score = db.Column(db.Integer, default=0)  # 預設強度分數為0
    user = db.relationship('User', backref='password_entries', lazy=True)

    # 新增方法解密密碼
    def get_plaintext_password(self):
        return cipher.decrypt(self.site_password.encode()).decode()

    # 新增方法加密密碼
    @staticmethod
    def set_encrypted_password(password):
        return cipher.encrypt(password.encode()).decode()
