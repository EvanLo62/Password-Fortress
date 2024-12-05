from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

# 初始化 SQLAlchemy
db = SQLAlchemy()

# 使用者模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    """
    這裡要在定義密碼儲存的格式
    或額外的類別
    ...
    """