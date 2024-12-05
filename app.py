from flask import Flask, render_template
from flask_login import LoginManager, login_required
from dotenv import load_dotenv
from auth import auth_bp  # 匯入藍圖
from models import db, User

import os

app = Flask(__name__)

# 載入環境變數
load_dotenv()

# 配置 Flask 應用
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todos.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 初始化擴展
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'

# 加載使用者
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 註冊藍圖
app.register_blueprint(auth_bp)

# 初始化資料庫
with app.app_context():
    db.create_all()

# 主頁路由
@app.route('/')
@login_required
def index():
    # TODO

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
