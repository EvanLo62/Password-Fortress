from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os

app = Flask(__name__)

load_dotenv()  # 加載 .env 檔案中的密鑰
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todos.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 定義資料庫模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    """
     這裡要在定義密碼儲存的格式
     或額外的類別
     ...
    """ 
   

# 初始化資料庫
with app.app_context():
    db.create_all()

# 加載使用者
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 註冊功能 - 存儲密碼的時候加密
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # 檢查密碼與確認密碼是否相同
        if password != request.form['confirm_password']:
            flash('密碼與確認密碼不一致，請再試一次。', 'error')
            return redirect(url_for('register'))


        # 檢查使用者名稱是否已存在
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('使用者名稱已存在，請選擇其他名稱。', 'error')
            return redirect(url_for('register'))

        # 如果使用者名稱不存在，則創建新使用者
        new_user = User(username=username, password=generate_password_hash(password, method='pbkdf2:sha256'))
        db.session.add(new_user)
        db.session.commit()

        flash('註冊成功，請登入！', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# 登入功能 - 檢查帳號和密碼
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('帳號不存在或密碼錯誤! 請再試一次', 'error')  # 錯誤訊息，類型為 'error'
            return redirect(url_for('login'))

    return render_template('login.html')

# 登出功能
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# 主頁
@app.route('/')
@login_required
def index():
    # TODO

    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)
