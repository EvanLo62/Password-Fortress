from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from models import User, db

# 建立藍圖
auth_bp = Blueprint('auth', __name__)

# 註冊功能
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # 檢查密碼與確認密碼是否一致
        if password != request.form['confirm_password']:
            flash('密碼與確認密碼不一致，請再試一次。', 'error')
            return redirect(url_for('auth.register'))

        # 檢查使用者名稱是否存在
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('使用者名稱已存在，請選擇其他名稱。', 'error')
            return redirect(url_for('auth.register'))
        
        # 檢查信箱是否已存在
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('該信箱已被使用，請選擇其他信箱。', 'error')
            return redirect(url_for('auth.register'))

        # 創建新使用者
        new_user = User(username=username,email=email, password=generate_password_hash(password, method='pbkdf2:sha256'))
        db.session.add(new_user)
        db.session.commit()

        flash('註冊成功，請登入！', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html')

# 登入功能
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('帳號不存在或密碼錯誤! 請再試一次', 'error')
            return redirect(url_for('auth.login'))

    return render_template('login.html')

# 登出功能
@auth_bp.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
