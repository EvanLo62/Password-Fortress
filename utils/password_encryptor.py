from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
import hashlib
from werkzeug.security import generate_password_hash
from models import db, PasswordEntry
from utils.password_strength_checker import pwdRating

encryptor_bp = Blueprint('password_encryptor', __name__, url_prefix='/password-encryptor')

# 字元集 (74位元)
CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_+"

# 將16進制轉換為自定義字元集
def hex_to_charset(hex_str):
    D_value = int(hex_str, 16)  # 16轉10
    if D_value == 0:
        return CHARSET[0]
    result = []
    while D_value > 0:
        result.append(CHARSET[D_value % 74])
        D_value //= 74
    return ''.join(reversed(result))  # 反轉字串

@encryptor_bp.route('/', methods=['GET', 'POST'])
@login_required
def encryptor():
    encrypted_password = None
    strength_score = None
    strength_level = None
    issues = []

    if request.method == 'POST':
        hint = request.form['hint']
        original_pw = request.form['original_pw']
        length = int(request.form.get('length', 12))  # 預設密碼長度為12

        # 從當前用戶中獲取鹽值
        salt = current_user.salt

        # 組合數據並進行SHA256哈希
        data = (original_pw + hint + salt).encode('utf-8')
        hashed = hashlib.sha256(data).hexdigest()

        # 轉換為自定義字符集
        full_password = hex_to_charset(hashed)

        # 截取指定長度的密碼
        step = len(full_password) // length
        encrypted_password = ''.join(full_password[i * step] for i in range(length))

        # 計算密碼強度
        strength_score, _, issues, strength_level, _ = pwdRating(encrypted_password)

    return render_template(
        'password_encryptor/encryptor.html',
        encrypted_password=encrypted_password,
        strength_score=strength_score,
        strength_level=strength_level,
        issues=issues
    )

@encryptor_bp.route('/save', methods=['POST'])
@login_required
def save_encrypted():
    site_name = request.form['site_name']
    site_username = request.form['site_username']
    encrypted_password = request.form['encrypted_password']

    # 加密密碼並存儲
    hashed_pw = generate_password_hash(encrypted_password, method='pbkdf2:sha256')
    score, _, _, _, _ = pwdRating(encrypted_password)
    new_entry = PasswordEntry(
        user_id=current_user.id,
        site_name=site_name,
        site_username=site_username,
        site_password=hashed_pw,
        strength_score=score
    )
    db.session.add(new_entry)
    db.session.commit()

    flash('密碼已成功儲存！', 'success')
    return redirect(url_for('password_encryptor.encryptor'))
