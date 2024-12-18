import string, random
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from models import db, PasswordEntry
from werkzeug.security import generate_password_hash
from utils.password_strength_checker import pwdRating

generator_bp = Blueprint('password_generator', __name__, url_prefix='/password-generator')

# 密碼生成邏輯（支持長度和數量）
def generate_passwords(length=12, count=1):
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%^&*()-_+"
    all_types = [lower, upper, digits, special]
    
    passwords = []
    for _ in range(count):
        while True:
            # 計算各種類字符數量
            num_each_type = length // 4
            remaining = length % 4

            # 生成密碼
            password_chars = (
                random.choices(lower, k=num_each_type) +
                random.choices(upper, k=num_each_type) +
                random.choices(digits, k=num_each_type) +
                random.choices(special, k=num_each_type)
            )
            for i in range(remaining):
                password_chars.append(random.choice(all_types[i]))
            random.shuffle(password_chars)
            pwd = ''.join(password_chars)

            # 驗證密碼強度
            score, _, _, strength, _ = pwdRating(pwd)
            if score >= 80:  # 確保生成的是高強度密碼
                passwords.append((pwd, score, strength))
                break
    return passwords

@generator_bp.route('/', methods=['GET', 'POST'])
@login_required
def generator():
    passwords = []
    if request.method == 'POST':
        try:
            length = int(request.form.get('length', 12))
            count = int(request.form.get('count', 1))
            if not (8 <= length <= 16):
                flash("密碼長度必須在 8 到 16 之間", 'danger')
            elif count <= 0:
                flash("密碼數量必須大於 0", 'danger')
            else:
                # 生成密碼
                passwords = generate_passwords(length=length, count=count)
        except ValueError:
            flash("請輸入有效的數字", 'danger')

    return render_template(
        'password_generator/generator.html',
        passwords=passwords
    )

@generator_bp.route('/save', methods=['POST'])
@login_required
def save_generated():
    site_name = request.form['site_name']
    site_username = request.form['site_username']
    gen_password = request.form['generated_password']

    hashed_pw = generate_password_hash(gen_password, method='pbkdf2:sha256')
    score, _, _, _, _ = pwdRating(gen_password)
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
    return redirect(url_for('password_generator.generator'))
