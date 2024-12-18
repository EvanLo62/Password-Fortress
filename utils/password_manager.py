# password_manager.py

from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from models import db, PasswordEntry
from flask import session
from flask_mail import Message
from functools import wraps
from utils import password_strength_checker

password_manager_bp = Blueprint('password_manager', __name__, url_prefix='/password-manager')

def is_2FA_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print("is_2FA_verified:", session.get('is_2fa_verified'))  # 檢查 session 狀態
        if not session.get('is_2fa_verified'):
            flash('需先完成信箱兩步驟驗證！', 'error')
            return redirect(url_for('password_manager.view_passwords'))
        return f(*args, **kwargs)
    return decorated_function


@password_manager_bp.route('/add', methods=['GET', 'POST'])
@login_required 
def add_password():
    if request.method == 'POST':
        site_name = request.form['site_name']
        site_username = request.form['site_username']
        site_password = request.form['site_password']

        # 新增檢查邏輯
        existing_entry = PasswordEntry.query.filter_by(
            user_id=current_user.id,
            site_name=site_name,
            site_username=site_username
        ).first()

        if existing_entry:
            flash('此網站名稱與網站用戶名的組合已存在，請重新輸入！', 'error')
            return redirect(url_for('password_manager.add_password'))

        # 若不存在重複紀錄則繼續原本邏輯
        strength_score = calculate_strength(site_password)
        hashed_pw = PasswordEntry.set_encrypted_password(site_password)

        new_entry = PasswordEntry(
            user_id=current_user.id,
            site_name=site_name,
            site_username=site_username,
            site_password=hashed_pw,
            strength_score=strength_score
        )
        db.session.add(new_entry)
        db.session.commit()

        # flash('密碼已成功新增！', 'success')
        return redirect(url_for('password_manager.view_passwords'))

    # GET請求時依然保持原有流程
    return render_template('password_manager/add_password.html')


@password_manager_bp.route('/view')
@login_required
def view_passwords():
    entries = PasswordEntry.query.filter_by(user_id=current_user.id).all()
    for entry in entries:
        entry.site_password = entry.get_plaintext_password()  # 解密密碼
    return render_template('password_manager/view_passwords.html', entries=entries)

@password_manager_bp.route('/edit/<int:entry_id>', methods=['GET', 'POST'])
@login_required
@is_2FA_required
def edit_password(entry_id):
    entry = PasswordEntry.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        flash('您無權限編輯此密碼條目。', 'error')
        return redirect(url_for('password_manager.view_passwords'))

    if request.method == 'POST':
        entry.site_name = request.form['site_name']
        entry.site_username = request.form['site_username']
        new_password = request.form['site_password']
        entry.site_password = PasswordEntry.set_encrypted_password(new_password)
        entry.strength_score = calculate_strength(new_password)
        db.session.commit()
        flash('密碼已成功更新！', 'success')
        return redirect(url_for('password_manager.view_passwords'))

    return render_template('password_manager/edit_password.html', entry=entry)

@password_manager_bp.route('/delete/<int:entry_id>', methods=['POST'])
@login_required
@is_2FA_required
def delete_password(entry_id):
    entry = PasswordEntry.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        flash('您無權限刪除此密碼條目。', 'error')
        return redirect(url_for('password_manager.view_passwords'))

    db.session.delete(entry)
    db.session.commit()
    flash('密碼已刪除。', 'success')
    return redirect(url_for('password_manager.view_passwords'))

@password_manager_bp.route('/copy/<int:entry_id>', methods=['POST'])
@login_required
def copy_password(entry_id):
    try:
        if not current_user.is_authenticated:
            return {'status': 'error', 'message': '未登入，請先登入！'}, 401
        if not session.get('is_2fa_verified'):
            return {'status': 'error', 'message': '需先完成信箱兩步驟驗證！'}, 403
        entry = PasswordEntry.query.get_or_404(entry_id)
        return {'status': 'success', 'password': entry.get_plaintext_password()}, 200
    except Exception as e:
        # 捕獲所有其他錯誤，並返回 JSON
        return {'status': 'error', 'message': f'伺服器錯誤：{str(e)}'}, 500



@password_manager_bp.route('/verify-2fa-page', methods=['GET', 'POST'])
@login_required
def verify_2fa_page():
    if session.get( 'is_2fa_verified' ) == True:
        flash('信箱已驗證成功！', 'success')
        return redirect(url_for('password_manager.view_passwords'))

    if request.method == 'POST':
        code = request.form.get('code')
        stored_code = session.get('2fa_code')
        expiry_time = session.get('2fa_code_expiry')

        # 驗證碼過期或不存在
        if not stored_code or datetime.now() > datetime.fromisoformat(expiry_time):
            flash('驗證碼已過期，請重新發送。', 'error')
            return redirect(url_for('password_manager.verify_2fa_page'))

        # 驗證碼正確
        if code == stored_code:
            session.permanent = True  # 讓 session 遵循自動過期時間設置
            session['is_2fa_verified'] = True  # 設定二因子驗證狀態
            flash('信箱兩步驟驗證成功！', 'success')
            return redirect(url_for('password_manager.view_passwords'))

        # 驗證碼錯誤
        flash('驗證碼不正確！', 'error')

    return render_template('verify_2fa_page.html')


@password_manager_bp.route('/send-2fa-code', methods=['POST'])
@login_required
def send_2fa_code():
    from app import MAIL_USERNAME, mail
    import random
    import string
    from datetime import datetime, timedelta

    # 生成隨機6位驗證碼
    code = ''.join(random.choices(string.digits, k=6))
    session['2fa_code'] = code
    session['2fa_code_expiry'] = (datetime.now() + timedelta(minutes=3)).isoformat()  # 設置有效期限

    # 發送郵件
    msg = Message(
        subject="Password Fortress 兩步驟驗證",
        sender=MAIL_USERNAME,  # 發送信箱
        recipients=[current_user.email]  # 用戶的信箱
    )
    msg.body = f"您的信箱驗證碼：{code}\n\n此驗證碼有效期限為 3 分鐘。"
    try:
        mail.send(msg)
        return {'status': 'success', 'message': '驗證碼已發送至您的信箱。'}, 200
    except Exception as e:
        return {'status': 'failure', 'message': f'郵件發送失敗：{e}'}, 500


def calculate_strength(password):
    score, entropy, issues, strength, advice = password_strength_checker.pwdRating(password)
    return score
