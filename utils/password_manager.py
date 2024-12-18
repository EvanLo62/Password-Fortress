# password_manager.py

from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from models import db, PasswordEntry
from flask import session

password_manager_bp = Blueprint('password_manager', __name__, url_prefix='/password-manager')

# password_manager.py (僅示範需要修改/新增部分的邏輯)

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
def edit_password(entry_id):
    entry = PasswordEntry.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        flash('您無權限編輯此密碼條目。', 'error')
        return redirect(url_for('password_manager.view_passwords'))

    if request.method == 'POST':
        entry.site_name = request.form['site_name']
        entry.site_username = request.form['site_username']
        new_password = request.form['site_password']
        entry.site_password = PasswordEntry.set_encrypted_password(new_password, method='pbkdf2:sha256')
        entry.strength_score = calculate_strength(new_password)
        db.session.commit()
        flash('密碼已成功更新！', 'success')
        return redirect(url_for('password_manager.view_passwords'))

    return render_template('password_manager/edit_password.html', entry=entry)

@password_manager_bp.route('/delete/<int:entry_id>', methods=['POST'])
@login_required
def delete_password(entry_id):
    entry = PasswordEntry.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        flash('您無權限刪除此密碼條目。', 'error')
        return redirect(url_for('password_manager.view_passwords'))

    db.session.delete(entry)
    db.session.commit()
    flash('密碼已刪除。', 'success')
    return redirect(url_for('password_manager.view_passwords'))

# @password_manager_bp.route('/2fa', methods=['GET', 'POST'])
# @login_required
# def two_factor_auth():
#     if request.method == 'POST':
#         # 簡單模擬雙因子驗證，實際應集成 OTP (如 Google Authenticator)
#         otp_code = request.form.get('otp_code')
#         if otp_code == '123456':  # 示例：預設驗證碼
#             session['2fa_verified'] = True
#             flash('雙因子驗證成功！', 'success')
#             return redirect(url_for('password_manager.view_passwords'))
#         else:
#             flash('驗證失敗，請再試一次。', 'error')

#     return render_template('password_manager/2fa.html')

def calculate_strength(password):
    # 簡單的密碼強度計算範例，可自行強化
    score = 0
    if len(password) >= 8:
        score += 20
    if any(c.isdigit() for c in password):
        score += 20
    if any(c.isupper() for c in password):
        score += 20
    if any(c.islower() for c in password):
        score += 20
    if any(c in "!@#$%^&*()_+" for c in password):
        score += 20
    return score
