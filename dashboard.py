# dashboard.py
from flask import Blueprint, render_template
from flask_login import login_required, current_user
from models import PasswordEntry
from collections import defaultdict

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')

@dashboard_bp.route('/')
@login_required
def dashboard():
    # 獲取當前用戶的密碼條目
    entries = PasswordEntry.query.filter_by(user_id=current_user.id).all()
    total_entries = len(entries)

    # 簡單計算平均強度(若無條目則給0)
    avg_strength = sum([e.strength_score for e in entries]) / total_entries if total_entries > 0 else 0
    
    # 計算弱密碼數量
    weak_passwords = [e for e in entries if e.strength_score < 50]

    # 計算重複密碼
    # password_map = defaultdict(list)
    # for entry in entries:
    #     password_map[entry.site_password].append(entry)
    
    # 篩選出重複使用的密碼（至少重複兩次）
    # duplicate_passwords = {password: entries for password, entries in password_map.items() if len(entries) > 1}

     # 調試日誌
    # print(f"Duplicate Passwords: {duplicate_passwords}")


    return render_template('dashboard/dashboard.html', 
                           total_entries=total_entries, 
                           avg_strength=round(avg_strength,2),
                           weak_passwords=weak_passwords,
                        #    duplicate_passwords=duplicate_passwords
                           )

# @dashboard_bp.route('/')
# @login_required
# def reminders():
#     # 簡單範例：提醒用戶更新長期未更新密碼或弱密碼
#     # 實務上你可以有一個 last_updated 欄位，這裡僅示範顯示弱密碼的提醒
#     entries = PasswordEntry.query.filter_by(user_id=current_user.id).all()
#     weak_passwords = [e for e in entries if e.strength_score < 50]
#     return render_template('dashboard/dashboard.html', weak_passwords=weak_passwords)

