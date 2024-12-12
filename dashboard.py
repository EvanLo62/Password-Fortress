# dashboard.py
from flask import Blueprint, render_template
from flask_login import login_required, current_user
from models import PasswordEntry

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')

@dashboard_bp.route('/')
@login_required
def dashboard():
    # 獲取當前用戶的密碼條目
    entries = PasswordEntry.query.filter_by(user_id=current_user.id).all()
    total_entries = len(entries)
    # 簡單計算平均強度(若無條目則給0)
    avg_strength = sum([e.strength_score for e in entries]) / total_entries if total_entries > 0 else 0
    
    return render_template('dashboard/dashboard.html', 
                           total_entries=total_entries, 
                           avg_strength=round(avg_strength,2))

@dashboard_bp.route('/reminders')
@login_required
def reminders():
    # 簡單範例：提醒用戶更新長期未更新密碼或弱密碼
    # 實務上你可以有一個 last_updated 欄位，這裡僅示範顯示弱密碼的提醒
    entries = PasswordEntry.query.filter_by(user_id=current_user.id).all()
    weak_passwords = [e for e in entries if e.strength_score < 50]
    return render_template('dashboard/reminders.html', weak_passwords=weak_passwords)
