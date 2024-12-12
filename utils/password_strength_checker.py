# password_strength_checker.py
from flask import Blueprint, render_template, request
from flask_login import login_required
from utils.password_manager import calculate_strength

strength_checker_bp = Blueprint('password_strength_checker', __name__, url_prefix='/password-strength-checker')

@strength_checker_bp.route('/', methods=['GET', 'POST'])
@login_required
def checker():
    score = None
    advice = None
    if request.method == 'POST':
        test_password = request.form['test_password']
        score = calculate_strength(test_password)
        advice = get_advice(score)
    return render_template('password_strength_checker/checker.html', score=score, advice=advice)

def get_advice(score):
    if score < 40:
        return "密碼過於簡單，請加入更多字元、大小寫、數字與符號。"
    elif score < 80:
        return "密碼還不錯，但可以再增加密碼長度或加入更多特別字元。"
    else:
        return "密碼很強，維持下去！"
