# password_encryptor.py
from flask import Blueprint, render_template, request
from flask_login import login_required
import hashlib

encryptor_bp = Blueprint('password_encryptor', __name__, url_prefix='/password-encryptor')

@encryptor_bp.route('/', methods=['GET', 'POST'])
@login_required
def encryptor():
    encrypted_password = None
    if request.method == 'POST':
        hint = request.form['hint']
        original_pw = request.form['original_pw']
        
        # 簡單範例：將 hint + original_pw 用 SHA256 生成一組雜湊字串，截取一段作為新密碼
        combined = (hint + original_pw).encode('utf-8')
        hashed = hashlib.sha256(combined).hexdigest()
        # 截取前16字元當作「加密後」密碼
        encrypted_password = hashed[:16]
    return render_template('password_encryptor/encryptor.html', encrypted_password=encrypted_password)
