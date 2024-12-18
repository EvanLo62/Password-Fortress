# password_encryptor.py
from flask import Blueprint, render_template, request
from flask_login import login_required, current_user
import hashlib

encryptor_bp = Blueprint('password_encryptor', __name__, url_prefix='/password-encryptor')

@encryptor_bp.route('/', methods=['GET', 'POST'])
@login_required
def encryptor():
    encrypted_password = None
    if request.method == 'POST':
        hint = request.form['hint']
        original_pw = request.form['original_pw']
        length = int(request.form.get('length', 12))  # 默認密碼長度為12

        # 從當前用戶中獲取專屬鹽值
        SALT = current_user.salt
        
        # 組合數據並哈希
        data = (original_pw + hint + SALT).encode('utf-8')
        hashed = hashlib.sha256(data).hexdigest()
        
        # 使用 hex_to_charset 函數轉換
        full_password = hex_to_charset(hashed)
        
        # 截取符合用戶需求的密碼長度
        step = len(full_password) // length
        encrypted_password = ''.join(full_password[i * step] for i in range(length))
        
    return render_template('password_encryptor/encryptor.html', encrypted_password=encrypted_password)


#將16進制轉為74位元
CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_+"

def hex_to_charset(hex_str):
    #16轉10
    D_value = int(hex_str,16)
    
    #10轉74
    if D_value==0:
        return CHARSET[0]
    result=[]
    while D_value > 0:
        result.append(CHARSET[D_value % 74] )
        D_value//=74
        
    #反轉字串(原本是從低有效位計算)
    return ''.join(reversed(result))