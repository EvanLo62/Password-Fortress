# password_generator.py
import string, random
from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from models import db, PasswordEntry
from werkzeug.security import generate_password_hash
from utils.password_manager import calculate_strength

generator_bp = Blueprint('password_generator', __name__, url_prefix='/password-generator')

@generator_bp.route('/', methods=['GET', 'POST'])
@login_required
def generator():
    generated_password = None
    if request.method == 'POST':
        length = int(request.form.get('length', 12))
        include_digits = 'digits' in request.form
        include_special = 'special' in request.form
        include_upper = 'upper' in request.form
        include_lower = 'lower' in request.form
        
        chars = ''
        if include_digits:
            chars += string.digits
        if include_special:
            chars += '!@#$%^&*()_+'
        if include_upper:
            chars += string.ascii_uppercase
        if include_lower:
            chars += string.ascii_lowercase
        
        if not chars:
            chars = string.ascii_letters + string.digits
        
        generated_password = ''.join(random.choice(chars) for _ in range(length))
    
    return render_template('password_generator/generator.html', generated_password=generated_password)

@generator_bp.route('/save', methods=['POST'])
@login_required
def save_generated():
    site_name = request.form['site_name']
    site_username = request.form['site_username']
    gen_password = request.form['generated_password']

    hashed_pw = generate_password_hash(gen_password, method='pbkdf2:sha256')
    score = calculate_strength(gen_password)
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
    return redirect(url_for('password_manager.view_passwords'))
