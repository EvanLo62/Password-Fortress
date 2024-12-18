from flask import Blueprint, render_template, request
from flask_login import login_required
from math import log2
import os


def load_common_passwords():
    # 動態計算檔案路徑
    base_dir = os.path.dirname(__file__)
    file_path = os.path.join(base_dir, "Common passwords.txt")
    
    common_passwords = set()
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                # 以逗號分割每行，去除空格或換行符
                passwords = [pwd.strip() for pwd in line.split(',') if pwd.strip()]
                common_passwords.update(passwords)  # 加入集合，去重複
    except FileNotFoundError:
        print(f"警告: 無法找到常用密碼檔案，路徑: {file_path}")
    return common_passwords


strength_checker_bp = Blueprint('password_strength_checker', __name__, url_prefix='/password-strength-checker')

# 密碼強度分級
LEVELS = [
    (0, 20, "非常弱", "您的密碼幾乎沒有安全性，建議完全重新設計！"),
    (21, 40, "弱", "密碼較為簡單，建議增加字符種類和長度。"),
    (41, 60, "中等", "密碼具備基本安全性，但仍有改進空間。"),
    (61, 80, "強", "密碼安全性良好，適合日常使用。"),
    (81, 100, "非常強", "您的密碼非常安全，可以放心使用！")
]
# 密碼強度評估核心邏輯
def pwdRating(pwd):
    # 預設值
    strength = "未知"
    advice = "密碼無法評估，請重新輸入一個更安全的密碼。"
    score = 0
    issues = []
    
    # 檢查密碼是否包含空格
    if " " in pwd:
        issues.append("密碼中不能包含空格！")
        return 0, 0, issues, "非常弱", "密碼中包含空格，請重新設計密碼。"

    # 去除前後空格
    pwd = pwd.strip()
    
    # 引入常用密碼
    COMMON_PASSWORDS = load_common_passwords()
    print("已載入的常用密碼數量:", len(COMMON_PASSWORDS))

    
    # 檢查是否為常用密碼（忽略大小寫）
    pwd_lower = pwd.lower()  # 將輸入密碼轉換為小寫

    for common_pwd in COMMON_PASSWORDS:
        if common_pwd and common_pwd in pwd_lower:  # 忽略大小寫比對
            issues.append(f"密碼包含常用密碼 '{common_pwd}'，安全性極低！")
            return 0, 0, issues, "非常弱", "您的密碼包含常用密碼，建議完全重新設計！"


    
    # 檢查密碼長度
    length = len(pwd)
    if length < 8:
        issues.append("重大缺失: 密碼長度過短！")
        return 0, 0, issues, "極弱", "您的密碼長度過短，請輸入更長的密碼!"
    elif length < 10:
        score += 20
    elif length < 13:
        score +=30
    elif length < 16:
        score += 40
    else:
        issues.append("提醒!密碼長度超過16，此程式主要測試長度為8~16的密碼")
        score += 40
    
    #檢查是否有多個交錯
    changes = type_different(pwd)
    if changes>4:
        score+=10
        
    # 檢查字符多樣性
    has_lower = any(c.islower() for c in pwd)
    has_upper = any(c.isupper() for c in pwd)
    has_digit = any(c.isdigit() for c in pwd)
    has_special = any(not c.isalnum() for c in pwd)

    type_count = sum([has_lower, has_upper, has_digit, has_special])
    diversity_score = type_count * 10
    if type_count >3:
        diversity_score+=10
    if type_count <= 2:
        issues.append("字符種類不足，建議包含大小寫字母、數字及特殊符號中的至少三種。")
    diversity_score+=score
    # 計算熵值
    charset_size = (26 if has_lower else 0) + (26 if has_upper else 0) + (10 if has_digit else 0) + (32 if has_special else 0)
    entropy = length * log2(charset_size) if charset_size > 0 else 0

    # 加權融合總分
    entropy_score = min(100, entropy / 60 * 100)  # 熵值轉換為百分比
    total_score = 0.3 * entropy_score + 0.7 * diversity_score

    #檢查是否連續三次出現相同類型
    previous_type = char_type(pwd[0])
    count = 1
    for i in range(1, len(pwd)):
        current_type = char_type(pwd[i])
        if current_type == previous_type:
            count += 1
        else:
            if count >= 3:
                deductions = count // 3
                score -= deductions*10
                issues.append("包含三個或更多連續相同類型字符")
            previous_type = current_type
            count = 1
            
    # 重複字符扣分
    char_counts = {}
    for char in pwd:
        char_counts[char] = char_counts.get(char, 0) + 1

    for char, count in char_counts.items():
        if count > 1:
            total_score -= (count - 1) * 5
            issues.append(f"字符 '{char}' 重複出現 {count} 次。")

    # 檢查是否只有字母或數字
    if pwd.isalpha():
        total_score -= 20
        issues.append("密碼僅包含字母，建議增加數字或符號。")
    if pwd.isdigit():
        total_score -= 20
        issues.append("密碼僅包含數字，建議增加字母或符號。")

    # 確保分數在合理範圍內
    total_score = max(0, min(100, total_score))
    # 密碼強度等級
    for level in LEVELS:
        if level[0] <= total_score <= level[1]:
            strength = level[2]
            advice = level[3]
            break
    return round(total_score), entropy, issues, strength, advice

#檢測不同字符交錯功能
def type_different(password):


    # 獲取密碼字符類型
    char_types = [char_type(c) for c in password]
    
    # 计算字符类型交错的次数
    changes = 0
    for i in range(len(char_types) - 1):
        if char_types[i] != char_types[i + 1]:
            changes += 1 

    return changes

#識別字符類型功能
def char_type(c):
        if c.islower():
            return 'lower'
        elif c.isupper():
            return 'upper'
        elif c.isdigit():
            return 'digit'
        elif not c.isalnum():
            return 'special'
        
# 提供密碼提示
def show_hint():
    return "使用包含大寫和小寫字母、數字、特殊符號的密碼。避免使用連續字符和常見密碼 (如 password, 123456)。"

@strength_checker_bp.route('/', methods=['GET', 'POST'])
@login_required
def checker():
    score = None
    strength = None
    advice = None
    issues = []
    hint_message = None

    if request.method == 'POST':
        if 'hint' in request.form:
            hint_message = show_hint()
        else:
            test_password = request.form['test_password']
            score, entropy, issues, strength, advice = pwdRating(test_password)

    return render_template(
        'password_strength_checker/checker.html',
        score=score,
        strength=strength,
        advice=advice,
        issues=issues,
        hint_message=hint_message
    )