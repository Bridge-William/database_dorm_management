"""
学生公寓交费管理系统 - Flask应用
作者: 翁联桥
日期: 2025-12-29
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import hashlib
import os
import logging
from logging.handlers import RotatingFileHandler
import traceback
import io
import time
import psutil
import platform
import shutil
import re
from pathlib import Path
from backup import DatabaseBackup
from auto_backup import AutoBackupScheduler
import sys

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'

# ==================== 初始化配置 ====================

# MySQL配置
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'MySQL'
app.config['MYSQL_DB'] = 'dorm_management'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

# ==================== 日志配置 ====================

# 创建logs目录
if not os.path.exists('logs'):
    os.makedirs('logs')

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# 创建文件处理器，每个日志文件最大10MB，保留5个备份
file_handler = RotatingFileHandler(
    'logs/dorm_management.log',
    maxBytes=10*1024*1024,
    backupCount=5,
    encoding='utf-8'
)
file_handler.setLevel(logging.INFO)

# 创建控制台处理器
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# 设置日志格式
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='Y-%m-%d %H:%M:%S'
)
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# 添加处理器到日志器
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# 日志装饰器
def log_operation(operation_type):
    """操作日志装饰器"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                user_id = session.get('user_id', '未登录')
                username = session.get('username', '未登录')
                realname = session.get('realname', '未登录')

                logger.info(f"开始执行 {operation_type} - 用户ID: {user_id}, 姓名: {realname}, 函数: {f.__name__}")

                # 执行函数
                result = f(*args, **kwargs)

                logger.info(f"成功执行 {operation_type} - 用户ID: {user_id}, 姓名: {realname}")
                return result

            except Exception as e:
                user_id = session.get('user_id', '未登录')
                logger.error(f"执行 {operation_type} 失败 - 用户ID: {user_id}, 错误: {str(e)}")
                logger.error(traceback.format_exc())
                raise

        return decorated_function
    return decorator

# ==================== 创建必要的目录 ====================
required_dirs = ['logs', 'backups', 'temp']
for dir_name in required_dirs:
    dir_path = Path(dir_name)
    if not dir_path.exists():
        dir_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"创建目录: {dir_name}")
    else:
        logger.debug(f"目录已存在: {dir_name}")

# ==================== 自动备份调度器 ====================
auto_backup_scheduler = AutoBackupScheduler(app.config, app)

def init_auto_backup():
    """初始化自动备份"""
    try:
        if app.config.get('AUTO_BACKUP_ENABLED', True):
            success = auto_backup_scheduler.start()
            if success:
                logger.info("自动备份调度器初始化成功")
            else:
                logger.warning("自动备份调度器初始化失败")
        else:
            logger.info("自动备份功能已禁用")
    except Exception as e:
        logger.error(f"初始化自动备份失败: {str(e)}")

# 应用启动时间
app_start_time = datetime.now()

# ==================== 辅助函数 ====================
def hash_password(password):
    """密码加密"""
    salt = 'salt'
    return f"sha256${salt}${hashlib.sha256(password.encode()).hexdigest()}"

def verify_password(stored_password, provided_password):
    """验证密码"""
    if stored_password.startswith('sha256$'):
        parts = stored_password.split('$')
        salt = parts[1]
        stored_hash = parts[2]
        new_hash = hashlib.sha256(provided_password.encode()).hexdigest()
        return stored_hash == new_hash
    return False

def validate_user_id(user_id):
    """验证用户ID格式：四位年份+两位部门+四位顺序号"""
    if not user_id or len(user_id) != 10:
        return False
    if not user_id.isdigit():
        return False
    year = user_id[:4]
    if int(year) < 2000 or int(year) > 2050:
        return False
    return True

def login_required(f):
    """登录验证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """管理员权限验证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录', 'warning')
            return redirect(url_for('login'))
        if session.get('permission') != '管理员':
            flash('需要管理员权限', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== 上下文处理器 ====================
@app.context_processor
def inject_pending_requests_count():
    """在所有模板中注入待审批的注册申请数量"""
    if 'user_id' in session and session.get('permission') == '管理员':
        try:
            cur = mysql.connection.cursor()
            cur.execute("SELECT COUNT(*) as count FROM user_requests WHERE status = '待审批'")
            pending_count = cur.fetchone()['count']
            cur.close()
            return dict(pending_requests_count=pending_count)
        except Exception as e:
            logger.error(f"获取待审批申请数量失败: {str(e)}")
            return dict(pending_requests_count=0)
    return dict(pending_requests_count=0)

# ==================== 认证路由 ====================
@app.route('/')
def index():
    """首页"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """登录 - 使用用户ID（学校身份编号）登录"""
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        password = request.form.get('password')

        logger.info(f"登录尝试 - 用户ID: {user_id}")

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
        user = cur.fetchone()
        cur.close()

        if user and verify_password(user['password'], password):
            session['user_id'] = user['user_id']
            session['realname'] = user['realname']
            session['permission'] = user['permission']
            session['job_title'] = user['job_title']

            logger.info(f"登录成功 - 用户ID: {user_id}, 姓名: {user['realname']}, 职务: {user['job_title']}, 权限: {user['permission']}")
            flash(f'欢迎回来，{user["realname"]}！', 'success')
            return redirect(url_for('dashboard'))
        else:
            logger.warning(f"登录失败 - 用户ID: {user_id} 用户名或密码错误")
            flash('用户ID或密码错误', 'danger')

    return render_template('login.html')

@app.route('/logout')
@log_operation("用户登出")
def logout():
    """退出登录"""
    user_id = session.get('user_id')
    realname = session.get('realname')

    session.clear()

    logger.info(f"用户登出 - 用户ID: {user_id}, 姓名: {realname}")
    flash('已退出登录', 'info')
    return redirect(url_for('login'))

# ==================== 用户注册功能 ====================
@app.route('/register', methods=['GET', 'POST'])
def register():
    """用户注册页面"""
    if request.method == 'POST':
        try:
            user_id = request.form.get('user_id')
            password = request.form.get('password')
            password_confirm = request.form.get('password_confirm')
            realname = request.form.get('realname')
            job_title = request.form.get('job_title', '教师')
            permission = request.form.get('permission', '教师')
            email = request.form.get('email', '')
            phone = request.form.get('phone', '')
            remark = request.form.get('remark', '')

            logger.info(f"注册申请 - 用户ID: {user_id}, 真实姓名: {realname}, 职务: {job_title}, 权限申请: {permission}")

            # 验证输入
            if not user_id or not password or not realname or not email or not phone:
                flash('请填写所有必填项', 'danger')
                return redirect(url_for('register'))

            # 验证用户ID格式
            if not validate_user_id(user_id):
                flash('用户ID格式不正确，应为10位数字（四位年份+两位部门+四位顺序号）', 'danger')
                return redirect(url_for('register'))

            if password != password_confirm:
                flash('两次输入的密码不一致', 'danger')
                return redirect(url_for('register'))

            if len(password) < 6:
                flash('密码长度至少6位', 'danger')
                return redirect(url_for('register'))

            cur = mysql.connection.cursor()

            # 检查是否已有相同用户ID的待审批申请
            cur.execute("SELECT user_id FROM user_requests WHERE user_id = %s AND status = '待审批'", (user_id,))
            if cur.fetchone():
                logger.warning(f"重复注册申请 - 用户ID: {user_id}")
                flash('您已提交过注册申请，请等待审批结果', 'warning')
                cur.close()
                return redirect(url_for('register'))

            # 检查用户ID是否已存在
            cur.execute("SELECT user_id FROM users WHERE user_id = %s", (user_id,))
            if cur.fetchone():
                flash('该用户ID已存在，请使用其他ID', 'danger')
                cur.close()
                return redirect(url_for('register'))

            # 加密密码
            hashed_password = hash_password(password)

            # 插入注册申请
            cur.execute("""
                INSERT INTO user_requests (user_id, password, realname, permission, job_title, email, phone, remark, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, '待审批')
            """, (user_id, hashed_password, realname, permission, job_title, email, phone, remark))

            mysql.connection.commit()
            cur.close()

            logger.info(f"注册申请提交成功 - 用户ID: {user_id}, 真实姓名: {realname}")
            flash('注册申请已提交，请等待管理员审批。审批通过后您将收到通知。', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            logger.error(f"注册申请失败 - 用户ID: {user_id}, 错误: {str(e)}")
            logger.error(traceback.format_exc())
            flash(f'注册失败: {str(e)}', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

# ==================== 忘记密码功能 ====================
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """忘记密码 - 重置密码为默认密码"""
    if request.method == 'POST':
        try:
            user_id = request.form.get('user_id')

            if not user_id:
                flash('请输入用户ID', 'danger')
                return redirect(url_for('forgot_password'))

            logger.info(f"密码重置请求 - 用户ID: {user_id}")

            # 验证用户ID格式（10位数字）
            if not re.match(r'^\d{10}$', user_id):
                logger.warning(f"密码重置失败 - 用户ID格式不正确: {user_id}")
                flash('用户ID格式不正确，应为10位数字（四位年份+两位部门+四位顺序号）', 'danger')
                return redirect(url_for('forgot_password'))

            cur = mysql.connection.cursor()

            # 验证用户ID是否存在
            cur.execute("SELECT user_id, realname FROM users WHERE user_id = %s", (user_id,))
            user = cur.fetchone()

            if not user:
                logger.warning(f"密码重置失败 - 用户ID不存在: {user_id}")
                flash('用户ID不存在', 'danger')
                cur.close()
                return redirect(url_for('forgot_password'))

            # 重置密码为默认密码 123456
            default_password = '123456'
            hashed_password = hash_password(default_password)

            # 更新密码
            cur.execute("""
                UPDATE users 
                SET password = %s, updated_at = CURRENT_TIMESTAMP
                WHERE user_id = %s
            """, (hashed_password, user_id))

            mysql.connection.commit()
            cur.close()

            logger.info(f"密码重置成功 - 用户ID: {user_id}, 姓名: {user['realname']}")
            flash(f'密码已重置为默认密码: 123456，请尽快登录修改密码', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            logger.error(f"密码重置失败 - 用户ID: {user_id}, 错误: {str(e)}")
            flash(f'重置密码失败: {str(e)}', 'danger')
            return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')

# ==================== 仪表板 ====================
@app.route('/dashboard')
@login_required
def dashboard():
    """仪表板"""
    logger.info(f"访问仪表板 - 用户: {session['user_id']}")
    cur = mysql.connection.cursor()

    # 统计数据
    cur.execute("SELECT COUNT(*) as count FROM students")
    student_count = cur.fetchone()['count']

    cur.execute("SELECT COUNT(*) as count FROM buildings")
    building_count = cur.fetchone()['count']

    cur.execute("SELECT COUNT(*) as count FROM rooms")
    room_count = cur.fetchone()['count']

    cur.execute("SELECT COUNT(*) as count FROM payments WHERE MONTH(payment_date) = MONTH(CURDATE())")
    month_payment_count = cur.fetchone()['count']

    cur.execute("SELECT SUM(amount) as total FROM payments WHERE MONTH(payment_date) = MONTH(CURDATE())")
    month_total = cur.fetchone()['total'] or 0

    # 最近交费记录
    cur.execute("""
        SELECT p.*, s.name as student_name 
        FROM payments p 
        JOIN students s ON p.student_id = s.student_id 
        ORDER BY p.payment_date DESC, p.payment_id DESC 
        LIMIT 10
    """)
    recent_payments = cur.fetchall()

    # 月度统计
    cur.execute("""
        SELECT 
            DATE_FORMAT(payment_date, '%Y-%m') as month,
            COUNT(*) as count,
            SUM(amount) as total
        FROM payments
        WHERE payment_date >= DATE_SUB(CURDATE(), INTERVAL 6 MONTH)
        GROUP BY DATE_FORMAT(payment_date, '%Y-%m')
        ORDER BY month DESC
    """)
    monthly_stats = cur.fetchall()

    cur.close()

    return render_template('dashboard.html',
                           student_count=student_count,
                           building_count=building_count,
                           room_count=room_count,
                           month_payment_count=month_payment_count,
                           month_total=month_total,
                           recent_payments=recent_payments,
                           monthly_stats=monthly_stats)

# ==================== 我的信息管理 ====================
@app.route('/my_info')
@login_required
def my_info():
    """查看和修改个人信息"""
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE user_id = %s", (session['user_id'],))
    user = cur.fetchone()
    cur.close()

    if not user:
        flash('用户信息不存在', 'danger')
        return redirect(url_for('dashboard'))

    return render_template('my_info.html', user=user)

@app.route('/my_info/update', methods=['POST'])
@login_required
@log_operation("更新个人信息")
def update_my_info():
    """更新个人信息"""
    try:
        # 获取表单数据
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        password_confirm = request.form.get('password_confirm')

        cur = mysql.connection.cursor()

        # 验证当前密码
        cur.execute("SELECT password FROM users WHERE user_id = %s", (session['user_id'],))
        user = cur.fetchone()

        if not user:
            flash('用户不存在', 'danger')
            cur.close()
            return redirect(url_for('my_info'))

        # 验证当前密码
        if session.get('permission') == '教师':
            if not verify_password(user['password'], current_password):
                flash('当前密码错误', 'danger')
                cur.close()
                return redirect(url_for('my_info'))

        # 如果提供了新密码，则更新密码
        if new_password:
            if len(new_password) < 6:
                flash('新密码长度至少6位', 'danger')
                cur.close()
                return redirect(url_for('my_info'))

            if new_password != password_confirm:
                flash('两次输入的新密码不一致', 'danger')
                cur.close()
                return redirect(url_for('my_info'))

            # 加密新密码
            hashed_password = hash_password(new_password)

            # 更新密码
            cur.execute("""
                UPDATE users 
                SET password = %s, updated_at = CURRENT_TIMESTAMP
                WHERE user_id = %s
            """, (hashed_password, session['user_id']))

        mysql.connection.commit()
        cur.close()

        logger.info(f"密码更新成功 - 用户ID: {session['user_id']}")
        flash('个人信息更新成功', 'success')

    except Exception as e:
        logger.error(f"密码更新失败 - 用户ID: {session['user_id']}, 错误: {str(e)}")
        flash(f'更新失败: {str(e)}', 'danger')

    return redirect(url_for('my_info'))

# ==================== 学生管理 ====================
@app.route('/students')
@login_required
def students():
    """学生列表 - 多条件组合查询"""
    logger.info(f"查看学生列表 - 用户: {session['user_id']}")
    page = request.args.get('page', 1, type=int)
    student_id = request.args.get('student_id', '')
    name = request.args.get('name', '')
    gender = request.args.get('gender', '')
    ethnicity = request.args.get('ethnicity', '')
    major = request.args.get('major', '')
    class_name = request.args.get('class', '')
    phone = request.args.get('phone', '')
    building_id = request.args.get('building_id', '')
    room_id = request.args.get('room_id', '')
    per_page = 15

    cur = mysql.connection.cursor()

    # 构建查询条件
    query = """
        SELECT s.*, 
               (SELECT COUNT(*) FROM payments WHERE student_id = s.student_id) as payment_count,
               (SELECT SUM(amount) FROM payments WHERE student_id = s.student_id) as total_paid
        FROM students s
        WHERE 1=1
    """
    params = []

    if student_id:
        query += " AND s.student_id LIKE %s"
        params.append(f'%{student_id}%')

    if name:
        query += " AND s.name LIKE %s"
        params.append(f'%{name}%')

    if gender:
        query += " AND s.gender = %s"
        params.append(gender)

    if ethnicity:
        query += " AND s.ethnicity LIKE %s"
        params.append(f'%{ethnicity}%')

    if major:
        query += " AND s.major LIKE %s"
        params.append(f'%{major}%')

    if class_name:
        query += " AND s.class LIKE %s"
        params.append(f'%{class_name}%')

    if phone:
        query += " AND s.phone LIKE %s"
        params.append(f'%{phone}%')

    if building_id:
        query += " AND s.building_id LIKE %s"
        params.append(f'%{building_id}%')

    if room_id:
        query += " AND s.room_id LIKE %s"
        params.append(f'%{room_id}%')

    query += " ORDER BY s.student_id"

    cur.execute(query, params)
    all_students = cur.fetchall()
    total = len(all_students)

    # 分页
    start = (page - 1) * per_page
    end = start + per_page
    students_page = all_students[start:end]

    total_pages = (total + per_page - 1) // per_page

    # 获取楼栋和房间
    cur.execute("SELECT building_id FROM buildings ORDER BY building_id")
    buildings = cur.fetchall()

    cur.execute("SELECT room_id, building_id FROM rooms ORDER BY room_id")
    rooms = cur.fetchall()

    cur.close()

    logger.info(f"查询学生列表结果 - 总数: {total}, 当前页: {page}")
    return render_template('students.html',
                           students=students_page,
                           page=page,
                           total_pages=total_pages,
                           buildings=buildings,
                           rooms=rooms,
                           filters={
                               'student_id': student_id,
                               'name': name,
                               'gender': gender,
                               'ethnicity': ethnicity,
                               'major': major,
                               'class': class_name,
                               'phone': phone,
                               'building_id': building_id,
                               'room_id': room_id
                           })

@app.route('/students/add', methods=['POST'])
@login_required
@log_operation("添加学生")
def add_student():
    """添加学生"""
    try:
        student_id = request.form.get('student_id')
        name = request.form.get('name')
        gender = request.form.get('gender')
        ethnicity = request.form.get('ethnicity', '汉族')
        major = request.form.get('major')
        class_name = request.form.get('class')
        phone = request.form.get('phone')
        building_id = request.form.get('building_id') or None
        room_id = request.form.get('room_id') or None

        logger.info(f"添加学生 - 学号: {student_id}, 姓名: {name}, 操作者: {session['user_id']}")

        cur = mysql.connection.cursor()

        # 检查学号是否存在
        cur.execute("SELECT student_id FROM students WHERE student_id = %s", (student_id,))
        if cur.fetchone():
            flash('学号已存在', 'danger')
            cur.close()
            return redirect(url_for('students'))

        # 检查房间容量
        if room_id:
            cur.execute("""
                SELECT r.capacity, COUNT(s.student_id) as current 
                FROM rooms r 
                LEFT JOIN students s ON r.room_id = s.room_id 
                WHERE r.room_id = %s 
                GROUP BY r.room_id, r.capacity
            """, (room_id,))
            room = cur.fetchone()
            if room and room['current'] >= room['capacity']:
                flash('该寝室已满员', 'danger')
                cur.close()
                return redirect(url_for('students'))

        cur.execute("""
            INSERT INTO students (student_id, name, gender, ethnicity, major, class, phone, building_id, room_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (student_id, name, gender, ethnicity, major, class_name, phone, building_id, room_id))

        mysql.connection.commit()
        cur.close()

        logger.info(f"添加学生成功 - 学号: {student_id}, 姓名: {name}")
        flash('学生信息添加成功', 'success')
    except Exception as e:
        logger.error(f"添加学生失败 - 学号: {student_id}, 错误: {str(e)}")
        flash(f'添加失败: {str(e)}', 'danger')

    return redirect(url_for('students'))

@app.route('/students/edit/<student_id>', methods=['POST'])
@login_required
@log_operation("编辑学生")
def edit_student(student_id):
    """编辑学生"""
    try:
        name = request.form.get('name')
        gender = request.form.get('gender')
        ethnicity = request.form.get('ethnicity')
        major = request.form.get('major')
        class_name = request.form.get('class')
        phone = request.form.get('phone')
        building_id = request.form.get('building_id') or None
        room_id = request.form.get('room_id') or None

        logger.info(f"编辑学生 - 学号: {student_id}, 新姓名: {name}, 操作者: {session['user_id']}")

        cur = mysql.connection.cursor()

        # 检查房间容量
        if room_id:
            cur.execute("""
                SELECT r.capacity, COUNT(s.student_id) as current 
                FROM rooms r 
                LEFT JOIN students s ON r.room_id = s.room_id 
                WHERE r.room_id = %s AND s.student_id != %s
                GROUP BY r.room_id, r.capacity
            """, (room_id, student_id))
            room = cur.fetchone()
            if room and room['current'] >= room['capacity']:
                flash('该寝室已满员', 'danger')
                cur.close()
                return redirect(url_for('students'))

        cur.execute("""
            UPDATE students 
            SET name=%s, gender=%s, ethnicity=%s, major=%s, class=%s, phone=%s, building_id=%s, room_id=%s
            WHERE student_id=%s
        """, (name, gender, ethnicity, major, class_name, phone, building_id, room_id, student_id))

        mysql.connection.commit()
        cur.close()

        logger.info(f"编辑学生成功 - 学号: {student_id}")
        flash('学生信息更新成功', 'success')
    except Exception as e:
        logger.error(f"编辑学生失败 - 学号: {student_id}, 错误: {str(e)}")
        flash(f'更新失败: {str(e)}', 'danger')

    return redirect(url_for('students'))

@app.route('/students/delete/<student_id>', methods=['POST'])
@login_required
@log_operation("删除学生")
def delete_student(student_id):
    """删除学生"""
    try:
        logger.info(f"删除学生 - 学号: {student_id}, 操作者: {session['user_id']}")

        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM students WHERE student_id = %s", (student_id,))
        mysql.connection.commit()
        cur.close()

        logger.info(f"删除学生成功 - 学号: {student_id}")
        flash('学生信息删除成功', 'success')
    except Exception as e:
        logger.error(f"删除学生失败 - 学号: {student_id}, 错误: {str(e)}")
        flash(f'删除失败: {str(e)}', 'danger')

    return redirect(url_for('students'))

# ==================== 学生API接口 ====================
@app.route('/api/student/<student_id>')
@login_required
def api_get_student(student_id):
    """获取学生信息"""
    logger.info(f"API获取学生信息 - 学号: {student_id}")
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM students WHERE student_id = %s", (student_id,))
    student = cur.fetchone()
    cur.close()
    if student:
        return jsonify(student)
    return jsonify({'error': 'Student not found'}), 404

# ==================== 公寓楼管理 ====================
@app.route('/buildings')
@login_required
def buildings():
    """公寓楼列表 - 增强查询功能"""
    logger.info(f"查看公寓楼列表 - 用户: {session['user_id']}")
    building_id = request.args.get('building_id', '')
    floors = request.args.get('floors', '')
    rooms_count = request.args.get('rooms_count', '')
    actual_rooms = request.args.get('actual_rooms', '')
    commission_date = request.args.get('commission_date', '')
    student_count = request.args.get('student_count', '')

    cur = mysql.connection.cursor()

    # 构建查询
    query = """
        SELECT b.*,
               (SELECT COUNT(*) FROM rooms WHERE building_id = b.building_id) as actual_rooms,
               (SELECT COUNT(*) FROM students WHERE building_id = b.building_id) as student_count
        FROM buildings b
        WHERE 1=1
    """
    params = []

    if building_id:
        query += " AND b.building_id LIKE %s"
        params.append(f'%{building_id}%')

    if floors:
        query += " AND b.floors = %s"
        params.append(int(floors))

    if rooms_count:
        query += " AND b.rooms_count = %s"
        params.append(int(rooms_count))

    if actual_rooms:
        query += " AND (SELECT COUNT(*) FROM rooms WHERE building_id = b.building_id) = %s"
        params.append(int(actual_rooms))

    if commission_date:
        query += " AND DATE(b.commission_date) = %s"
        params.append(commission_date)

    if student_count:
        query += " AND (SELECT COUNT(*) FROM students WHERE building_id = b.building_id) = %s"
        params.append(int(student_count))

    query += " ORDER BY b.building_id"

    cur.execute(query, params)
    buildings_list = cur.fetchall()
    cur.close()

    logger.info(f"查询公寓楼列表结果 - 数量: {len(buildings_list)}")
    return render_template('buildings.html',
                           buildings=buildings_list,
                           filters={
                               'building_id': building_id,
                               'floors': floors,
                               'rooms_count': rooms_count,
                               'actual_rooms': actual_rooms,
                               'commission_date': commission_date,
                               'student_count': student_count
                           })

@app.route('/buildings/add', methods=['POST'])
@login_required
@log_operation("添加公寓楼")
def add_building():
    """添加公寓楼"""
    try:
        building_id = request.form.get('building_id')
        floors = request.form.get('floors', type=int)
        rooms_count = request.form.get('rooms_count', type=int)
        commission_date = request.form.get('commission_date')

        logger.info(f"添加公寓楼 - 楼号: {building_id}, 楼层: {floors}, 房间数: {rooms_count}")

        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO buildings (building_id, floors, rooms_count, commission_date)
            VALUES (%s, %s, %s, %s)
        """, (building_id, floors, rooms_count, commission_date))

        mysql.connection.commit()
        cur.close()

        logger.info(f"添加公寓楼成功 - 楼号: {building_id}")
        flash('公寓楼添加成功', 'success')
    except Exception as e:
        logger.error(f"添加公寓楼失败 - 楼号: {building_id}, 错误: {str(e)}")
        flash(f'添加失败: {str(e)}', 'danger')

    return redirect(url_for('buildings'))

@app.route('/buildings/edit/<building_id>', methods=['POST'])
@login_required
@log_operation("编辑公寓楼")
def edit_building(building_id):
    """编辑公寓楼"""
    try:
        floors = request.form.get('floors', type=int)
        rooms_count = request.form.get('rooms_count', type=int)
        commission_date = request.form.get('commission_date')

        logger.info(f"编辑公寓楼 - 楼号: {building_id}, 新楼层: {floors}, 新房间数: {rooms_count}")

        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE buildings 
            SET floors=%s, rooms_count=%s, commission_date=%s
            WHERE building_id=%s
        """, (floors, rooms_count, commission_date, building_id))

        mysql.connection.commit()
        cur.close()

        logger.info(f"编辑公寓楼成功 - 楼号: {building_id}")
        flash('公寓楼信息更新成功', 'success')
    except Exception as e:
        logger.error(f"编辑公寓楼失败 - 楼号: {building_id}, 错误: {str(e)}")
        flash(f'更新失败: {str(e)}', 'danger')

    return redirect(url_for('buildings'))

@app.route('/buildings/delete/<building_id>', methods=['POST'])
@login_required
@log_operation("删除公寓楼")
def delete_building(building_id):
    """删除公寓楼"""
    try:
        logger.info(f"删除公寓楼 - 楼号: {building_id}, 操作者: {session['user_id']}")

        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM buildings WHERE building_id = %s", (building_id,))
        mysql.connection.commit()
        cur.close()

        logger.info(f"删除公寓楼成功 - 楼号: {building_id}")
        flash('公寓楼删除成功', 'success')
    except Exception as e:
        logger.error(f"删除公寓楼失败 - 楼号: {building_id}, 错误: {str(e)}")
        flash(f'删除失败: {str(e)}', 'danger')

    return redirect(url_for('buildings'))

# ==================== 寝室管理 ====================
@app.route('/rooms')
@login_required
def rooms():
    """寝室列表 - 增加查询功能"""
    logger.info(f"查看寝室列表 - 用户: {session['user_id']}")
    building_filter = request.args.get('building', '')
    room_id_filter = request.args.get('room_id', '')
    available_beds_filter = request.args.get('available_beds', '')
    fee_min = request.args.get('fee_min', '')
    fee_max = request.args.get('fee_max', '')
    phone_filter = request.args.get('phone', '')

    cur = mysql.connection.cursor()

    # 构建查询
    query = """
        SELECT r.*,
               (SELECT COUNT(*) FROM students WHERE room_id = r.room_id) as current_occupancy,
               r.capacity - (SELECT COUNT(*) FROM students WHERE room_id = r.room_id) as available_beds
        FROM rooms r
        WHERE 1=1
    """
    params = []

    if building_filter:
        query += " AND r.building_id = %s"
        params.append(building_filter)

    if room_id_filter:
        query += " AND r.room_id LIKE %s"
        params.append(f'%{room_id_filter}%')

    if fee_min:
        query += " AND r.fee >= %s"
        params.append(float(fee_min))

    if fee_max:
        query += " AND r.fee <= %s"
        params.append(float(fee_max))

    if phone_filter:
        query += " AND r.phone LIKE %s"
        params.append(f'%{phone_filter}%')

    query += " ORDER BY r.building_id, r.room_id"

    cur.execute(query, params)
    rooms_list = cur.fetchall()

    # 根据剩余床位筛选
    if available_beds_filter:
        if available_beds_filter == '0':
            rooms_list = [r for r in rooms_list if r['available_beds'] == 0]
        elif available_beds_filter == '1':
            rooms_list = [r for r in rooms_list if r['available_beds'] > 0]
        elif available_beds_filter == '2':
            rooms_list = [r for r in rooms_list if r['available_beds'] >= 2]
        elif available_beds_filter == '4':
            rooms_list = [r for r in rooms_list if r['available_beds'] >= 4]

    cur.execute("SELECT building_id FROM buildings ORDER BY building_id")
    buildings = cur.fetchall()

    cur.close()

    logger.info(f"查询寝室列表结果 - 数量: {len(rooms_list)}")
    return render_template('rooms.html',
                          rooms=rooms_list,
                          buildings=buildings,
                          building_filter=building_filter,
                          room_id_filter=room_id_filter,
                          available_beds_filter=available_beds_filter,
                          fee_min=fee_min,
                          fee_max=fee_max,
                          phone_filter=phone_filter)

@app.route('/rooms/add', methods=['POST'])
@login_required
@log_operation("添加寝室")
def add_room():
    """添加寝室"""
    try:
        room_id = request.form.get('room_id')
        building_id = request.form.get('building_id')
        capacity = request.form.get('capacity', type=int)
        fee = request.form.get('fee', type=float)
        phone = request.form.get('phone')

        logger.info(f"添加寝室 - 寝室号: {room_id}, 楼号: {building_id}, 容量: {capacity}, 费用: {fee}")

        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO rooms (room_id, building_id, capacity, fee, phone)
            VALUES (%s, %s, %s, %s, %s)
        """, (room_id, building_id, capacity, fee, phone))

        mysql.connection.commit()
        cur.close()

        logger.info(f"添加寝室成功 - 寝室号: {room_id}")
        flash('寝室添加成功', 'success')
    except Exception as e:
        logger.error(f"添加寝室失败 - 寝室号: {room_id}, 错误: {str(e)}")
        flash(f'添加失败: {str(e)}', 'danger')

    return redirect(url_for('rooms'))

@app.route('/rooms/edit/<room_id>', methods=['POST'])
@login_required
@log_operation("编辑寝室")
def edit_room(room_id):
    """编辑寝室"""
    try:
        building_id = request.form.get('building_id')
        capacity = request.form.get('capacity', type=int)
        fee = request.form.get('fee', type=float)
        phone = request.form.get('phone')

        logger.info(f"编辑寝室 - 寝室号: {room_id}, 新楼号: {building_id}, 新容量: {capacity}, 新费用: {fee}")

        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE rooms 
            SET building_id=%s, capacity=%s, fee=%s, phone=%s
            WHERE room_id=%s
        """, (building_id, capacity, fee, phone, room_id))

        mysql.connection.commit()
        cur.close()

        logger.info(f"编辑寝室成功 - 寝室号: {room_id}")
        flash('寝室信息更新成功', 'success')
    except Exception as e:
        logger.error(f"编辑寝室失败 - 寝室号: {room_id}, 错误: {str(e)}")
        flash(f'更新失败: {str(e)}', 'danger')

    return redirect(url_for('rooms'))

@app.route('/rooms/delete/<room_id>', methods=['POST'])
@login_required
@log_operation("删除寝室")
def delete_room(room_id):
    """删除寝室"""
    try:
        logger.info(f"删除寝室 - 寝室号: {room_id}, 操作者: {session['user_id']}")

        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM rooms WHERE room_id = %s", (room_id,))
        mysql.connection.commit()
        cur.close()

        logger.info(f"删除寝室成功 - 寝室号: {room_id}")
        flash('寝室删除成功', 'success')
    except Exception as e:
        logger.error(f"删除寝室失败 - 寝室号: {room_id}, 错误: {str(e)}")
        flash(f'删除失败: {str(e)}', 'danger')

    return redirect(url_for('rooms'))

# ==================== 房间API接口 ====================
@app.route('/api/rooms/<building_id>')
@login_required
def api_get_rooms(building_id):
    """获取指定楼栋的房间"""
    logger.info(f"API获取房间列表 - 楼号: {building_id}")
    cur = mysql.connection.cursor()
    cur.execute("SELECT room_id, capacity, fee FROM rooms WHERE building_id = %s ORDER BY room_id", (building_id,))
    rooms = cur.fetchall()
    cur.close()
    return jsonify(rooms)

# ==================== 交费管理 ====================
@app.route('/payments')
@login_required
def payments():
    """交费记录列表 - 增强查询功能"""
    logger.info(f"查看交费记录 - 用户: {session['user_id']}")
    page = request.args.get('page', 1, type=int)
    payment_id = request.args.get('payment_id', '')
    student_id = request.args.get('student_id', '')
    student_name = request.args.get('student_name', '')
    major = request.args.get('major', '')
    class_name = request.args.get('class', '')
    building_id = request.args.get('building_id', '')
    room_id = request.args.get('room_id', '')
    payment_type = request.args.get('payment_type', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    per_page = 15

    cur = mysql.connection.cursor()

    query = """
        SELECT p.*, s.name as student_name, s.major, s.class, s.building_id, s.room_id
        FROM payments p
        JOIN students s ON p.student_id = s.student_id
        WHERE 1=1
    """
    params = []

    if payment_id:
        query += " AND p.payment_id = %s"
        params.append(payment_id)

    if student_id:
        query += " AND p.student_id LIKE %s"
        params.append(f'%{student_id}%')

    if student_name:
        query += " AND s.name LIKE %s"
        params.append(f'%{student_name}%')

    if major:
        query += " AND s.major LIKE %s"
        params.append(f'%{major}%')

    if class_name:
        query += " AND s.class LIKE %s"
        params.append(f'%{class_name}%')

    if building_id:
        query += " AND s.building_id LIKE %s"
        params.append(f'%{building_id}%')

    if room_id:
        query += " AND s.room_id LIKE %s"
        params.append(f'%{room_id}%')

    if payment_type:
        query += " AND p.payment_type = %s"
        params.append(payment_type)

    if start_date:
        query += " AND p.payment_date >= %s"
        params.append(start_date)

    if end_date:
        query += " AND p.payment_date <= %s"
        params.append(end_date)

    query += " ORDER BY p.payment_date DESC, p.payment_id DESC"

    cur.execute(query, params)
    all_payments = cur.fetchall()
    total = len(all_payments)

    # 分页
    start = (page - 1) * per_page
    end = start + per_page
    payments_page = all_payments[start:end]

    total_pages = (total + per_page - 1) // per_page

    # 统计
    total_amount = sum(p['amount'] for p in all_payments)

    # 获取学生和寝室数据
    cur.execute("SELECT student_id, name, building_id, room_id FROM students ORDER BY student_id")
    students = cur.fetchall()

    cur.execute("SELECT building_id FROM buildings ORDER BY building_id")
    buildings = cur.fetchall()

    cur.execute("SELECT room_id, building_id FROM rooms ORDER BY room_id")
    rooms = cur.fetchall()

    cur.close()

    logger.info(f"查询交费记录结果 - 总数: {total}, 总金额: {total_amount}")
    return render_template('payments.html',
                           payments=payments_page,
                           page=page,
                           total_pages=total_pages,
                           total_amount=total_amount,
                           students=students,
                           buildings=buildings,
                           rooms=rooms,
                           filters={
                               'payment_id': payment_id,
                               'student_id': student_id,
                               'student_name': student_name,
                               'major': major,
                               'class': class_name,
                               'building_id': building_id,
                               'room_id': room_id,
                               'payment_type': payment_type,
                               'start_date': start_date,
                               'end_date': end_date
                           })

@app.route('/payments/add', methods=['POST'])
@login_required
@log_operation("添加交费记录")
def add_payment():
    """添加交费记录"""
    try:
        student_id = request.form.get('student_id')
        payment_date = request.form.get('payment_date')
        payment_type = request.form.get('payment_type')
        amount = request.form.get('amount', type=float)
        remark = request.form.get('remark', '')

        logger.info(f"添加交费记录 - 学号: {student_id}, 类型: {payment_type}, 金额: {amount}")

        cur = mysql.connection.cursor()

        # 获取学生的楼栋和寝室信息
        cur.execute("SELECT building_id, room_id FROM students WHERE student_id = %s", (student_id,))
        student = cur.fetchone()

        if not student or not student['building_id'] or not student['room_id']:
            flash('该学生未分配寝室', 'danger')
            cur.close()
            return redirect(url_for('payments'))

        cur.execute("""
            INSERT INTO payments (building_id, room_id, payment_date, payment_type, amount, student_id, remark)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (student['building_id'], student['room_id'], payment_date, payment_type, amount, student_id, remark))

        mysql.connection.commit()
        cur.close()

        logger.info(f"添加交费记录成功 - 学号: {student_id}, 金额: {amount}")
        flash('交费记录添加成功', 'success')
    except Exception as e:
        logger.error(f"添加交费记录失败 - 学号: {student_id}, 错误: {str(e)}")
        flash(f'添加失败: {str(e)}', 'danger')

    return redirect(url_for('payments'))

@app.route('/payments/edit/<int:payment_id>', methods=['POST'])
@login_required
@log_operation("修改交费记录")
def edit_payment(payment_id):
    """修改交费记录"""
    try:
        payment_date = request.form.get('payment_date')
        payment_type = request.form.get('payment_type')
        amount = request.form.get('amount', type=float)
        remark = request.form.get('remark', '')

        logger.info(f"修改交费记录 - 记录ID: {payment_id}, 新金额: {amount}")

        cur = mysql.connection.cursor()

        cur.execute("""
            UPDATE payments 
            SET payment_date=%s, payment_type=%s, amount=%s, remark=%s
            WHERE payment_id=%s
        """, (payment_date, payment_type, amount, remark, payment_id))

        mysql.connection.commit()
        cur.close()

        logger.info(f"修改交费记录成功 - 记录ID: {payment_id}")
        flash('交费记录修改成功', 'success')
    except Exception as e:
        logger.error(f"修改交费记录失败 - 记录ID: {payment_id}, 错误: {str(e)}")
        flash(f'修改失败: {str(e)}', 'danger')

    return redirect(url_for('payments'))

@app.route('/payments/delete/<int:payment_id>', methods=['POST'])
@login_required
@log_operation("删除交费记录")
def delete_payment(payment_id):
    """删除交费记录"""
    try:
        logger.info(f"删除交费记录 - 记录ID: {payment_id}, 操作者: {session['user_id']}")

        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM payments WHERE payment_id = %s", (payment_id,))
        mysql.connection.commit()
        cur.close()

        logger.info(f"删除交费记录成功 - 记录ID: {payment_id}")
        flash('交费记录删除成功', 'success')
    except Exception as e:
        logger.error(f"删除交费记录失败 - 记录ID: {payment_id}, 错误: {str(e)}")
        flash(f'删除失败: {str(e)}', 'danger')

    return redirect(url_for('payments'))

# ==================== 统计报表 ====================
@app.route('/reports')
@login_required
def reports():
    """统计报表"""
    logger.info(f"查看统计报表 - 用户: {session['user_id']}")
    cur = mysql.connection.cursor()

    # 月度统计
    cur.execute("""
        SELECT 
            DATE_FORMAT(payment_date, '%Y-%m') as month,
            payment_type,
            COUNT(*) as count,
            SUM(amount) as total
        FROM payments
        WHERE payment_date >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
        GROUP BY DATE_FORMAT(payment_date, '%Y-%m'), payment_type
        ORDER BY month DESC, payment_type
    """)
    monthly_stats = cur.fetchall()

    # 各公寓楼统计
    cur.execute("""
        SELECT 
            b.building_id,
            b.floors,
            b.rooms_count,
            b.commission_date,
            COUNT(DISTINCT s.student_id) as student_count,
            COUNT(DISTINCT p.payment_id) as payment_count,
            COALESCE(SUM(p.amount), 0) as total_amount
        FROM buildings b
        LEFT JOIN students s ON b.building_id = s.building_id
        LEFT JOIN payments p ON b.building_id = p.building_id
        GROUP BY b.building_id, b.floors, b.rooms_count, b.commission_date
        ORDER BY b.building_id
    """)
    building_stats = cur.fetchall()

    # 专业统计
    cur.execute("""
        SELECT 
            s.major,
            COUNT(DISTINCT s.student_id) as student_count,
            COUNT(p.payment_id) as payment_count,
            COALESCE(SUM(p.amount), 0) as total_amount
        FROM students s
        LEFT JOIN payments p ON s.student_id = p.student_id
        GROUP BY s.major
        ORDER BY student_count DESC
    """)
    major_stats = cur.fetchall()

    # 欠费学生
    cur.execute("""
        SELECT s.student_id, s.name, s.major, s.class, s.building_id, s.room_id,
               COALESCE(SUM(CASE WHEN p.payment_type = '住宿费' THEN p.amount ELSE 0 END), 0) as paid_amount,
               COALESCE(r.fee, 1200) as should_pay
        FROM students s
        LEFT JOIN rooms r ON s.room_id = r.room_id
        LEFT JOIN payments p ON s.student_id = p.student_id 
        GROUP BY s.student_id, s.name, s.major, s.class, s.building_id, s.room_id, r.fee
        HAVING paid_amount < should_pay OR (r.fee IS NOT NULL AND paid_amount = 0)
        ORDER BY (should_pay - paid_amount) DESC
        LIMIT 20
    """)
    arrears_students = cur.fetchall()

    cur.close()

    # 获取当前时间
    from datetime import datetime
    now = datetime.now()

    logger.info(f"统计报表查询完成 - 月度统计: {len(monthly_stats)}条")
    return render_template('reports.html',
                           monthly_stats=monthly_stats,
                           building_stats=building_stats,
                           major_stats=major_stats,
                           arrears_students=arrears_students,
                           now=now)

# ==================== 通知公告管理 ====================
@app.route('/announcements')
@login_required
def announcements():
    """通知公告列表 - 多条件组合查询"""
    logger.info(f"查看通知公告 - 用户: {session['user_id']}")
    page = request.args.get('page', 1, type=int)
    title = request.args.get('title', '')
    publisher_name = request.args.get('publisher_name', '')
    content = request.args.get('content', '')
    permission = request.args.get('permission', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    per_page = 10

    cur = mysql.connection.cursor()

    # 构建查询条件
    query = """
        SELECT a.*, 
               CASE 
                   WHEN a.publisher_id = %s THEN 1
                   ELSE 0 
               END as is_owner
        FROM announcements a
        WHERE (a.permission = '全部' OR 
               a.permission = %s OR 
               %s = '管理员')
    """
    params = [session['user_id'], session['permission'], session['permission']]

    if title:
        query += " AND a.title LIKE %s"
        params.append(f'%{title}%')

    if publisher_name:
        query += " AND a.publisher_name LIKE %s"
        params.append(f'%{publisher_name}%')

    if content:
        query += " AND a.content LIKE %s"
        params.append(f'%{content}%')

    if permission and permission != '全部':
        query += " AND a.permission = %s"
        params.append(permission)

    if start_date:
        query += " AND DATE(a.created_at) >= %s"
        params.append(start_date)

    if end_date:
        query += " AND DATE(a.created_at) <= %s"
        params.append(end_date)

    query += " ORDER BY a.created_at DESC, a.announcement_id DESC"

    cur.execute(query, params)
    all_announcements = cur.fetchall()
    total = len(all_announcements)

    # 分页
    start = (page - 1) * per_page
    end = start + per_page
    announcements_page = all_announcements[start:end]

    total_pages = (total + per_page - 1) // per_page

    cur.close()

    logger.info(f"查询通知公告结果 - 总数: {total}")
    return render_template('announcements.html',
                           announcements=announcements_page,
                           page=page,
                           total_pages=total_pages,
                           total=total,
                           filters={
                               'title': title,
                               'publisher_name': publisher_name,
                               'content': content,
                               'permission': permission,
                               'start_date': start_date,
                               'end_date': end_date
                           })

@app.route('/announcements/add', methods=['POST'])
@login_required
@log_operation("添加通知公告")
def add_announcement():
    """添加通知公告"""
    try:
        title = request.form.get('title')
        content = request.form.get('content')
        permission = request.form.get('permission', '全部')

        logger.info(f"添加通知公告 - 标题: {title}, 发布者: {session['realname']}")

        if not title or not content:
            flash('请填写标题和内容', 'danger')
            return redirect(url_for('announcements'))

        cur = mysql.connection.cursor()

        cur.execute("""
            INSERT INTO announcements (title, content, publisher_id, publisher_name, permission)
            VALUES (%s, %s, %s, %s, %s)
        """, (title, content, session['user_id'], session['realname'], permission))

        mysql.connection.commit()
        cur.close()

        logger.info(f"添加通知公告成功 - 标题: {title}")
        flash('通知发布成功', 'success')
    except Exception as e:
        logger.error(f"添加通知公告失败 - 标题: {title}, 错误: {str(e)}")
        flash(f'发布失败: {str(e)}', 'danger')

    return redirect(url_for('announcements'))

@app.route('/announcements/edit/<int:announcement_id>', methods=['POST'])
@login_required
@log_operation("编辑通知公告")
def edit_announcement(announcement_id):
    """编辑通知公告"""
    try:
        title = request.form.get('title')
        content = request.form.get('content')
        permission = request.form.get('permission', '全部')

        logger.info(f"编辑通知公告 - ID: {announcement_id}, 新标题: {title}")

        if not title or not content:
            flash('请填写标题和内容', 'danger')
            return redirect(url_for('announcements'))

        cur = mysql.connection.cursor()

        # 检查权限：只有管理员或发布者本人可以编辑
        cur.execute("SELECT publisher_id, permission FROM announcements WHERE announcement_id = %s", (announcement_id,))
        announcement = cur.fetchone()

        if not announcement:
            flash('通知不存在', 'danger')
            cur.close()
            return redirect(url_for('announcements'))

        if session['permission'] != '管理员' and session['user_id'] != announcement['publisher_id']:
            flash('没有权限编辑此通知', 'danger')
            cur.close()
            return redirect(url_for('announcements'))

        cur.execute("""
            UPDATE announcements 
            SET title=%s, content=%s, permission=%s, updated_at=CURRENT_TIMESTAMP
            WHERE announcement_id=%s
        """, (title, content, permission, announcement_id))

        mysql.connection.commit()
        cur.close()

        logger.info(f"编辑通知公告成功 - ID: {announcement_id}")
        flash('通知修改成功', 'success')
    except Exception as e:
        logger.error(f"编辑通知公告失败 - ID: {announcement_id}, 错误: {str(e)}")
        flash(f'修改失败: {str(e)}', 'danger')

    return redirect(url_for('announcements'))

@app.route('/announcements/delete/<int:announcement_id>', methods=['POST'])
@login_required
@log_operation("删除通知公告")
def delete_announcement(announcement_id):
    """删除通知公告"""
    try:
        logger.info(f"删除通知公告 - ID: {announcement_id}, 操作者: {session['user_id']}")

        cur = mysql.connection.cursor()

        # 检查权限：只有管理员或发布者本人可以删除
        cur.execute("SELECT publisher_id, permission FROM announcements WHERE announcement_id = %s", (announcement_id,))
        announcement = cur.fetchone()

        if not announcement:
            flash('通知不存在', 'danger')
            cur.close()
            return redirect(url_for('announcements'))

        if session['permission'] != '管理员' and session['user_id'] != announcement['publisher_id']:
            flash('没有权限删除此通知', 'danger')
            cur.close()
            return redirect(url_for('announcements'))

        cur.execute("DELETE FROM announcements WHERE announcement_id = %s", (announcement_id,))

        mysql.connection.commit()
        cur.close()

        logger.info(f"删除通知公告成功 - ID: {announcement_id}")
        flash('通知删除成功', 'success')
    except Exception as e:
        logger.error(f"删除通知公告失败 - ID: {announcement_id}, 错误: {str(e)}")
        flash(f'删除失败: {str(e)}', 'danger')

    return redirect(url_for('announcements'))

@app.route('/announcements/view/<int:announcement_id>')
@login_required
def view_announcement(announcement_id):
    """查看通知详情"""
    logger.info(f"查看通知详情 - ID: {announcement_id}, 用户: {session['user_id']}")

    cur = mysql.connection.cursor()

    # 检查是否有权限查看
    cur.execute("""
        SELECT a.* 
        FROM announcements a
        WHERE a.announcement_id = %s 
          AND (a.permission = '全部' OR 
               a.permission = %s OR 
               %s = '管理员')
    """, (announcement_id, session['permission'], session['permission']))

    announcement = cur.fetchone()
    cur.close()

    if not announcement:
        logger.warning(f"查看通知详情失败 - 无权限或不存在, ID: {announcement_id}")
        flash('通知不存在或没有权限查看', 'danger')
        return redirect(url_for('announcements'))

    # 添加当前时间给模板使用
    from datetime import datetime
    now = datetime.now()

    return render_template('view_announcement.html', announcement=announcement, now=now)

# ==================== 用户管理 ====================
@app.route('/users')
@admin_required
def users():
    """用户管理 - 添加查询功能"""
    logger.info(f"查看用户列表 - 管理员: {session['user_id']}")
    user_id = request.args.get('user_id', '')
    realname = request.args.get('realname', '')
    job_title = request.args.get('job_title', '')
    permission = request.args.get('permission', '')
    created_start = request.args.get('created_start', '')
    created_end = request.args.get('created_end', '')
    updated_start = request.args.get('updated_start', '')
    updated_end = request.args.get('updated_end', '')

    cur = mysql.connection.cursor()

    query = """
        SELECT user_id, realname, permission, job_title, email, phone, remark, created_at, updated_at 
        FROM users 
        WHERE 1=1
    """
    params = []

    if user_id:
        query += " AND user_id LIKE %s"
        params.append(f'%{user_id}%')

    if realname:
        query += " AND realname LIKE %s"
        params.append(f'%{realname}%')

    if job_title:
        query += " AND job_title = %s"
        params.append(job_title)

    if permission:
        query += " AND permission = %s"
        params.append(permission)

    if created_start:
        query += " AND DATE(created_at) >= %s"
        params.append(created_start)

    if created_end:
        query += " AND DATE(created_at) <= %s"
        params.append(created_end)

    if updated_start:
        query += " AND DATE(updated_at) >= %s"
        params.append(updated_start)

    if updated_end:
        query += " AND DATE(updated_at) <= %s"
        params.append(updated_end)

    query += " ORDER BY user_id"

    cur.execute(query, params)
    users_list = cur.fetchall()

    # 获取待审批数量
    cur.execute("SELECT COUNT(*) as count FROM user_requests WHERE status = '待审批'")
    pending_count = cur.fetchone()['count']

    cur.close()

    logger.info(f"用户列表查询结果 - 数量: {len(users_list)}")
    return render_template('users.html',
                           users=users_list,
                           pending_requests_count=pending_count,
                           filters={
                               'user_id': user_id,
                               'realname': realname,
                               'job_title': job_title,
                               'permission': permission,
                               'created_start': created_start,
                               'created_end': created_end,
                               'updated_start': updated_start,
                               'updated_end': updated_end
                           })

@app.route('/users/add', methods=['POST'])
@admin_required
@log_operation("添加用户")
def add_user():
    """添加用户"""
    try:
        user_id = request.form.get('user_id')
        password = request.form.get('password')
        realname = request.form.get('realname')
        job_title = request.form.get('job_title')
        permission = request.form.get('permission')

        logger.info(f"添加用户 - 用户ID: {user_id}, 真实姓名: {realname}, 职务: {job_title}, 权限: {permission}")

        if not user_id or not password or not realname or not job_title:
            flash('请填写完整信息', 'danger')
            return redirect(url_for('users'))

        # 验证用户ID格式
        if not validate_user_id(user_id):
            flash('用户ID格式不正确，应为10位数字（四位年份+两位部门+四位顺序号）', 'danger')
            return redirect(url_for('users'))

        hashed_password = hash_password(password)

        cur = mysql.connection.cursor()

        # 检查用户ID是否已存在
        cur.execute("SELECT user_id FROM users WHERE user_id = %s", (user_id,))
        if cur.fetchone():
            flash('用户ID已存在', 'danger')
            cur.close()
            return redirect(url_for('users'))

        cur.execute("""
            INSERT INTO users (user_id, password, realname, permission, job_title)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, hashed_password, realname, permission, job_title))

        mysql.connection.commit()
        cur.close()

        logger.info(f"添加用户成功 - 用户ID: {user_id}, 真实姓名: {realname}")
        flash(f'用户添加成功！用户ID: {user_id}', 'success')
    except Exception as e:
        logger.error(f"添加用户失败 - 用户ID: {user_id}, 错误: {str(e)}")
        flash(f'添加失败: {str(e)}', 'danger')

    return redirect(url_for('users'))

@app.route('/users/edit/<user_id>', methods=['POST'])
@admin_required
@log_operation("编辑用户")
def edit_user(user_id):
    """编辑用户"""
    try:
        realname = request.form.get('realname')
        job_title = request.form.get('job_title')
        permission = request.form.get('permission')
        password = request.form.get('password')

        logger.info(f"编辑用户 - 用户ID: {user_id}, 新真实姓名: {realname}, 新职务: {job_title}, 新权限: {permission}")

        cur = mysql.connection.cursor()

        if password:
            hashed_password = hash_password(password)
            cur.execute("""
                UPDATE users 
                SET realname=%s, job_title=%s, permission=%s, password=%s
                WHERE user_id=%s
            """, (realname, job_title, permission, hashed_password, user_id))
        else:
            cur.execute("""
                UPDATE users 
                SET realname=%s, job_title=%s, permission=%s
                WHERE user_id=%s
            """, (realname, job_title, permission, user_id))

        mysql.connection.commit()
        cur.close()

        logger.info(f"编辑用户成功 - 用户ID: {user_id}")
        flash('用户信息更新成功', 'success')
    except Exception as e:
        logger.error(f"编辑用户失败 - 用户ID: {user_id}, 错误: {str(e)}")
        flash(f'更新失败: {str(e)}', 'danger')

    return redirect(url_for('users'))

@app.route('/users/delete/<user_id>', methods=['POST'])
@admin_required
@log_operation("删除用户")
def delete_user(user_id):
    """删除用户"""
    if user_id == session.get('user_id'):
        logger.warning(f"尝试删除当前登录用户 - 用户ID: {user_id}")
        flash('不能删除当前登录用户', 'danger')
        return redirect(url_for('users'))

    try:
        logger.info(f"删除用户 - 用户ID: {user_id}, 操作者: {session['user_id']}")

        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
        mysql.connection.commit()
        cur.close()

        logger.info(f"删除用户成功 - 用户ID: {user_id}")
        flash('用户删除成功', 'success')
    except Exception as e:
        logger.error(f"删除用户失败 - 用户ID: {user_id}, 错误: {str(e)}")
        flash(f'删除失败: {str(e)}', 'danger')

    return redirect(url_for('users'))

# ==================== 注册审批管理 ====================
@app.route('/user_requests')
@admin_required
def user_requests():
    """查看待审批的注册申请 - 增加查询功能"""
    logger.info(f"查看注册申请 - 管理员: {session['user_id']}")
    status_filter = request.args.get('status', '待审批')
    request_id = request.args.get('request_id', '')
    user_id = request.args.get('user_id', '')
    realname = request.args.get('realname', '')
    job_title = request.args.get('job_title', '')
    permission = request.args.get('permission', '')
    email = request.args.get('email', '')
    phone = request.args.get('phone', '')
    created_start = request.args.get('created_start', '')
    created_end = request.args.get('created_end', '')

    cur = mysql.connection.cursor()

    # 构建查询条件
    conditions = []
    params = []

    if status_filter != '全部':
        conditions.append("status = %s")
        params.append(status_filter)

    if request_id:
        conditions.append("request_id = %s")
        params.append(request_id)

    if user_id:
        conditions.append("user_id LIKE %s")
        params.append(f'%{user_id}%')

    if realname:
        conditions.append("realname LIKE %s")
        params.append(f'%{realname}%')

    if job_title:
        conditions.append("job_title = %s")
        params.append(job_title)

    if permission:
        conditions.append("permission = %s")
        params.append(permission)

    if email:
        conditions.append("email LIKE %s")
        params.append(f'%{email}%')

    if phone:
        conditions.append("phone LIKE %s")
        params.append(f'%{phone}%')

    if created_start:
        conditions.append("DATE(created_at) >= %s")
        params.append(created_start)

    if created_end:
        conditions.append("DATE(created_at) <= %s")
        params.append(created_end)

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    query = f"""
        SELECT * FROM user_requests 
        WHERE {where_clause}
        ORDER BY 
            CASE status 
                WHEN '待审批' THEN 1
                WHEN '已批准' THEN 2
                WHEN '已拒绝' THEN 3
            END, created_at DESC
    """

    cur.execute(query, params)
    requests_list = cur.fetchall()
    cur.close()

    logger.info(f"查询注册申请结果 - 数量: {len(requests_list)}")
    return render_template('user_requests.html',
                           requests=requests_list,
                           status_filter=status_filter,
                           filters={
                               'request_id': request_id,
                               'user_id': user_id,
                               'realname': realname,
                               'job_title': job_title,
                               'permission': permission,
                               'email': email,
                               'phone': phone,
                               'created_start': created_start,
                               'created_end': created_end
                           })

@app.route('/user_requests/approve/<int:request_id>', methods=['POST'])
@admin_required
@log_operation("批准注册申请")
def approve_user_request(request_id):
    """批准注册申请 - 管理员可以选择授予的权限"""
    try:
        # 获取管理员选择的权限，默认为申请时的权限
        granted_permission = request.form.get('granted_permission')
        if not granted_permission:
            flash('请选择要授予的权限', 'danger')
            return redirect(url_for('user_requests'))

        if granted_permission not in ['管理员', '教师']:
            flash('权限参数错误', 'danger')
            return redirect(url_for('user_requests'))

        cur = mysql.connection.cursor()

        # 获取申请信息
        cur.execute("SELECT * FROM user_requests WHERE request_id = %s", (request_id,))
        user_request = cur.fetchone()

        if not user_request:
            flash('申请不存在', 'danger')
            cur.close()
            return redirect(url_for('user_requests'))

        if user_request['status'] != '待审批':
            flash('该申请已处理', 'warning')
            cur.close()
            return redirect(url_for('user_requests'))

        # 检查用户ID是否已存在
        cur.execute("SELECT user_id FROM users WHERE user_id = %s", (user_request['user_id'],))
        if cur.fetchone():
            flash('该用户ID已存在', 'danger')
            cur.close()
            return redirect(url_for('user_requests'))

        # 创建用户，使用管理员选择的权限
        cur.execute("""
            INSERT INTO users (user_id, password, realname, permission, job_title, email, phone, remark)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (user_request['user_id'], user_request['password'], user_request['realname'],
              granted_permission, user_request['job_title'], user_request.get('email', ''),
              user_request.get('phone', ''), user_request.get('remark', '')))

        # 更新申请状态，记录授予的权限和审批人信息
        cur.execute("""
            UPDATE user_requests 
            SET status = '已批准', 
                admin_remark = CONCAT('已批准 - 授予权限: ', %s),
                approver_id = %s,
                approver_name = %s,
                approved_at = CURRENT_TIMESTAMP
            WHERE request_id = %s
        """, (granted_permission, session['user_id'], session['realname'], request_id))

        mysql.connection.commit()
        cur.close()

        logger.info(f"批准注册申请成功 - 申请ID: {request_id}, 用户ID: {user_request['user_id']}, 授予权限: {granted_permission}, 审批人: {session['user_id']}")
        flash(f'已批准用户申请！用户ID: {user_request["user_id"]}，授予权限: {granted_permission}', 'success')

    except Exception as e:
        logger.error(f"批准注册申请失败 - 申请ID: {request_id}, 错误: {str(e)}")
        flash(f'批准失败: {str(e)}', 'danger')

    return redirect(url_for('user_requests'))

@app.route('/user_requests/reject/<int:request_id>', methods=['POST'])
@admin_required
@log_operation("拒绝注册申请")
def reject_user_request(request_id):
    """拒绝注册申请"""
    try:
        admin_remark = request.form.get('admin_remark', '申请被拒绝')

        cur = mysql.connection.cursor()

        # 检查申请是否存在且未处理
        cur.execute("SELECT status FROM user_requests WHERE request_id = %s", (request_id,))
        request_data = cur.fetchone()

        if not request_data:
            flash('申请不存在', 'danger')
            cur.close()
            return redirect(url_for('user_requests'))

        if request_data['status'] != '待审批':
            flash('该申请已处理', 'warning')
            cur.close()
            return redirect(url_for('user_requests'))

        # 更新申请状态和审批人信息
        cur.execute("""
            UPDATE user_requests 
            SET status = '已拒绝', 
                admin_remark = %s,
                approver_id = %s,
                approver_name = %s,
                approved_at = CURRENT_TIMESTAMP
            WHERE request_id = %s
        """, (admin_remark, session['user_id'], session['realname'], request_id))

        mysql.connection.commit()
        cur.close()

        logger.info(f"拒绝注册申请 - 申请ID: {request_id}, 备注: {admin_remark}, 审批人: {session['user_id']}")
        flash('已拒绝用户申请', 'success')

    except Exception as e:
        logger.error(f"拒绝注册申请失败 - 申请ID: {request_id}, 错误: {str(e)}")
        flash(f'拒绝失败: {str(e)}', 'danger')

    return redirect(url_for('user_requests'))

@app.route('/user_requests/delete/<int:request_id>', methods=['POST'])
@admin_required
@log_operation("删除注册申请")
def delete_user_request(request_id):
    """删除注册申请"""
    try:
        cur = mysql.connection.cursor()

        # 只允许删除已处理（批准或拒绝）的申请
        cur.execute("SELECT status FROM user_requests WHERE request_id = %s", (request_id,))
        request_data = cur.fetchone()

        if not request_data:
            flash('申请不存在', 'danger')
            cur.close()
            return redirect(url_for('user_requests'))

        if request_data['status'] == '待审批':
            flash('不能删除待审批的申请', 'danger')
            cur.close()
            return redirect(url_for('user_requests'))

        cur.execute("DELETE FROM user_requests WHERE request_id = %s", (request_id,))

        mysql.connection.commit()
        cur.close()

        logger.info(f"删除注册申请记录 - 申请ID: {request_id}")
        flash('申请记录已删除', 'success')

    except Exception as e:
        logger.error(f"删除注册申请失败 - 申请ID: {request_id}, 错误: {str(e)}")
        flash(f'删除失败: {str(e)}', 'danger')

    return redirect(url_for('user_requests'))

# ==================== 系统日志管理 ====================
@app.route('/logs')
@admin_required
def logs():
    """日志查看页面"""
    logger.info(f"访问日志页面 - 管理员: {session['user_id']}")
    return render_template('logs.html')

@app.route('/api/logs')
@admin_required
def api_get_logs():
    """获取日志数据API"""
    try:
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 50, type=int)
        level = request.args.get('level', '')
        user_id = request.args.get('userId', '')
        operation = request.args.get('operation', '')
        keyword = request.args.get('keyword', '')
        start_time = request.args.get('start', '')
        end_time = request.args.get('end', '')

        # 读取日志文件
        log_file = 'logs/dorm_management.log'
        if not os.path.exists(log_file):
            return jsonify({
                'success': True,
                'logs': [],
                'stats': {'total': 0, 'info': 0, 'warning': 0, 'error': 0}
            })

        with open(log_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        # 反转日志行（最新的在前面）
        lines.reverse()

        # 解析和过滤日志
        parsed_logs = []
        stats = {'total': 0, 'info': 0, 'warning': 0, 'error': 0}

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # 解析日志行格式: 时间 - 模块名 - 级别 - 消息
            parts = line.split(' - ', 3)
            if len(parts) < 4:
                continue

            log_time, module, log_level, message = parts

            # 应用筛选条件
            if level and log_level != level:
                continue

            if user_id and user_id not in message:
                continue

            if operation and operation not in message:
                continue

            if keyword and keyword.lower() not in message.lower():
                continue

            if start_time and log_time < start_time:
                continue

            if end_time and log_time > end_time:
                continue

            # 统计
            stats['total'] += 1
            if log_level == 'INFO':
                stats['info'] += 1
            elif log_level == 'WARNING':
                stats['warning'] += 1
            elif log_level == 'ERROR':
                stats['error'] += 1

            parsed_logs.append({
                'time': log_time,
                'module': module,
                'level': log_level,
                'message': message
            })

        # 分页
        start = (page - 1) * limit
        end = start + limit
        paginated_logs = parsed_logs[start:end]

        return jsonify({
            'success': True,
            'logs': paginated_logs,
            'stats': stats,
            'total': len(parsed_logs),
            'page': page,
            'limit': limit
        })

    except Exception as e:
        logger.error(f"获取日志数据失败: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/logs/clear', methods=['POST'])
@admin_required
@log_operation("清空日志文件")
def api_clear_logs():
    """清空日志文件API"""
    try:
        log_file = 'logs/dorm_management.log'

        # 创建备份
        if os.path.exists(log_file):
            backup_file = f'logs/dorm_management.log.backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
            shutil.copy2(log_file, backup_file)

        # 清空日志文件
        with open(log_file, 'w', encoding='utf-8') as f:
            f.write('')

        # 记录清空操作
        logger.info(f"日志文件已清空 - 操作者: {session['user_id']}")

        return jsonify({
            'success': True,
            'message': '日志已清空'
        })

    except Exception as e:
        logger.error(f"清空日志文件失败: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/logs/download')
@admin_required
@log_operation("下载日志文件")
def api_download_logs():
    """下载日志文件API"""
    try:
        log_file = 'logs/dorm_management.log'

        if not os.path.exists(log_file):
            return jsonify({
                'success': False,
                'message': '日志文件不存在'
            }), 404

        # 记录下载操作
        logger.info(f"日志文件已下载 - 操作者: {session['user_id']}")

        return send_file(
            log_file,
            as_attachment=True,
            download_name=f'dorm_management_log_{datetime.now().strftime("%Y%m%d")}.log',
            mimetype='text/plain'
        )

    except Exception as e:
        logger.error(f"下载日志文件失败: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

# ==================== 系统状态监控 ====================
@app.route('/system/status')
@admin_required
def system_status():
    """系统状态监控页面"""
    logger.info(f"访问系统状态页面 - 管理员: {session['user_id']}")
    return render_template('system_status.html')

@app.route('/api/system/status')
@admin_required
def api_system_status():
    """获取系统状态API"""
    try:
        # 获取系统信息
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        # 获取进程运行时间
        process = psutil.Process()
        uptime = int(time.time() - process.create_time())

        # 获取数据库状态
        db_status = "正常"
        try:
            cur = mysql.connection.cursor()
            cur.execute("SELECT 1")
            cur.close()
        except Exception as e:
            db_status = f"异常: {str(e)}"

        # 获取日志文件大小
        log_size = "0 MB"
        log_file = 'logs/dorm_management.log'
        if os.path.exists(log_file):
            size_bytes = os.path.getsize(log_file)
            size_mb = size_bytes / (1024 * 1024)
            log_size = f"{size_mb:.2f} MB"

        # 获取在线用户数
        online_users = 1  # 当前用户

        # 构建系统警告
        warnings = []

        if cpu_percent > 80:
            warnings.append({
                'level': 'WARNING',
                'title': 'CPU使用率过高',
                'message': f'CPU使用率达到 {cpu_percent}%，请检查系统负载',
                'time': datetime.now().strftime('%H:%M:%S')
            })

        if memory.percent > 80:
            warnings.append({
                'level': 'WARNING',
                'title': '内存使用率过高',
                'message': f'内存使用率达到 {memory.percent}%，可用内存: {memory.available/(1024*1024*1024):.2f} GB',
                'time': datetime.now().strftime('%H:%M:%S')
            })

        if disk.percent > 85:
            warnings.append({
                'level': 'WARNING',
                'title': '磁盘空间不足',
                'message': f'磁盘使用率达到 {disk.percent}%，可用空间: {disk.free/(1024*1024*1024):.2f} GB',
                'time': datetime.now().strftime('%H:%M:%S')
            })

        # 模拟最近活动
        recent_activities = [
            {
                'user': session.get('realname', '管理员'),
                'action': '查看系统状态',
                'type': '访问',
                'time': datetime.now().strftime('%H:%M:%S')
            }
        ]

        # 模拟数据库性能
        database_performance = {
            'query_count': 156,
            'avg_response_time': 12.5,
            'error_count': 3
        }

        # 模拟性能数据
        performance_data = {
            'labels': ['10:00', '10:15', '10:30', '10:45', '11:00', '11:15'],
            'cpu': [cpu_percent, cpu_percent * 0.9, cpu_percent * 0.8, cpu_percent * 1.1, cpu_percent, cpu_percent * 0.7],
            'memory': [memory.percent, memory.percent * 0.95, memory.percent * 0.9, memory.percent * 1.05, memory.percent, memory.percent * 0.85]
        }

        return jsonify({
            'success': True,
            'uptime': uptime,
            'database_status': db_status,
            'log_size': log_size,
            'online_users': online_users,
            'server_status': {
                'cpuUsage': cpu_percent,
                'memoryUsage': memory.percent,
                'memoryTotal': memory.total,
                'memoryAvailable': memory.available,
                'diskUsage': disk.percent,
                'diskFree': disk.free,
                'system': platform.system(),
                'pythonVersion': platform.python_version()
            },
            'warnings': warnings,
            'recent_activities': recent_activities,
            'database_performance': database_performance,
            'performance_data': performance_data
        })

    except Exception as e:
        logger.error(f"获取系统状态失败: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/system/status/report')
@admin_required
@log_operation("下载系统状态报告")
def api_system_status_report():
    """下载系统状态报告"""
    try:
        # 收集系统信息
        status_data = api_system_status().get_json()

        # 创建报告内容
        report_lines = []
        report_lines.append("=" * 60)
        report_lines.append("学生公寓管理系统 - 系统状态报告")
        report_lines.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("=" * 60)

        if status_data['success']:
            report_lines.append(f"\n系统运行时间: {format_uptime(status_data['uptime'])}")
            report_lines.append(f"数据库状态: {status_data['database_status']}")
            report_lines.append(f"日志文件大小: {status_data['log_size']}")
            report_lines.append(f"在线用户数: {status_data['online_users']}")

            report_lines.append("\n服务器状态:")
            for key, value in status_data['server_status'].items():
                report_lines.append(f"  {key}: {value}")

            if status_data['warnings']:
                report_lines.append("\n系统警告:")
                for warning in status_data['warnings']:
                    report_lines.append(f"  [{warning['level']}] {warning['title']}: {warning['message']}")

            report_lines.append("\n数据库性能:")
            report_lines.append(f"  查询次数: {status_data['database_performance']['query_count']}")
            report_lines.append(f"  平均响应时间: {status_data['database_performance']['avg_response_time']} ms")
            report_lines.append(f"  错误查询数: {status_data['database_performance']['error_count']}")

        report_content = "\n".join(report_lines)

        # 创建内存文件并返回
        report_file = io.BytesIO(report_content.encode('utf-8'))

        logger.info(f"下载系统状态报告 - 操作者: {session['user_id']}")

        return send_file(
            report_file,
            as_attachment=True,
            download_name=f'system_status_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt',
            mimetype='text/plain'
        )

    except Exception as e:
        logger.error(f"生成系统状态报告失败: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

def format_uptime(seconds):
    """格式化运行时间"""
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60

    if days > 0:
        return f"{days}天{hours}小时"
    elif hours > 0:
        return f"{hours}小时{minutes}分钟"
    else:
        return f"{minutes}分钟"

# ==================== 数据库备份功能 ====================
@app.route('/backup')
@admin_required
def backup_management():
    """数据库备份管理页面"""
    logger.info(f"访问数据库备份管理 - 管理员: {session['user_id']}")
    return render_template('backup.html')

@app.route('/api/backup/create', methods=['POST'])
@admin_required
@log_operation("创建数据库备份")
def api_create_backup():
    """创建数据库备份API"""
    try:
        backup_type = request.form.get('backup_type', 'full')
        comment = request.form.get('comment', '')

        if backup_type not in ['full', 'data', 'schema']:
            return jsonify({
                'success': False,
                'message': '无效的备份类型'
            }), 400

        backup_manager = DatabaseBackup(app.config)
        result = backup_manager.create_backup(backup_type, comment)

        if result['success']:
            logger.info(f"数据库备份创建成功 - 文件: {result['filename']}, 操作者: {session['user_id']}")
        else:
            logger.error(f"数据库备份创建失败 - 错误: {result.get('error', '未知错误')}, 操作者: {session['user_id']}")

        return jsonify(result)

    except Exception as e:
        logger.error(f"创建备份API失败: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'创建备份失败: {str(e)}'
        }), 500

@app.route('/api/backup/list')
@admin_required
def api_list_backups():
    """列出备份文件API"""
    try:
        backup_manager = DatabaseBackup(app.config)
        backups = backup_manager.list_backups()

        return jsonify({
            'success': True,
            'backups': backups,
            'count': len(backups)
        })

    except Exception as e:
        logger.error(f"列出备份文件失败: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'列出备份文件失败: {str(e)}'
        }), 500

@app.route('/api/backup/delete/<filename>', methods=['POST'])
@admin_required
@log_operation("删除数据库备份")
def api_delete_backup(filename):
    """删除备份文件API"""
    try:
        backup_manager = DatabaseBackup(app.config)
        result = backup_manager.delete_backup(filename)

        if result['success']:
            logger.info(f"删除备份文件成功 - 文件: {filename}, 操作者: {session['user_id']}")
        else:
            logger.warning(f"删除备份文件失败 - 文件: {filename}, 错误: {result.get('message', '未知错误')}")

        return jsonify(result)

    except Exception as e:
        logger.error(f"删除备份文件API失败: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'删除备份文件失败: {str(e)}'
        }), 500

@app.route('/api/backup/info/<filename>')
@admin_required
def api_get_backup_info(filename):
    """获取备份文件信息API"""
    try:
        backup_manager = DatabaseBackup(app.config)
        info = backup_manager.get_backup_info(filename)

        if info:
            return jsonify({
                'success': True,
                'info': info
            })
        else:
            return jsonify({
                'success': False,
                'message': '备份文件不存在'
            }), 404

    except Exception as e:
        logger.error(f"获取备份文件信息失败: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'获取备份文件信息失败: {str(e)}'
        }), 500

@app.route('/api/backup/disk-usage')
@admin_required
def api_get_disk_usage():
    """获取备份磁盘使用情况API"""
    try:
        backup_manager = DatabaseBackup(app.config)
        usage = backup_manager.get_disk_usage()

        return jsonify({
            'success': True,
            'usage': usage
        })

    except Exception as e:
        logger.error(f"获取磁盘使用情况失败: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'获取磁盘使用情况失败: {str(e)}'
        }), 500

@app.route('/api/backup/download/<filename>')
@admin_required
@log_operation("下载数据库备份")
def api_download_backup(filename):
    """下载备份文件API"""
    try:
        backup_dir = Path("backups")
        backup_file = backup_dir / filename

        if not backup_file.exists():
            flash('备份文件不存在', 'danger')
            return redirect(url_for('backup_management'))

        logger.info(f"下载备份文件 - 文件: {filename}, 操作者: {session['user_id']}")

        return send_file(
            str(backup_file),
            as_attachment=True,
            download_name=filename,
            mimetype='application/zip'
        )

    except Exception as e:
        logger.error(f"下载备份文件失败: {str(e)}")
        flash(f'下载备份文件失败: {str(e)}', 'danger')
        return redirect(url_for('backup_management'))

@app.route('/api/backup/restore/<filename>', methods=['POST'])
@admin_required
@log_operation("恢复数据库备份")
def api_restore_backup(filename):
    """恢复数据库备份API"""
    try:
        # 确认操作
        confirm = request.form.get('confirm', 'no')
        if confirm != 'yes':
            return jsonify({
                'success': False,
                'message': '需要确认恢复操作'
            }), 400

        backup_manager = DatabaseBackup(app.config)
        result = backup_manager.restore_backup(f"backups/{filename}")

        if result['success']:
            logger.warning(f"数据库恢复成功 - 文件: {filename}, 操作者: {session['user_id']}")
            logger.warning(f"数据库已从备份恢复，操作者: {session['user_id']}")
        else:
            logger.error(f"数据库恢复失败 - 文件: {filename}, 错误: {result.get('message', '未知错误')}")

        return jsonify(result)

    except Exception as e:
        logger.error(f"恢复备份API失败: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'恢复备份失败: {str(e)}'
        }), 500

# ==================== 自动备份管理 ====================
@app.route('/auto_backup')
@admin_required
def auto_backup_management():
    """自动备份管理页面"""
    logger.info(f"访问自动备份管理 - 管理员: {session['user_id']}")

    # 获取调度器状态
    status = auto_backup_scheduler.get_status()

    # 获取备份统计
    stats = auto_backup_scheduler.get_backup_stats()

    return render_template('auto_backup.html',
                           status=status,
                           stats=stats)

@app.route('/api/auto_backup/status')
@admin_required
def api_auto_backup_status():
    """获取自动备份状态API"""
    try:
        status = auto_backup_scheduler.get_status()
        stats = auto_backup_scheduler.get_backup_stats()

        return jsonify({
            'success': True,
            'status': status,
            'stats': stats
        })

    except Exception as e:
        logger.error(f"获取自动备份状态失败: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'获取状态失败: {str(e)}'
        }), 500

@app.route('/api/auto_backup/start', methods=['POST'])
@admin_required
@log_operation("启动自动备份")
def api_start_auto_backup():
    """启动自动备份API"""
    try:
        success = auto_backup_scheduler.start()

        if success:
            logger.info(f"手动启动自动备份 - 操作者: {session['user_id']}")
            return jsonify({
                'success': True,
                'message': '自动备份已启动'
            })
        else:
            return jsonify({
                'success': False,
                'message': '启动自动备份失败'
            })

    except Exception as e:
        logger.error(f"启动自动备份失败: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'启动失败: {str(e)}'
        }), 500

@app.route('/api/auto_backup/stop', methods=['POST'])
@admin_required
@log_operation("停止自动备份")
def api_stop_auto_backup():
    """停止自动备份API"""
    try:
        success = auto_backup_scheduler.stop()

        if success:
            logger.info(f"手动停止自动备份 - 操作者: {session['user_id']}")
            return jsonify({
                'success': True,
                'message': '自动备份已停止'
            })
        else:
            return jsonify({
                'success': False,
                'message': '停止自动备份失败'
            })

    except Exception as e:
        logger.error(f"停止自动备份失败: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'停止失败: {str(e)}'
        }), 500

@app.route('/api/auto_backup/restart', methods=['POST'])
@admin_required
@log_operation("重启自动备份")
def api_restart_auto_backup():
    """重启自动备份API"""
    try:
        success = auto_backup_scheduler.restart()

        if success:
            logger.info(f"手动重启自动备份 - 操作者: {session['user_id']}")
            return jsonify({
                'success': True,
                'message': '自动备份已重启'
            })
        else:
            return jsonify({
                'success': False,
                'message': '重启自动备份失败'
            })

    except Exception as e:
        logger.error(f"重启自动备份失败: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'重启失败: {str(e)}'
        }), 500

@app.route('/api/auto_backup/backup_now', methods=['POST'])
@admin_required
@log_operation("立即执行备份")
def api_backup_now():
    """立即执行备份API"""
    try:
        result = auto_backup_scheduler.manual_backup_now()

        if result['success']:
            logger.info(f"手动执行立即备份 - 操作者: {session['user_id']}")

        return jsonify(result)

    except Exception as e:
        logger.error(f"立即备份执行失败: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'立即备份失败: {str(e)}'
        }), 500

@app.route('/api/auto_backup/settings', methods=['GET', 'POST'])
@admin_required
def api_auto_backup_settings():
    """自动备份设置API"""
    if request.method == 'GET':
        try:
            status = auto_backup_scheduler.get_status()
            return jsonify({
                'success': True,
                'settings': status['settings']
            })
        except Exception as e:
            logger.error(f"获取自动备份设置失败: {str(e)}")
            return jsonify({
                'success': False,
                'message': f'获取设置失败: {str(e)}'
            }), 500

    elif request.method == 'POST':
        try:
            settings = request.json

            if not settings:
                return jsonify({
                    'success': False,
                    'message': '设置数据不能为空'
                }), 400

            # 验证时间格式
            if 'time' in settings:
                import re
                if not re.match(r'^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$', settings['time']):
                    return jsonify({
                        'success': False,
                        'message': '时间格式不正确，应为 HH:MM'
                    }), 400

            # 验证备份类型
            if 'backup_type' in settings:
                if settings['backup_type'] not in ['full', 'data', 'schema']:
                    return jsonify({
                        'success': False,
                        'message': '备份类型不正确'
                    }), 400

            # 更新设置
            success = auto_backup_scheduler.update_settings(settings)

            if success:
                logger.info(f"更新自动备份设置 - 操作者: {session['user_id']}, 设置: {settings}")
                return jsonify({
                    'success': True,
                    'message': '设置已更新'
                })
            else:
                return jsonify({
                    'success': False,
                    'message': '更新设置失败'
                })

        except Exception as e:
            logger.error(f"更新自动备份设置失败: {str(e)}")
            return jsonify({
                'success': False,
                'message': f'更新设置失败: {str(e)}'
            }), 500

@app.route('/api/auto_backup/history')
@admin_required
def api_auto_backup_history():
    """获取备份历史API"""
    try:
        history = auto_backup_scheduler._get_backup_history()

        # 反转顺序，最新的在前面
        history.reverse()

        return jsonify({
            'success': True,
            'history': history,
            'count': len(history)
        })

    except Exception as e:
        logger.error(f"获取备份历史失败: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'获取历史失败: {str(e)}'
        }), 500

# ==================== 应用启动 ====================
if __name__ == '__main__':
    # 记录应用启动
    logger.info("=" * 50)
    logger.info("学生公寓交费管理系统启动")
    logger.info(f"启动时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"日志目录: {os.path.abspath('logs')}")
    logger.info(f"备份目录: {os.path.abspath('backups')}")
    logger.info(f"数据库配置: {app.config['MYSQL_DB']}@{app.config['MYSQL_HOST']}")
    logger.info("=" * 50)

    # 创建必要的模板文件
    try:
        # 检查是否缺少必要的模板文件
        required_templates = ['logs.html', 'system_status.html', 'auto_backup.html', 'backup.html']
        for template in required_templates:
            template_path = os.path.join('templates', template)
            if not os.path.exists(template_path):
                logger.warning(f"缺少模板文件: {template}，请确保已创建")
    except Exception as e:
        logger.error(f"检查模板文件失败: {str(e)}")

    # 初始化自动备份
    logger.info("初始化自动备份功能...")
    init_auto_backup()

    # 添加优雅关闭处理
    import signal

    def shutdown_handler(signum, frame):
        logger.info("接收到关闭信号，正在停止自动备份调度器...")
        auto_backup_scheduler.stop()
        logger.info("系统正在关闭...")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    app.run(debug=True, host='0.0.0.0', port=5000)