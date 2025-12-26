"""
学生公寓交费管理系统 - Flask应用
作者: William
日期: 2025
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
import hashlib
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'

# MySQL配置
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'MySQL'
app.config['MYSQL_DB'] = 'dorm_management'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)


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


def generate_next_user_id():
    """生成下一个用户ID，格式：U + 年月(4位) + 4位顺序号"""
    cur = mysql.connection.cursor()

    # 获取当前年月
    current_year_month = datetime.now().strftime("%y%m")  # 格式：2501（25年1月）

    # 查询当前年月最大的用户ID
    cur.execute("""
        SELECT user_id FROM users 
        WHERE user_id LIKE %s 
        ORDER BY user_id DESC 
        LIMIT 1
    """, (f'U{current_year_month}%',))

    result = cur.fetchone()
    cur.close()

    if result:
        last_id = result['user_id']
        # 提取最后4位数字
        last_number = int(last_id[-4:])
        next_number = last_number + 1
    else:
        # 该年月还没有用户，从0001开始
        next_number = 1

    # 格式化为4位数字，例如：0001, 0002, ... 9999
    next_user_id = f'U{current_year_month}{next_number:04d}'

    # 如果超过9999，则使用更大的数字，但保持4位显示
    if next_number > 9999:
        next_user_id = f'U{current_year_month}{next_number}'

    return next_user_id


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


# ==================== 认证路由 ====================

@app.route('/')
def index():
    """首页"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """登录 - 使用用户ID登录"""
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        password = request.form.get('password')

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
        user = cur.fetchone()
        cur.close()

        if user and verify_password(user['password'], password):
            session['user_id'] = user['user_id']
            session['username'] = user['username']
            session['realname'] = user['realname']
            session['permission'] = user['permission']
            flash(f'欢迎回来，{user["realname"]}！', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('用户ID或密码错误', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    """退出登录"""
    session.clear()
    flash('已退出登录', 'info')
    return redirect(url_for('login'))


# ==================== 仪表板 ====================

@app.route('/dashboard')
@login_required
def dashboard():
    """仪表板"""
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


# ==================== 学生管理 ====================

@app.route('/students')
@login_required
def students():
    """学生列表"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    per_page = 15

    cur = mysql.connection.cursor()

    if search:
        cur.execute("""
            SELECT s.*, 
                   (SELECT COUNT(*) FROM payments WHERE student_id = s.student_id) as payment_count,
                   (SELECT SUM(amount) FROM payments WHERE student_id = s.student_id) as total_paid
            FROM students s
            WHERE s.student_id LIKE %s OR s.name LIKE %s OR s.major LIKE %s OR s.class LIKE %s
            ORDER BY s.student_id
        """, (f'%{search}%', f'%{search}%', f'%{search}%', f'%{search}%'))
    else:
        cur.execute("""
            SELECT s.*, 
                   (SELECT COUNT(*) FROM payments WHERE student_id = s.student_id) as payment_count,
                   (SELECT SUM(amount) FROM payments WHERE student_id = s.student_id) as total_paid
            FROM students s
            ORDER BY s.student_id
        """)

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

    return render_template('students.html',
                           students=students_page,
                           page=page,
                           total_pages=total_pages,
                           search=search,
                           buildings=buildings,
                           rooms=rooms)


@app.route('/students/add', methods=['POST'])
@login_required
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

        flash('学生信息添加成功', 'success')
    except Exception as e:
        flash(f'添加失败: {str(e)}', 'danger')

    return redirect(url_for('students'))


@app.route('/students/edit/<student_id>', methods=['POST'])
@login_required
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

        flash('学生信息更新成功', 'success')
    except Exception as e:
        flash(f'更新失败: {str(e)}', 'danger')

    return redirect(url_for('students'))


@app.route('/students/delete/<student_id>', methods=['POST'])
@login_required
def delete_student(student_id):
    """删除学生"""
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM students WHERE student_id = %s", (student_id,))
        mysql.connection.commit()
        cur.close()

        flash('学生信息删除成功', 'success')
    except Exception as e:
        flash(f'删除失败: {str(e)}', 'danger')

    return redirect(url_for('students'))


# ==================== 公寓楼管理 ====================

@app.route('/buildings')
@login_required
def buildings():
    """公寓楼列表"""
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT b.*,
               (SELECT COUNT(*) FROM rooms WHERE building_id = b.building_id) as actual_rooms,
               (SELECT COUNT(*) FROM students WHERE building_id = b.building_id) as student_count
        FROM buildings b
        ORDER BY b.building_id
    """)
    buildings_list = cur.fetchall()
    cur.close()

    return render_template('buildings.html', buildings=buildings_list)


@app.route('/buildings/add', methods=['POST'])
@login_required
def add_building():
    """添加公寓楼"""
    try:
        building_id = request.form.get('building_id')
        floors = request.form.get('floors', type=int)
        rooms_count = request.form.get('rooms_count', type=int)
        commission_date = request.form.get('commission_date')

        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO buildings (building_id, floors, rooms_count, commission_date)
            VALUES (%s, %s, %s, %s)
        """, (building_id, floors, rooms_count, commission_date))

        mysql.connection.commit()
        cur.close()

        flash('公寓楼添加成功', 'success')
    except Exception as e:
        flash(f'添加失败: {str(e)}', 'danger')

    return redirect(url_for('buildings'))


@app.route('/buildings/edit/<building_id>', methods=['POST'])
@login_required
def edit_building(building_id):
    """编辑公寓楼"""
    try:
        floors = request.form.get('floors', type=int)
        rooms_count = request.form.get('rooms_count', type=int)
        commission_date = request.form.get('commission_date')

        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE buildings 
            SET floors=%s, rooms_count=%s, commission_date=%s
            WHERE building_id=%s
        """, (floors, rooms_count, commission_date, building_id))

        mysql.connection.commit()
        cur.close()

        flash('公寓楼信息更新成功', 'success')
    except Exception as e:
        flash(f'更新失败: {str(e)}', 'danger')

    return redirect(url_for('buildings'))


@app.route('/buildings/delete/<building_id>', methods=['POST'])
@login_required
def delete_building(building_id):
    """删除公寓楼"""
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM buildings WHERE building_id = %s", (building_id,))
        mysql.connection.commit()
        cur.close()

        flash('公寓楼删除成功', 'success')
    except Exception as e:
        flash(f'删除失败: {str(e)}', 'danger')

    return redirect(url_for('buildings'))


# ==================== 寝室管理 ====================

@app.route('/rooms')
@login_required
def rooms():
    """寝室列表"""
    building_filter = request.args.get('building', '')

    cur = mysql.connection.cursor()

    if building_filter:
        cur.execute("""
            SELECT r.*,
                   (SELECT COUNT(*) FROM students WHERE room_id = r.room_id) as current_occupancy,
                   r.capacity - (SELECT COUNT(*) FROM students WHERE room_id = r.room_id) as available_beds
            FROM rooms r
            WHERE r.building_id = %s
            ORDER BY r.room_id
        """, (building_filter,))
    else:
        cur.execute("""
            SELECT r.*,
                   (SELECT COUNT(*) FROM students WHERE room_id = r.room_id) as current_occupancy,
                   r.capacity - (SELECT COUNT(*) FROM students WHERE room_id = r.room_id) as available_beds
            FROM rooms r
            ORDER BY r.room_id
        """)

    rooms_list = cur.fetchall()

    cur.execute("SELECT building_id FROM buildings ORDER BY building_id")
    buildings = cur.fetchall()

    cur.close()

    return render_template('rooms.html', rooms=rooms_list, buildings=buildings, building_filter=building_filter)


@app.route('/rooms/add', methods=['POST'])
@login_required
def add_room():
    """添加寝室"""
    try:
        room_id = request.form.get('room_id')
        building_id = request.form.get('building_id')
        capacity = request.form.get('capacity', type=int)
        fee = request.form.get('fee', type=float)
        phone = request.form.get('phone')

        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO rooms (room_id, building_id, capacity, fee, phone)
            VALUES (%s, %s, %s, %s, %s)
        """, (room_id, building_id, capacity, fee, phone))

        mysql.connection.commit()
        cur.close()

        flash('寝室添加成功', 'success')
    except Exception as e:
        flash(f'添加失败: {str(e)}', 'danger')

    return redirect(url_for('rooms'))


@app.route('/rooms/edit/<room_id>', methods=['POST'])
@login_required
def edit_room(room_id):
    """编辑寝室"""
    try:
        building_id = request.form.get('building_id')
        capacity = request.form.get('capacity', type=int)
        fee = request.form.get('fee', type=float)
        phone = request.form.get('phone')

        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE rooms 
            SET building_id=%s, capacity=%s, fee=%s, phone=%s
            WHERE room_id=%s
        """, (building_id, capacity, fee, phone, room_id))

        mysql.connection.commit()
        cur.close()

        flash('寝室信息更新成功', 'success')
    except Exception as e:
        flash(f'更新失败: {str(e)}', 'danger')

    return redirect(url_for('rooms'))


@app.route('/rooms/delete/<room_id>', methods=['POST'])
@login_required
def delete_room(room_id):
    """删除寝室"""
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM rooms WHERE room_id = %s", (room_id,))
        mysql.connection.commit()
        cur.close()

        flash('寝室删除成功', 'success')
    except Exception as e:
        flash(f'删除失败: {str(e)}', 'danger')

    return redirect(url_for('rooms'))


# ==================== 交费管理 ====================

@app.route('/payments')
@login_required
def payments():
    """交费记录列表"""
    page = request.args.get('page', 1, type=int)
    student_id = request.args.get('student_id', '')
    payment_type = request.args.get('payment_type', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    per_page = 15

    cur = mysql.connection.cursor()

    query = """
        SELECT p.*, s.name as student_name, s.major, s.class
        FROM payments p
        JOIN students s ON p.student_id = s.student_id
        WHERE 1=1
    """
    params = []

    if student_id:
        query += " AND p.student_id LIKE %s"
        params.append(f'%{student_id}%')

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

    return render_template('payments.html',
                           payments=payments_page,
                           page=page,
                           total_pages=total_pages,
                           total_amount=total_amount,
                           students=students,
                           buildings=buildings,
                           rooms=rooms,
                           filters={'student_id': student_id, 'payment_type': payment_type,
                                    'start_date': start_date, 'end_date': end_date})


@app.route('/payments/add', methods=['POST'])
@login_required
def add_payment():
    """添加交费记录"""
    try:
        student_id = request.form.get('student_id')
        payment_date = request.form.get('payment_date')
        payment_type = request.form.get('payment_type')
        amount = request.form.get('amount', type=float)
        remark = request.form.get('remark', '')

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

        flash('交费记录添加成功', 'success')
    except Exception as e:
        flash(f'添加失败: {str(e)}', 'danger')

    return redirect(url_for('payments'))


@app.route('/payments/delete/<int:payment_id>', methods=['POST'])
@login_required
def delete_payment(payment_id):
    """删除交费记录"""
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM payments WHERE payment_id = %s", (payment_id,))
        mysql.connection.commit()
        cur.close()

        flash('交费记录删除成功', 'success')
    except Exception as e:
        flash(f'删除失败: {str(e)}', 'danger')

    return redirect(url_for('payments'))


# ==================== 统计报表 ====================

@app.route('/reports')
@login_required
def reports():
    """统计报表"""
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
            COUNT(DISTINCT s.student_id) as student_count,
            COUNT(DISTINCT p.payment_id) as payment_count,
            COALESCE(SUM(p.amount), 0) as total_amount
        FROM buildings b
        LEFT JOIN students s ON b.building_id = s.building_id
        LEFT JOIN payments p ON b.building_id = p.building_id
        GROUP BY b.building_id
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

    # 欠费学生（假设每学期住宿费1200，已到期但未交费的）
    cur.execute("""
        SELECT s.student_id, s.name, s.major, s.class, s.building_id, s.room_id,
               COALESCE(SUM(p.amount), 0) as paid_amount,
               r.fee as should_pay
        FROM students s
        LEFT JOIN rooms r ON s.room_id = r.room_id
        LEFT JOIN payments p ON s.student_id = p.student_id AND p.payment_type = '住宿费'
        GROUP BY s.student_id, s.name, s.major, s.class, s.building_id, s.room_id, r.fee
        HAVING paid_amount < should_pay OR paid_amount IS NULL
        ORDER BY s.student_id
        LIMIT 20
    """)
    arrears_students = cur.fetchall()

    cur.close()

    return render_template('reports.html',
                           monthly_stats=monthly_stats,
                           building_stats=building_stats,
                           major_stats=major_stats,
                           arrears_students=arrears_students)


# ==================== 用户管理 ====================

@app.route('/users')
@admin_required
def users():
    """用户管理"""
    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id, username, realname, permission, created_at FROM users ORDER BY user_id")
    users_list = cur.fetchall()

    # 获取待审批数量
    cur.execute("SELECT COUNT(*) as count FROM user_requests WHERE status = '待审批'")
    pending_count = cur.fetchone()['count']

    cur.close()

    # 生成下一个用户ID用于前端显示
    next_user_id = generate_next_user_id()

    return render_template('users.html',
                           users=users_list,
                           next_user_id=next_user_id,
                           pending_requests_count=pending_count)


@app.route('/users/add', methods=['POST'])
@admin_required
def add_user():
    """添加用户"""
    try:
        # 不再需要前端传入user_id，改为自动生成
        username = request.form.get('username')
        password = request.form.get('password')
        realname = request.form.get('realname')
        permission = request.form.get('permission')

        if not username or not password or not realname:
            flash('请填写完整信息', 'danger')
            return redirect(url_for('users'))

        hashed_password = hash_password(password)

        cur = mysql.connection.cursor()

        # 检查用户名是否已存在
        cur.execute("SELECT username FROM users WHERE username = %s", (username,))
        if cur.fetchone():
            flash('用户名已存在', 'danger')
            cur.close()
            return redirect(url_for('users'))

        # 生成用户ID
        user_id = generate_next_user_id()

        cur.execute("""
            INSERT INTO users (user_id, username, password, realname, permission)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, username, hashed_password, realname, permission))

        mysql.connection.commit()
        cur.close()

        flash(f'用户添加成功！用户ID: {user_id}，请告知用户使用此ID登录', 'success')
    except Exception as e:
        flash(f'添加失败: {str(e)}', 'danger')

    return redirect(url_for('users'))


@app.route('/users/edit/<user_id>', methods=['POST'])
@admin_required
def edit_user(user_id):
    """编辑用户"""
    try:
        realname = request.form.get('realname')
        permission = request.form.get('permission')
        password = request.form.get('password')

        cur = mysql.connection.cursor()

        if password:
            hashed_password = hash_password(password)
            cur.execute("""
                UPDATE users 
                SET realname=%s, permission=%s, password=%s
                WHERE user_id=%s
            """, (realname, permission, hashed_password, user_id))
        else:
            cur.execute("""
                UPDATE users 
                SET realname=%s, permission=%s
                WHERE user_id=%s
            """, (realname, permission, user_id))

        mysql.connection.commit()
        cur.close()

        flash('用户信息更新成功', 'success')
    except Exception as e:
        flash(f'更新失败: {str(e)}', 'danger')

    return redirect(url_for('users'))


@app.route('/users/delete/<user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    """删除用户"""
    if user_id == session.get('user_id'):
        flash('不能删除当前登录用户', 'danger')
        return redirect(url_for('users'))

    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
        mysql.connection.commit()
        cur.close()

        flash('用户删除成功', 'success')
    except Exception as e:
        flash(f'删除失败: {str(e)}', 'danger')

    return redirect(url_for('users'))


# ==================== API接口 ====================

@app.route('/api/rooms/<building_id>')
@login_required
def api_get_rooms(building_id):
    """获取指定楼栋的房间"""
    cur = mysql.connection.cursor()
    cur.execute("SELECT room_id, capacity, fee FROM rooms WHERE building_id = %s ORDER BY room_id", (building_id,))
    rooms = cur.fetchall()
    cur.close()
    return jsonify(rooms)


@app.route('/api/student/<student_id>')
@login_required
def api_get_student(student_id):
    """获取学生信息"""
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM students WHERE student_id = %s", (student_id,))
    student = cur.fetchone()
    cur.close()
    if student:
        return jsonify(student)
    return jsonify({'error': 'Student not found'}), 404


# ==================== 用户注册功能 ====================

@app.route('/register', methods=['GET', 'POST'])
def register():
    """用户注册页面"""
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            password = request.form.get('password')
            password_confirm = request.form.get('password_confirm')
            realname = request.form.get('realname')
            permission = request.form.get('permission', '教师')
            email = request.form.get('email', '')
            phone = request.form.get('phone', '')

            # 验证输入
            if not username or not password or not realname:
                flash('请填写必填项', 'danger')
                return redirect(url_for('register'))

            if password != password_confirm:
                flash('两次输入的密码不一致', 'danger')
                return redirect(url_for('register'))

            if len(password) < 6:
                flash('密码长度至少6位', 'danger')
                return redirect(url_for('register'))

            cur = mysql.connection.cursor()

            # 检查用户名是否已存在（在users表或user_requests表中）
            cur.execute("SELECT username FROM users WHERE username = %s", (username,))
            if cur.fetchone():
                flash('用户名已存在', 'danger')
                cur.close()
                return redirect(url_for('register'))

            cur.execute("SELECT username FROM user_requests WHERE username = %s AND status = '待审批'", (username,))
            if cur.fetchone():
                flash('该用户名已提交注册申请，请等待审批', 'warning')
                cur.close()
                return redirect(url_for('register'))

            # 加密密码
            hashed_password = hash_password(password)

            # 插入注册申请
            cur.execute("""
                INSERT INTO user_requests (username, password, realname, permission, email, phone, status)
                VALUES (%s, %s, %s, %s, %s, %s, '待审批')
            """, (username, hashed_password, realname, permission, email, phone))

            mysql.connection.commit()
            cur.close()

            flash('注册申请已提交，请等待管理员审批。审批通过后您将收到通知。', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            flash(f'注册失败: {str(e)}', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')


# ==================== 注册审批管理 ====================

@app.route('/user_requests')
@admin_required
def user_requests():
    """查看待审批的注册申请"""
    status_filter = request.args.get('status', '待审批')

    cur = mysql.connection.cursor()

    if status_filter == '全部':
        cur.execute("""
            SELECT * FROM user_requests 
            ORDER BY 
                CASE status 
                    WHEN '待审批' THEN 1
                    WHEN '已批准' THEN 2
                    WHEN '已拒绝' THEN 3
                END, created_at DESC
        """)
    else:
        cur.execute("""
            SELECT * FROM user_requests 
            WHERE status = %s 
            ORDER BY created_at DESC
        """, (status_filter,))

    requests_list = cur.fetchall()
    cur.close()

    return render_template('user_requests.html',
                           requests=requests_list,
                           status_filter=status_filter)


@app.route('/user_requests/approve/<int:request_id>', methods=['POST'])
@admin_required
def approve_user_request(request_id):
    """批准注册申请"""
    try:
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

        # 检查用户名是否已存在
        cur.execute("SELECT username FROM users WHERE username = %s", (user_request['username'],))
        if cur.fetchone():
            flash('用户名已存在，请拒绝此申请', 'danger')
            cur.close()
            return redirect(url_for('user_requests'))

        # 生成用户ID
        user_id = generate_next_user_id()

        # 创建用户
        cur.execute("""
            INSERT INTO users (user_id, username, password, realname, permission, email, phone)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (user_id, user_request['username'], user_request['password'],
              user_request['realname'], user_request['permission'],
              user_request.get('email', ''), user_request.get('phone', '')))

        # 更新申请状态
        cur.execute("""
            UPDATE user_requests 
            SET status = '已批准', 
                remark = '已批准 - 用户ID: %s' 
            WHERE request_id = %s
        """, (user_id, request_id))

        mysql.connection.commit()
        cur.close()

        flash(f'已批准用户申请！新用户ID: {user_id}', 'success')

    except Exception as e:
        flash(f'批准失败: {str(e)}', 'danger')

    return redirect(url_for('user_requests'))


@app.route('/user_requests/reject/<int:request_id>', methods=['POST'])
@admin_required
def reject_user_request(request_id):
    """拒绝注册申请"""
    try:
        remark = request.form.get('remark', '申请被拒绝')

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

        # 更新申请状态
        cur.execute("""
            UPDATE user_requests 
            SET status = '已拒绝', remark = %s 
            WHERE request_id = %s
        """, (remark, request_id))

        mysql.connection.commit()
        cur.close()

        flash('已拒绝用户申请', 'success')

    except Exception as e:
        flash(f'拒绝失败: {str(e)}', 'danger')

    return redirect(url_for('user_requests'))


@app.route('/user_requests/delete/<int:request_id>', methods=['POST'])
@admin_required
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

        flash('申请记录已删除', 'success')

    except Exception as e:
        flash(f'删除失败: {str(e)}', 'danger')

    return redirect(url_for('user_requests'))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)



# """
# 学生公寓交费管理系统 - Flask应用
# 作者: William
# 日期: 2025
# """
#
# from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
# from flask_mysqldb import MySQL
# from werkzeug.security import generate_password_hash, check_password_hash
# from functools import wraps
# from datetime import datetime, timedelta
# import hashlib
# import os
#
# app = Flask(__name__)
# app.secret_key = 'your-secret-key-change-in-production'
#
# # MySQL配置
# app.config['MYSQL_HOST'] = 'localhost'
# app.config['MYSQL_USER'] = 'root'
# app.config['MYSQL_PASSWORD'] = 'MySQL'
# app.config['MYSQL_DB'] = 'dorm_management'
# app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
#
# mysql = MySQL(app)
#
#
# # ==================== 辅助函数 ====================
#
# def hash_password(password):
#     """密码加密"""
#     salt = 'salt'
#     return f"sha256${salt}${hashlib.sha256(password.encode()).hexdigest()}"
#
#
# def verify_password(stored_password, provided_password):
#     """验证密码"""
#     if stored_password.startswith('sha256$'):
#         parts = stored_password.split('$')
#         salt = parts[1]
#         stored_hash = parts[2]
#         new_hash = hashlib.sha256(provided_password.encode()).hexdigest()
#         return stored_hash == new_hash
#     return False
#
#
# def login_required(f):
#     """登录验证装饰器"""
#
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if 'user_id' not in session:
#             flash('请先登录', 'warning')
#             return redirect(url_for('login'))
#         return f(*args, **kwargs)
#
#     return decorated_function
#
#
# def admin_required(f):
#     """管理员权限验证装饰器"""
#
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if 'user_id' not in session:
#             flash('请先登录', 'warning')
#             return redirect(url_for('login'))
#         if session.get('permission') != '管理员':
#             flash('需要管理员权限', 'danger')
#             return redirect(url_for('index'))
#         return f(*args, **kwargs)
#
#     return decorated_function
#
#
# # ==================== 认证路由 ====================
#
# @app.route('/')
# def index():
#     """首页"""
#     if 'user_id' not in session:
#         return redirect(url_for('login'))
#     return redirect(url_for('dashboard'))
#
#
# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     """登录"""
#     if request.method == 'POST':
#         username = request.form.get('username')
#         password = request.form.get('password')
#
#         cur = mysql.connection.cursor()
#         cur.execute("SELECT * FROM users WHERE username = %s", (username,))
#         user = cur.fetchone()
#         cur.close()
#
#         if user and verify_password(user['password'], password):
#             session['user_id'] = user['user_id']
#             session['username'] = user['username']
#             session['realname'] = user['realname']
#             session['permission'] = user['permission']
#             flash(f'欢迎回来，{user["realname"]}！', 'success')
#             return redirect(url_for('dashboard'))
#         else:
#             flash('用户名或密码错误', 'danger')
#
#     return render_template('login.html')
#
#
# @app.route('/logout')
# def logout():
#     """退出登录"""
#     session.clear()
#     flash('已退出登录', 'info')
#     return redirect(url_for('login'))
#
#
# # ==================== 仪表板 ====================
#
# @app.route('/dashboard')
# @login_required
# def dashboard():
#     """仪表板"""
#     cur = mysql.connection.cursor()
#
#     # 统计数据
#     cur.execute("SELECT COUNT(*) as count FROM students")
#     student_count = cur.fetchone()['count']
#
#     cur.execute("SELECT COUNT(*) as count FROM buildings")
#     building_count = cur.fetchone()['count']
#
#     cur.execute("SELECT COUNT(*) as count FROM rooms")
#     room_count = cur.fetchone()['count']
#
#     cur.execute("SELECT COUNT(*) as count FROM payments WHERE MONTH(payment_date) = MONTH(CURDATE())")
#     month_payment_count = cur.fetchone()['count']
#
#     cur.execute("SELECT SUM(amount) as total FROM payments WHERE MONTH(payment_date) = MONTH(CURDATE())")
#     month_total = cur.fetchone()['total'] or 0
#
#     # 最近交费记录
#     cur.execute("""
#         SELECT p.*, s.name as student_name
#         FROM payments p
#         JOIN students s ON p.student_id = s.student_id
#         ORDER BY p.payment_date DESC, p.payment_id DESC
#         LIMIT 10
#     """)
#     recent_payments = cur.fetchall()
#
#     # 月度统计
#     cur.execute("""
#         SELECT
#             DATE_FORMAT(payment_date, '%Y-%m') as month,
#             COUNT(*) as count,
#             SUM(amount) as total
#         FROM payments
#         WHERE payment_date >= DATE_SUB(CURDATE(), INTERVAL 6 MONTH)
#         GROUP BY DATE_FORMAT(payment_date, '%Y-%m')
#         ORDER BY month DESC
#     """)
#     monthly_stats = cur.fetchall()
#
#     cur.close()
#
#     return render_template('dashboard.html',
#                            student_count=student_count,
#                            building_count=building_count,
#                            room_count=room_count,
#                            month_payment_count=month_payment_count,
#                            month_total=month_total,
#                            recent_payments=recent_payments,
#                            monthly_stats=monthly_stats)
#
#
# # ==================== 学生管理 ====================
#
# @app.route('/students')
# @login_required
# def students():
#     """学生列表"""
#     page = request.args.get('page', 1, type=int)
#     search = request.args.get('search', '')
#     per_page = 15
#
#     cur = mysql.connection.cursor()
#
#     if search:
#         cur.execute("""
#             SELECT s.*,
#                    (SELECT COUNT(*) FROM payments WHERE student_id = s.student_id) as payment_count,
#                    (SELECT SUM(amount) FROM payments WHERE student_id = s.student_id) as total_paid
#             FROM students s
#             WHERE s.student_id LIKE %s OR s.name LIKE %s OR s.major LIKE %s OR s.class LIKE %s
#             ORDER BY s.student_id
#         """, (f'%{search}%', f'%{search}%', f'%{search}%', f'%{search}%'))
#     else:
#         cur.execute("""
#             SELECT s.*,
#                    (SELECT COUNT(*) FROM payments WHERE student_id = s.student_id) as payment_count,
#                    (SELECT SUM(amount) FROM payments WHERE student_id = s.student_id) as total_paid
#             FROM students s
#             ORDER BY s.student_id
#         """)
#
#     all_students = cur.fetchall()
#     total = len(all_students)
#
#     # 分页
#     start = (page - 1) * per_page
#     end = start + per_page
#     students_page = all_students[start:end]
#
#     total_pages = (total + per_page - 1) // per_page
#
#     # 获取楼栋和房间
#     cur.execute("SELECT building_id FROM buildings ORDER BY building_id")
#     buildings = cur.fetchall()
#
#     cur.execute("SELECT room_id, building_id FROM rooms ORDER BY room_id")
#     rooms = cur.fetchall()
#
#     cur.close()
#
#     return render_template('students.html',
#                            students=students_page,
#                            page=page,
#                            total_pages=total_pages,
#                            search=search,
#                            buildings=buildings,
#                            rooms=rooms)
#
#
# @app.route('/students/add', methods=['POST'])
# @login_required
# def add_student():
#     """添加学生"""
#     try:
#         student_id = request.form.get('student_id')
#         name = request.form.get('name')
#         gender = request.form.get('gender')
#         ethnicity = request.form.get('ethnicity', '汉族')
#         major = request.form.get('major')
#         class_name = request.form.get('class')
#         phone = request.form.get('phone')
#         building_id = request.form.get('building_id') or None
#         room_id = request.form.get('room_id') or None
#
#         cur = mysql.connection.cursor()
#
#         # 检查学号是否存在
#         cur.execute("SELECT student_id FROM students WHERE student_id = %s", (student_id,))
#         if cur.fetchone():
#             flash('学号已存在', 'danger')
#             cur.close()
#             return redirect(url_for('students'))
#
#         # 检查房间容量
#         if room_id:
#             cur.execute("""
#                 SELECT r.capacity, COUNT(s.student_id) as current
#                 FROM rooms r
#                 LEFT JOIN students s ON r.room_id = s.room_id
#                 WHERE r.room_id = %s
#                 GROUP BY r.room_id, r.capacity
#             """, (room_id,))
#             room = cur.fetchone()
#             if room and room['current'] >= room['capacity']:
#                 flash('该寝室已满员', 'danger')
#                 cur.close()
#                 return redirect(url_for('students'))
#
#         cur.execute("""
#             INSERT INTO students (student_id, name, gender, ethnicity, major, class, phone, building_id, room_id)
#             VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
#         """, (student_id, name, gender, ethnicity, major, class_name, phone, building_id, room_id))
#
#         mysql.connection.commit()
#         cur.close()
#
#         flash('学生信息添加成功', 'success')
#     except Exception as e:
#         flash(f'添加失败: {str(e)}', 'danger')
#
#     return redirect(url_for('students'))
#
#
# @app.route('/students/edit/<student_id>', methods=['POST'])
# @login_required
# def edit_student(student_id):
#     """编辑学生"""
#     try:
#         name = request.form.get('name')
#         gender = request.form.get('gender')
#         ethnicity = request.form.get('ethnicity')
#         major = request.form.get('major')
#         class_name = request.form.get('class')
#         phone = request.form.get('phone')
#         building_id = request.form.get('building_id') or None
#         room_id = request.form.get('room_id') or None
#
#         cur = mysql.connection.cursor()
#
#         # 检查房间容量
#         if room_id:
#             cur.execute("""
#                 SELECT r.capacity, COUNT(s.student_id) as current
#                 FROM rooms r
#                 LEFT JOIN students s ON r.room_id = s.room_id
#                 WHERE r.room_id = %s AND s.student_id != %s
#                 GROUP BY r.room_id, r.capacity
#             """, (room_id, student_id))
#             room = cur.fetchone()
#             if room and room['current'] >= room['capacity']:
#                 flash('该寝室已满员', 'danger')
#                 cur.close()
#                 return redirect(url_for('students'))
#
#         cur.execute("""
#             UPDATE students
#             SET name=%s, gender=%s, ethnicity=%s, major=%s, class=%s, phone=%s, building_id=%s, room_id=%s
#             WHERE student_id=%s
#         """, (name, gender, ethnicity, major, class_name, phone, building_id, room_id, student_id))
#
#         mysql.connection.commit()
#         cur.close()
#
#         flash('学生信息更新成功', 'success')
#     except Exception as e:
#         flash(f'更新失败: {str(e)}', 'danger')
#
#     return redirect(url_for('students'))
#
#
# @app.route('/students/delete/<student_id>', methods=['POST'])
# @login_required
# def delete_student(student_id):
#     """删除学生"""
#     try:
#         cur = mysql.connection.cursor()
#         cur.execute("DELETE FROM students WHERE student_id = %s", (student_id,))
#         mysql.connection.commit()
#         cur.close()
#
#         flash('学生信息删除成功', 'success')
#     except Exception as e:
#         flash(f'删除失败: {str(e)}', 'danger')
#
#     return redirect(url_for('students'))
#
#
# # ==================== 公寓楼管理 ====================
#
# @app.route('/buildings')
# @login_required
# def buildings():
#     """公寓楼列表"""
#     cur = mysql.connection.cursor()
#     cur.execute("""
#         SELECT b.*,
#                (SELECT COUNT(*) FROM rooms WHERE building_id = b.building_id) as actual_rooms,
#                (SELECT COUNT(*) FROM students WHERE building_id = b.building_id) as student_count
#         FROM buildings b
#         ORDER BY b.building_id
#     """)
#     buildings_list = cur.fetchall()
#     cur.close()
#
#     return render_template('buildings.html', buildings=buildings_list)
#
#
# @app.route('/buildings/add', methods=['POST'])
# @login_required
# def add_building():
#     """添加公寓楼"""
#     try:
#         building_id = request.form.get('building_id')
#         floors = request.form.get('floors', type=int)
#         rooms_count = request.form.get('rooms_count', type=int)
#         commission_date = request.form.get('commission_date')
#
#         cur = mysql.connection.cursor()
#         cur.execute("""
#             INSERT INTO buildings (building_id, floors, rooms_count, commission_date)
#             VALUES (%s, %s, %s, %s)
#         """, (building_id, floors, rooms_count, commission_date))
#
#         mysql.connection.commit()
#         cur.close()
#
#         flash('公寓楼添加成功', 'success')
#     except Exception as e:
#         flash(f'添加失败: {str(e)}', 'danger')
#
#     return redirect(url_for('buildings'))
#
#
# @app.route('/buildings/edit/<building_id>', methods=['POST'])
# @login_required
# def edit_building(building_id):
#     """编辑公寓楼"""
#     try:
#         floors = request.form.get('floors', type=int)
#         rooms_count = request.form.get('rooms_count', type=int)
#         commission_date = request.form.get('commission_date')
#
#         cur = mysql.connection.cursor()
#         cur.execute("""
#             UPDATE buildings
#             SET floors=%s, rooms_count=%s, commission_date=%s
#             WHERE building_id=%s
#         """, (floors, rooms_count, commission_date, building_id))
#
#         mysql.connection.commit()
#         cur.close()
#
#         flash('公寓楼信息更新成功', 'success')
#     except Exception as e:
#         flash(f'更新失败: {str(e)}', 'danger')
#
#     return redirect(url_for('buildings'))
#
#
# @app.route('/buildings/delete/<building_id>', methods=['POST'])
# @login_required
# def delete_building(building_id):
#     """删除公寓楼"""
#     try:
#         cur = mysql.connection.cursor()
#         cur.execute("DELETE FROM buildings WHERE building_id = %s", (building_id,))
#         mysql.connection.commit()
#         cur.close()
#
#         flash('公寓楼删除成功', 'success')
#     except Exception as e:
#         flash(f'删除失败: {str(e)}', 'danger')
#
#     return redirect(url_for('buildings'))
#
#
# # ==================== 寝室管理 ====================
#
# @app.route('/rooms')
# @login_required
# def rooms():
#     """寝室列表"""
#     building_filter = request.args.get('building', '')
#
#     cur = mysql.connection.cursor()
#
#     if building_filter:
#         cur.execute("""
#             SELECT r.*,
#                    (SELECT COUNT(*) FROM students WHERE room_id = r.room_id) as current_occupancy,
#                    r.capacity - (SELECT COUNT(*) FROM students WHERE room_id = r.room_id) as available_beds
#             FROM rooms r
#             WHERE r.building_id = %s
#             ORDER BY r.room_id
#         """, (building_filter,))
#     else:
#         cur.execute("""
#             SELECT r.*,
#                    (SELECT COUNT(*) FROM students WHERE room_id = r.room_id) as current_occupancy,
#                    r.capacity - (SELECT COUNT(*) FROM students WHERE room_id = r.room_id) as available_beds
#             FROM rooms r
#             ORDER BY r.room_id
#         """)
#
#     rooms_list = cur.fetchall()
#
#     cur.execute("SELECT building_id FROM buildings ORDER BY building_id")
#     buildings = cur.fetchall()
#
#     cur.close()
#
#     return render_template('rooms.html', rooms=rooms_list, buildings=buildings, building_filter=building_filter)
#
#
# @app.route('/rooms/add', methods=['POST'])
# @login_required
# def add_room():
#     """添加寝室"""
#     try:
#         room_id = request.form.get('room_id')
#         building_id = request.form.get('building_id')
#         capacity = request.form.get('capacity', type=int)
#         fee = request.form.get('fee', type=float)
#         phone = request.form.get('phone')
#
#         cur = mysql.connection.cursor()
#         cur.execute("""
#             INSERT INTO rooms (room_id, building_id, capacity, fee, phone)
#             VALUES (%s, %s, %s, %s, %s)
#         """, (room_id, building_id, capacity, fee, phone))
#
#         mysql.connection.commit()
#         cur.close()
#
#         flash('寝室添加成功', 'success')
#     except Exception as e:
#         flash(f'添加失败: {str(e)}', 'danger')
#
#     return redirect(url_for('rooms'))
#
#
# @app.route('/rooms/edit/<room_id>', methods=['POST'])
# @login_required
# def edit_room(room_id):
#     """编辑寝室"""
#     try:
#         building_id = request.form.get('building_id')
#         capacity = request.form.get('capacity', type=int)
#         fee = request.form.get('fee', type=float)
#         phone = request.form.get('phone')
#
#         cur = mysql.connection.cursor()
#         cur.execute("""
#             UPDATE rooms
#             SET building_id=%s, capacity=%s, fee=%s, phone=%s
#             WHERE room_id=%s
#         """, (building_id, capacity, fee, phone, room_id))
#
#         mysql.connection.commit()
#         cur.close()
#
#         flash('寝室信息更新成功', 'success')
#     except Exception as e:
#         flash(f'更新失败: {str(e)}', 'danger')
#
#     return redirect(url_for('rooms'))
#
#
# @app.route('/rooms/delete/<room_id>', methods=['POST'])
# @login_required
# def delete_room(room_id):
#     """删除寝室"""
#     try:
#         cur = mysql.connection.cursor()
#         cur.execute("DELETE FROM rooms WHERE room_id = %s", (room_id,))
#         mysql.connection.commit()
#         cur.close()
#
#         flash('寝室删除成功', 'success')
#     except Exception as e:
#         flash(f'删除失败: {str(e)}', 'danger')
#
#     return redirect(url_for('rooms'))
#
#
# # ==================== 交费管理 ====================
#
# @app.route('/payments')
# @login_required
# def payments():
#     """交费记录列表"""
#     page = request.args.get('page', 1, type=int)
#     student_id = request.args.get('student_id', '')
#     payment_type = request.args.get('payment_type', '')
#     start_date = request.args.get('start_date', '')
#     end_date = request.args.get('end_date', '')
#     per_page = 15
#
#     cur = mysql.connection.cursor()
#
#     query = """
#         SELECT p.*, s.name as student_name, s.major, s.class
#         FROM payments p
#         JOIN students s ON p.student_id = s.student_id
#         WHERE 1=1
#     """
#     params = []
#
#     if student_id:
#         query += " AND p.student_id LIKE %s"
#         params.append(f'%{student_id}%')
#
#     if payment_type:
#         query += " AND p.payment_type = %s"
#         params.append(payment_type)
#
#     if start_date:
#         query += " AND p.payment_date >= %s"
#         params.append(start_date)
#
#     if end_date:
#         query += " AND p.payment_date <= %s"
#         params.append(end_date)
#
#     query += " ORDER BY p.payment_date DESC, p.payment_id DESC"
#
#     cur.execute(query, params)
#     all_payments = cur.fetchall()
#     total = len(all_payments)
#
#     # 分页
#     start = (page - 1) * per_page
#     end = start + per_page
#     payments_page = all_payments[start:end]
#
#     total_pages = (total + per_page - 1) // per_page
#
#     # 统计
#     total_amount = sum(p['amount'] for p in all_payments)
#
#     # 获取学生和寝室数据
#     cur.execute("SELECT student_id, name, building_id, room_id FROM students ORDER BY student_id")
#     students = cur.fetchall()
#
#     cur.execute("SELECT building_id FROM buildings ORDER BY building_id")
#     buildings = cur.fetchall()
#
#     cur.execute("SELECT room_id, building_id FROM rooms ORDER BY room_id")
#     rooms = cur.fetchall()
#
#     cur.close()
#
#     return render_template('payments.html',
#                            payments=payments_page,
#                            page=page,
#                            total_pages=total_pages,
#                            total_amount=total_amount,
#                            students=students,
#                            buildings=buildings,
#                            rooms=rooms,
#                            filters={'student_id': student_id, 'payment_type': payment_type,
#                                     'start_date': start_date, 'end_date': end_date})
#
#
# @app.route('/payments/add', methods=['POST'])
# @login_required
# def add_payment():
#     """添加交费记录"""
#     try:
#         student_id = request.form.get('student_id')
#         payment_date = request.form.get('payment_date')
#         payment_type = request.form.get('payment_type')
#         amount = request.form.get('amount', type=float)
#         remark = request.form.get('remark', '')
#
#         cur = mysql.connection.cursor()
#
#         # 获取学生的楼栋和寝室信息
#         cur.execute("SELECT building_id, room_id FROM students WHERE student_id = %s", (student_id,))
#         student = cur.fetchone()
#
#         if not student or not student['building_id'] or not student['room_id']:
#             flash('该学生未分配寝室', 'danger')
#             cur.close()
#             return redirect(url_for('payments'))
#
#         cur.execute("""
#             INSERT INTO payments (building_id, room_id, payment_date, payment_type, amount, student_id, remark)
#             VALUES (%s, %s, %s, %s, %s, %s, %s)
#         """, (student['building_id'], student['room_id'], payment_date, payment_type, amount, student_id, remark))
#
#         mysql.connection.commit()
#         cur.close()
#
#         flash('交费记录添加成功', 'success')
#     except Exception as e:
#         flash(f'添加失败: {str(e)}', 'danger')
#
#     return redirect(url_for('payments'))
#
#
# @app.route('/payments/delete/<int:payment_id>', methods=['POST'])
# @login_required
# def delete_payment(payment_id):
#     """删除交费记录"""
#     try:
#         cur = mysql.connection.cursor()
#         cur.execute("DELETE FROM payments WHERE payment_id = %s", (payment_id,))
#         mysql.connection.commit()
#         cur.close()
#
#         flash('交费记录删除成功', 'success')
#     except Exception as e:
#         flash(f'删除失败: {str(e)}', 'danger')
#
#     return redirect(url_for('payments'))
#
#
# # ==================== 统计报表 ====================
#
# @app.route('/reports')
# @login_required
# def reports():
#     """统计报表"""
#     cur = mysql.connection.cursor()
#
#     # 月度统计
#     cur.execute("""
#         SELECT
#             DATE_FORMAT(payment_date, '%Y-%m') as month,
#             payment_type,
#             COUNT(*) as count,
#             SUM(amount) as total
#         FROM payments
#         WHERE payment_date >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
#         GROUP BY DATE_FORMAT(payment_date, '%Y-%m'), payment_type
#         ORDER BY month DESC, payment_type
#     """)
#     monthly_stats = cur.fetchall()
#
#     # 各公寓楼统计
#     cur.execute("""
#         SELECT
#             b.building_id,
#             COUNT(DISTINCT s.student_id) as student_count,
#             COUNT(DISTINCT p.payment_id) as payment_count,
#             COALESCE(SUM(p.amount), 0) as total_amount
#         FROM buildings b
#         LEFT JOIN students s ON b.building_id = s.building_id
#         LEFT JOIN payments p ON b.building_id = p.building_id
#         GROUP BY b.building_id
#         ORDER BY b.building_id
#     """)
#     building_stats = cur.fetchall()
#
#     # 专业统计
#     cur.execute("""
#         SELECT
#             s.major,
#             COUNT(DISTINCT s.student_id) as student_count,
#             COUNT(p.payment_id) as payment_count,
#             COALESCE(SUM(p.amount), 0) as total_amount
#         FROM students s
#         LEFT JOIN payments p ON s.student_id = p.student_id
#         GROUP BY s.major
#         ORDER BY student_count DESC
#     """)
#     major_stats = cur.fetchall()
#
#     # 欠费学生（假设每学期住宿费1200，已到期但未交费的）
#     cur.execute("""
#         SELECT s.student_id, s.name, s.major, s.class, s.building_id, s.room_id,
#                COALESCE(SUM(p.amount), 0) as paid_amount,
#                r.fee as should_pay
#         FROM students s
#         LEFT JOIN rooms r ON s.room_id = r.room_id
#         LEFT JOIN payments p ON s.student_id = p.student_id AND p.payment_type = '住宿费'
#         GROUP BY s.student_id, s.name, s.major, s.class, s.building_id, s.room_id, r.fee
#         HAVING paid_amount < should_pay OR paid_amount IS NULL
#         ORDER BY s.student_id
#         LIMIT 20
#     """)
#     arrears_students = cur.fetchall()
#
#     cur.close()
#
#     return render_template('reports.html',
#                            monthly_stats=monthly_stats,
#                            building_stats=building_stats,
#                            major_stats=major_stats,
#                            arrears_students=arrears_students)
#
#
# # ==================== 用户管理 ====================
#
# @app.route('/users')
# @admin_required
# def users():
#     """用户管理"""
#     cur = mysql.connection.cursor()
#     cur.execute("SELECT user_id, username, realname, permission, created_at FROM users ORDER BY user_id")
#     users_list = cur.fetchall()
#     cur.close()
#
#     return render_template('users.html', users=users_list)
#
#
# @app.route('/users/add', methods=['POST'])
# @admin_required
# def add_user():
#     """添加用户"""
#     try:
#         username = request.form.get('username')
#         password = request.form.get('password')
#         realname = request.form.get('realname')
#         permission = request.form.get('permission')
#
#         hashed_password = hash_password(password)
#
#         cur = mysql.connection.cursor()
#         cur.execute("""
#             INSERT INTO users (username, password, realname, permission)
#             VALUES (%s, %s, %s, %s)
#         """, (username, hashed_password, realname, permission))
#
#         mysql.connection.commit()
#         cur.close()
#
#         flash('用户添加成功', 'success')
#     except Exception as e:
#         flash(f'添加失败: {str(e)}', 'danger')
#
#     return redirect(url_for('users'))
#
#
# @app.route('/users/edit/<int:user_id>', methods=['POST'])
# @admin_required
# def edit_user(user_id):
#     """编辑用户"""
#     try:
#         realname = request.form.get('realname')
#         permission = request.form.get('permission')
#         password = request.form.get('password')
#
#         cur = mysql.connection.cursor()
#
#         if password:
#             hashed_password = hash_password(password)
#             cur.execute("""
#                 UPDATE users
#                 SET realname=%s, permission=%s, password=%s
#                 WHERE user_id=%s
#             """, (realname, permission, hashed_password, user_id))
#         else:
#             cur.execute("""
#                 UPDATE users
#                 SET realname=%s, permission=%s
#                 WHERE user_id=%s
#             """, (realname, permission, user_id))
#
#         mysql.connection.commit()
#         cur.close()
#
#         flash('用户信息更新成功', 'success')
#     except Exception as e:
#         flash(f'更新失败: {str(e)}', 'danger')
#
#     return redirect(url_for('users'))
#
#
# @app.route('/users/delete/<int:user_id>', methods=['POST'])
# @admin_required
# def delete_user(user_id):
#     """删除用户"""
#     if user_id == session.get('user_id'):
#         flash('不能删除当前登录用户', 'danger')
#         return redirect(url_for('users'))
#
#     try:
#         cur = mysql.connection.cursor()
#         cur.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
#         mysql.connection.commit()
#         cur.close()
#
#         flash('用户删除成功', 'success')
#     except Exception as e:
#         flash(f'删除失败: {str(e)}', 'danger')
#
#     return redirect(url_for('users'))
#
#
# # ==================== API接口 ====================
#
# @app.route('/api/rooms/<building_id>')
# @login_required
# def api_get_rooms(building_id):
#     """获取指定楼栋的房间"""
#     cur = mysql.connection.cursor()
#     cur.execute("SELECT room_id, capacity, fee FROM rooms WHERE building_id = %s ORDER BY room_id", (building_id,))
#     rooms = cur.fetchall()
#     cur.close()
#     return jsonify(rooms)
#
#
# @app.route('/api/student/<student_id>')
# @login_required
# def api_get_student(student_id):
#     """获取学生信息"""
#     cur = mysql.connection.cursor()
#     cur.execute("SELECT * FROM students WHERE student_id = %s", (student_id,))
#     student = cur.fetchone()
#     cur.close()
#     if student:
#         return jsonify(student)
#     return jsonify({'error': 'Student not found'}), 404
#
#
# if __name__ == '__main__':
#     app.run(debug=True, host='0.0.0.0', port=5000)
