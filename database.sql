-- 学生公寓交费管理系统数据库脚本
-- 创建数据库
CREATE DATABASE IF NOT EXISTS dorm_management DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE dorm_management;

-- 1. 公寓楼表
CREATE TABLE buildings (
    building_id VARCHAR(20) PRIMARY KEY COMMENT '公寓楼号',
    floors INT NOT NULL COMMENT '楼层数',
    rooms_count INT NOT NULL COMMENT '房间数',
    commission_date DATE NOT NULL COMMENT '启用时间',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='公寓楼信息表';

-- 2. 寝室表
CREATE TABLE rooms (
    room_id VARCHAR(20) PRIMARY KEY COMMENT '寝室号',
    building_id VARCHAR(20) NOT NULL COMMENT '公寓号',
    capacity INT NOT NULL COMMENT '可住人数',
    fee DECIMAL(10,2) NOT NULL COMMENT '住宿费用',
    phone VARCHAR(20) COMMENT '电话',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (building_id) REFERENCES buildings(building_id) ON DELETE CASCADE,
    INDEX idx_building (building_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='寝室信息表';

-- 3. 学生表
CREATE TABLE students (
    student_id VARCHAR(20) PRIMARY KEY COMMENT '学号',
    name VARCHAR(50) NOT NULL COMMENT '姓名',
    gender ENUM('男', '女') NOT NULL COMMENT '性别',
    ethnicity VARCHAR(20) DEFAULT '汉族' COMMENT '民族',
    major VARCHAR(50) NOT NULL COMMENT '专业',
    class VARCHAR(50) NOT NULL COMMENT '班级',
    phone VARCHAR(20) NOT NULL COMMENT '联系方式',
    building_id VARCHAR(20) COMMENT '公寓楼号',
    room_id VARCHAR(20) COMMENT '寝室号',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (building_id) REFERENCES buildings(building_id) ON DELETE SET NULL,
    FOREIGN KEY (room_id) REFERENCES rooms(room_id) ON DELETE SET NULL,
    INDEX idx_name (name),
    INDEX idx_major (major),
    INDEX idx_class (class)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='学生信息表';

-- 4. 交费表
CREATE TABLE payments (
    payment_id INT AUTO_INCREMENT PRIMARY KEY COMMENT '交费编号',
    building_id VARCHAR(20) NOT NULL COMMENT '公寓号',
    room_id VARCHAR(20) NOT NULL COMMENT '寝室号',
    payment_date DATE NOT NULL COMMENT '交费时间',
    payment_type ENUM('住宿费', '水电费', '其他') NOT NULL COMMENT '交费类型',
    amount DECIMAL(10,2) NOT NULL COMMENT '金额',
    student_id VARCHAR(20) NOT NULL COMMENT '学号',
    remark VARCHAR(200) COMMENT '备注',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (building_id) REFERENCES buildings(building_id) ON DELETE CASCADE,
    FOREIGN KEY (room_id) REFERENCES rooms(room_id) ON DELETE CASCADE,
    FOREIGN KEY (student_id) REFERENCES students(student_id) ON DELETE CASCADE,
    INDEX idx_student (student_id),
    INDEX idx_date (payment_date),
    INDEX idx_type (payment_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='交费记录表';

-- 5. 用户表
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY COMMENT '用户ID',
    username VARCHAR(50) UNIQUE NOT NULL COMMENT '用户名',
    password VARCHAR(255) NOT NULL COMMENT '密码(加密)',
    realname VARCHAR(50) NOT NULL COMMENT '真实姓名',
    permission ENUM('管理员', '教师') NOT NULL DEFAULT '教师' COMMENT '权限',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='系统用户表';

-- ================================
-- 插入示例数据
-- ================================

-- 插入公寓楼数据
INSERT INTO buildings (building_id, floors, rooms_count, commission_date) VALUES
('A栋', 6, 120, '2020-09-01'),
('B栋', 6, 120, '2020-09-01'),
('C栋', 8, 160, '2021-09-01'),
('D栋', 8, 160, '2021-09-01');

-- 插入寝室数据
INSERT INTO rooms (room_id, building_id, capacity, fee, phone) VALUES
('A101', 'A栋', 4, 1200.00, '8101'),
('A102', 'A栋', 4, 1200.00, '8102'),
('A201', 'A栋', 4, 1200.00, '8201'),
('A202', 'A栋', 4, 1200.00, '8202'),
('B101', 'B栋', 4, 1200.00, '8301'),
('B102', 'B栋', 4, 1200.00, '8302'),
('B201', 'B栋', 4, 1200.00, '8401'),
('C101', 'C栋', 6, 1000.00, '8501'),
('C102', 'C栋', 6, 1000.00, '8502'),
('D101', 'D栋', 6, 1000.00, '8601');

-- 插入学生数据
INSERT INTO students (student_id, name, gender, ethnicity, major, class, phone, building_id, room_id) VALUES
('2024001', '张三', '男', '汉族', '计算机科学与技术', '计科2401', '13800138001', 'A栋', 'A101'),
('2024002', '李四', '男', '汉族', '计算机科学与技术', '计科2401', '13800138002', 'A栋', 'A101'),
('2024003', '王五', '女', '汉族', '软件工程', '软工2401', '13800138003', 'A栋', 'A102'),
('2024004', '赵六', '女', '回族', '软件工程', '软工2401', '13800138004', 'A栋', 'A102'),
('2024005', '钱七', '男', '汉族', '电子信息工程', '电信2401', '13800138005', 'B栋', 'B101'),
('2024006', '孙八', '男', '汉族', '电子信息工程', '电信2401', '13800138006', 'B栋', 'B101'),
('2024007', '周九', '女', '汉族', '通信工程', '通信2401', '13800138007', 'C栋', 'C101'),
('2024008', '吴十', '女', '满族', '通信工程', '通信2401', '13800138008', 'C栋', 'C101'),
('2024009', '郑一', '男', '汉族', '物联网工程', '物联2401', '13800138009', 'D栋', 'D101'),
('2024010', '刘二', '男', '汉族', '物联网工程', '物联2401', '13800138010', 'D栋', 'D101');

-- 插入交费记录
INSERT INTO payments (building_id, room_id, payment_date, payment_type, amount, student_id, remark) VALUES
('A栋', 'A101', '2024-09-01', '住宿费', 1200.00, '2024001', '2024-2025学年第一学期'),
('A栋', 'A101', '2024-09-01', '住宿费', 1200.00, '2024002', '2024-2025学年第一学期'),
('A栋', 'A102', '2024-09-01', '住宿费', 1200.00, '2024003', '2024-2025学年第一学期'),
('A栋', 'A102', '2024-09-01', '住宿费', 1200.00, '2024004', '2024-2025学年第一学期'),
('B栋', 'B101', '2024-09-05', '住宿费', 1200.00, '2024005', '2024-2025学年第一学期'),
('B栋', 'B101', '2024-09-05', '住宿费', 1200.00, '2024006', '2024-2025学年第一学期'),
('A栋', 'A101', '2024-10-10', '水电费', 150.00, '2024001', '9月水电费'),
('A栋', 'A102', '2024-10-10', '水电费', 180.00, '2024003', '9月水电费'),
('C栋', 'C101', '2024-09-10', '住宿费', 1000.00, '2024007', '2024-2025学年第一学期'),
('D栋', 'D101', '2024-09-10', '住宿费', 1000.00, '2024009', '2024-2025学年第一学期');

-- 插入用户数据 (密码统一为: admin123, 使用SHA256加密)
INSERT INTO users (username, password, realname, permission) VALUES
('admin', 'sha256$salt$240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9', '系统管理员', '管理员'),
('teacher1', 'sha256$salt$240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9', '张老师', '教师'),
('teacher2', 'sha256$salt$240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9', '李老师', '教师');

-- 创建视图：学生交费统计
CREATE VIEW student_payment_summary AS
SELECT
    s.student_id,
    s.name,
    s.major,
    s.class,
    s.building_id,
    s.room_id,
    COUNT(p.payment_id) as payment_count,
    SUM(p.amount) as total_amount
FROM students s
LEFT JOIN payments p ON s.student_id = p.student_id
GROUP BY s.student_id, s.name, s.major, s.class, s.building_id, s.room_id;

-- 创建视图：寝室入住情况
CREATE VIEW room_occupancy AS
SELECT
    r.room_id,
    r.building_id,
    r.capacity,
    r.fee,
    COUNT(s.student_id) as current_occupancy,
    r.capacity - COUNT(s.student_id) as available_beds
FROM rooms r
LEFT JOIN students s ON r.room_id = s.room_id
GROUP BY r.room_id, r.building_id, r.capacity, r.fee;

-- 显示所有表
SHOW TABLES;

-- 数据库创建完成
SELECT '数据库创建成功！' as message;