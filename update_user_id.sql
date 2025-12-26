-- 更新用户表结构脚本
USE dorm_management;

-- 1. 备份原用户数据
CREATE TABLE users_backup AS SELECT * FROM users;

-- 2. 删除外键约束（如果有的话）
-- 注意：根据实际情况，如果有其他表引用users表，需要先处理

-- 3. 删除原表
DROP TABLE users;

-- 4. 重新创建用户表（使用字符串ID）
CREATE TABLE users (
    user_id VARCHAR(20) PRIMARY KEY COMMENT '用户ID',
    username VARCHAR(50) UNIQUE NOT NULL COMMENT '用户名',
    password VARCHAR(255) NOT NULL COMMENT '密码(加密)',
    realname VARCHAR(50) NOT NULL COMMENT '真实姓名',
    permission ENUM('管理员', '教师') NOT NULL DEFAULT '教师' COMMENT '权限',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_user_id (user_id),
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='系统用户表';

-- 5. 重新插入用户数据，使用新的ID格式
INSERT INTO users (user_id, username, password, realname, permission, created_at) VALUES
('U25010001', 'admin', 'sha256$salt$240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9', '系统管理员', '管理员', NOW()),
('U25010002', 'teacher1', 'sha256$salt$240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9', '张老师', '教师', NOW()),
('U25010003', 'teacher2', 'sha256$salt$240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9', '李老师', '教师', NOW());

-- 6. 清理备份表
DROP TABLE users_backup;

SELECT '用户表更新成功！' as message;