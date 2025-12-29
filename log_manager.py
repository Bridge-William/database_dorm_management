# !/usr/bin/env python3
"""
日志管理工具
用于管理学生公寓交费管理系统的日志文件
"""

import os
import sys
import logging
import argparse
from datetime import datetime, timedelta


def setup_logging():
    """配置日志"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger(__name__)


def list_log_files():
    """列出所有日志文件"""
    logger = setup_logging()

    log_dir = 'logs'
    if not os.path.exists(log_dir):
        logger.error(f"日志目录不存在: {log_dir}")
        return

    print("\n" + "=" * 60)
    print("日志文件列表")
    print("=" * 60)

    total_size = 0
    files = []

    for filename in os.listdir(log_dir):
        if filename.endswith('.log') or 'backup' in filename:
            filepath = os.path.join(log_dir, filename)
            file_stat = os.stat(filepath)
            file_size = file_stat.st_size
            modified_time = datetime.fromtimestamp(file_stat.st_mtime)

            files.append({
                'name': filename,
                'size': file_size,
                'modified': modified_time,
                'path': filepath
            })

            total_size += file_size

    # 按修改时间排序
    files.sort(key=lambda x: x['modified'], reverse=True)

    for file_info in files:
        size_mb = file_info['size'] / (1024 * 1024)
        print(f"{file_info['name']:30} | {size_mb:8.2f} MB | {file_info['modified'].strftime('%Y-%m-%d %H:%M:%S')}")

    print("=" * 60)
    print(f"总计: {len(files)} 个文件, {total_size / (1024 * 1024):.2f} MB")
    print("=" * 60)


def analyze_logs():
    """分析日志文件"""
    logger = setup_logging()

    log_file = 'logs/dorm_management.log'
    if not os.path.exists(log_file):
        logger.error(f"日志文件不存在: {log_file}")
        return

    print("\n" + "=" * 60)
    print("日志分析报告")
    print("=" * 60)

    stats = {
        'total': 0,
        'levels': {},
        'operations': {},
        'users': {},
        'errors': []
    }

    with open(log_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            stats['total'] += 1

            # 解析日志行
            parts = line.split(' - ', 3)
            if len(parts) < 4:
                continue

            timestamp, module, level, message = parts

            # 统计级别
            stats['levels'][level] = stats['levels'].get(level, 0) + 1

            # 提取操作类型
            if '执行' in message:
                operation_start = message.find('执行') + 2
                operation_end = message.find(' ', operation_start)
                if operation_end == -1:
                    operation_end = len(message)

                operation = message[operation_start:operation_end].strip()
                if operation:
                    stats['operations'][operation] = stats['operations'].get(operation, 0) + 1

            # 提取用户ID
            if '用户ID:' in message:
                user_start = message.find('用户ID:') + 4
                user_end = message.find(',', user_start)
                if user_end == -1:
                    user_end = message.find(')', user_start)
                if user_end == -1:
                    user_end = len(message)

                user_id = message[user_start:user_end].strip()
                if user_id:
                    stats['users'][user_id] = stats['users'].get(user_id, 0) + 1

            # 收集错误日志
            if level == 'ERROR':
                stats['errors'].append({
                    'time': timestamp,
                    'message': message
                })

    # 打印统计信息
    print(f"\n总日志条数: {stats['total']}")

    print("\n日志级别分布:")
    for level, count in sorted(stats['levels'].items(), key=lambda x: x[1], reverse=True):
        percentage = (count / stats['total']) * 100
        print(f"  {level:10}: {count:5} ({percentage:5.1f}%)")

    print("\n操作类型统计:")
    for operation, count in sorted(stats['operations'].items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {operation:20}: {count}")

    print("\n用户操作统计:")
    for user_id, count in sorted(stats['users'].items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {user_id:15}: {count}")

    print(f"\n错误日志总数: {len(stats['errors'])}")
    if stats['errors']:
        print("\n最近10个错误:")
        for error in stats['errors'][:10]:
            print(f"  {error['time']}: {error['message'][:100]}...")

    print("=" * 60)


def cleanup_old_logs(days=30):
    """清理旧的日志文件"""
    logger = setup_logging()

    log_dir = 'logs'
    if not os.path.exists(log_dir):
        logger.error(f"日志目录不存在: {log_dir}")
        return

    cutoff_date = datetime.now() - timedelta(days=days)

    print(f"\n清理 {days} 天前的日志文件...")

    deleted_files = []
    deleted_size = 0

    for filename in os.listdir(log_dir):
        if 'backup' in filename:
            filepath = os.path.join(log_dir, filename)
            file_stat = os.stat(filepath)
            modified_time = datetime.fromtimestamp(file_stat.st_mtime)

            if modified_time < cutoff_date:
                file_size = file_stat.st_size

                try:
                    os.remove(filepath)
                    deleted_files.append(filename)
                    deleted_size += file_size
                    logger.info(f"删除旧日志文件: {filename}")
                except Exception as e:
                    logger.error(f"删除文件失败 {filename}: {str(e)}")

    print(f"已删除 {len(deleted_files)} 个文件，释放 {deleted_size / (1024 * 1024):.2f} MB 空间")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='学生公寓管理系统日志管理工具')
    parser.add_argument('command', choices=['list', 'analyze', 'cleanup'],
                        help='命令: list-列出文件, analyze-分析日志, cleanup-清理旧文件')
    parser.add_argument('--days', type=int, default=30,
                        help='清理多少天前的日志文件（默认: 30天）')

    args = parser.parse_args()

    if args.command == 'list':
        list_log_files()
    elif args.command == 'analyze':
        analyze_logs()
    elif args.command == 'cleanup':
        cleanup_old_logs(args.days)


if __name__ == '__main__':
    main()
