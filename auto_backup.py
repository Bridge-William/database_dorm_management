#!/usr/bin/env python3
"""
自动备份调度器模块
用于管理定时备份任务
"""

import os
import sys
import time
import threading
from datetime import datetime
from pathlib import Path
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

# 配置日志
logger = logging.getLogger(__name__)


class AutoBackupScheduler:
    """自动备份调度器"""

    def __init__(self, config, app=None):
        """
        初始化自动备份调度器

        Args:
            config: Flask应用配置
            app: Flask应用实例（可选）
        """
        self.config = config
        self.app = app
        self.scheduler = None
        self.is_running = False
        self.backup_dir = Path("backups")
        self.backup_dir.mkdir(exist_ok=True)

        # 备份配置
        self.settings = {
            'enabled': True,
            'time': '00:00',  # 默认每天零点
            'backup_type': 'full',
            'keep_days': 30,  # 保留30天备份
            'max_backups': 50,  # 最多保留50个备份
            'compress': True,
            'notify_on_error': True
        }

        # 加载保存的设置
        self._load_settings()

    def _load_settings(self):
        """加载保存的设置"""
        try:
            settings_file = self.backup_dir / 'auto_backup_settings.json'
            if settings_file.exists():
                import json
                with open(settings_file, 'r', encoding='utf-8') as f:
                    saved_settings = json.load(f)
                    self.settings.update(saved_settings)
                logger.info("已加载自动备份设置")
        except Exception as e:
            logger.warning(f"加载自动备份设置失败: {str(e)}")

    def _save_settings(self):
        """保存设置到文件"""
        try:
            settings_file = self.backup_dir / 'auto_backup_settings.json'
            import json
            with open(settings_file, 'w', encoding='utf-8') as f:
                json.dump(self.settings, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"保存自动备份设置失败: {str(e)}")

    def start(self):
        """启动自动备份调度器"""
        if not self.settings['enabled']:
            logger.info("自动备份未启用")
            return False

        try:
            if self.scheduler and self.scheduler.running:
                logger.warning("自动备份调度器已在运行")
                return True

            # 创建调度器
            self.scheduler = BackgroundScheduler()
            self.scheduler.add_listener(self._on_scheduler_event)

            # 解析备份时间
            hour_str, minute_str = self.settings['time'].split(':')
            hour = int(hour_str)
            minute = int(minute_str)

            # 添加备份任务
            self.scheduler.add_job(
                func=self._perform_backup,
                trigger=CronTrigger(hour=hour, minute=minute),
                id='auto_backup_job',
                name='自动数据库备份',
                replace_existing=True,
                misfire_grace_time=300  # 允许5分钟的延迟
            )

            # 添加清理旧备份任务（每天凌晨1点）
            self.scheduler.add_job(
                func=self._cleanup_old_backups,
                trigger=CronTrigger(hour=1, minute=0),
                id='cleanup_backups_job',
                name='清理旧备份',
                replace_existing=True
            )

            # 启动调度器
            self.scheduler.start()
            self.is_running = True

            next_run = self.scheduler.get_job('auto_backup_job').next_run_time
            logger.info(f"自动备份调度器已启动，下次备份时间: {next_run}")
            return True

        except Exception as e:
            logger.error(f"启动自动备份调度器失败: {str(e)}")
            return False

    def stop(self):
        """停止自动备份调度器"""
        try:
            if self.scheduler and self.scheduler.running:
                self.scheduler.shutdown(wait=False)
                self.is_running = False
                logger.info("自动备份调度器已停止")
            return True
        except Exception as e:
            logger.error(f"停止自动备份调度器失败: {str(e)}")
            return False

    def restart(self):
        """重启自动备份调度器"""
        self.stop()
        time.sleep(1)
        return self.start()

    def _perform_backup(self):
        """执行自动备份"""
        try:
            logger.info("开始执行自动备份...")

            # 在应用上下文中执行备份
            if self.app:
                with self.app.app_context():
                    self._do_backup()
            else:
                self._do_backup()

            logger.info("自动备份执行完成")

        except Exception as e:
            logger.error(f"自动备份执行失败: {str(e)}")

            # 错误通知（可以扩展为发送邮件或系统通知）
            if self.settings['notify_on_error']:
                self._notify_backup_error(str(e))

    def _do_backup(self):
        """实际执行备份"""
        # 导入备份模块
        from backup import DatabaseBackup

        # 创建备份管理器
        backup_manager = DatabaseBackup(self.config)

        # 生成备份说明
        comment = f"自动备份 {datetime.now().strftime('%Y-%m-%d')}"

        # 执行备份
        result = backup_manager.create_backup(
            backup_type=self.settings['backup_type'],
            comment=comment
        )

        if result['success']:
            logger.info(f"自动备份成功: {result['filename']} ({result['size']})")

            # 记录备份历史
            self._log_backup_history(result)

            # 检查备份数量，如果过多则触发清理
            backups = backup_manager.list_backups()
            if len(backups) > self.settings['max_backups']:
                logger.info(f"备份文件数量({len(backups)})超过限制({self.settings['max_backups']})，触发清理")
                self._cleanup_old_backups()
        else:
            logger.error(f"自动备份失败: {result.get('message', '未知错误')}")
            raise Exception(result.get('message', '备份失败'))

    def _cleanup_old_backups(self):
        """清理旧的备份文件"""
        try:
            from backup import DatabaseBackup
            backup_manager = DatabaseBackup(self.config)
            backups = backup_manager.list_backups()

            # 计算保留截止日期
            from datetime import timedelta
            cutoff_date = datetime.now() - timedelta(days=self.settings['keep_days'])

            deleted_count = 0
            deleted_size = 0

            for backup in backups:
                backup_time = backup['created_time']

                # 如果备份时间早于截止日期，则删除
                if backup_time < cutoff_date:
                    result = backup_manager.delete_backup(backup['filename'])
                    if result['success']:
                        deleted_count += 1
                        deleted_size += backup['size_bytes'] if 'size_bytes' in backup else 0
                        logger.info(f"删除旧备份: {backup['filename']}")

            if deleted_count > 0:
                logger.info(f"已清理 {deleted_count} 个旧备份，释放 {backup_manager._format_size(deleted_size)} 空间")
            else:
                logger.debug("无需清理旧备份")

        except Exception as e:
            logger.error(f"清理旧备份失败: {str(e)}")

    def _log_backup_history(self, backup_result):
        """记录备份历史"""
        try:
            history_file = self.backup_dir / 'backup_history.log'

            with open(history_file, 'a', encoding='utf-8') as f:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                f.write(
                    f"{timestamp} | {backup_result['filename']} | {backup_result['size']} | {backup_result.get('message', '成功')}\n")

        except Exception as e:
            logger.warning(f"记录备份历史失败: {str(e)}")

    def _notify_backup_error(self, error_message):
        """通知备份错误（可以扩展为发送邮件）"""
        # 这里可以添加邮件通知、系统通知等
        # 目前只记录到日志
        logger.error(f"备份错误需要通知: {error_message}")

        # 示例：写入错误日志文件
        try:
            error_log = self.backup_dir / 'backup_errors.log'
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with open(error_log, 'a', encoding='utf-8') as f:
                f.write(f"{timestamp} | {error_message}\n")
        except:
            pass

    def _on_scheduler_event(self, event):
        """调度器事件处理"""
        if event.code == 4096:  # EVENT_JOB_EXECUTED
            logger.debug(f"任务执行完成: {event.job_id}")
        elif event.code == 8192:  # EVENT_JOB_ERROR
            logger.error(f"任务执行错误: {event.job_id}, 异常: {event.exception}")
        elif event.code == 1:  # EVENT_SCHEDULER_STARTED
            logger.info("调度器已启动")
        elif event.code == 2:  # EVENT_SCHEDULER_SHUTDOWN
            logger.info("调度器已关闭")

    def get_status(self):
        """获取调度器状态"""
        if not self.scheduler:
            return {
                'running': False,
                'enabled': self.settings['enabled'],
                'next_backup': None,
                'last_backup': self._get_last_backup_time(),
                'settings': self.settings
            }

        next_backup = None
        if self.scheduler.running:
            job = self.scheduler.get_job('auto_backup_job')
            if job:
                next_backup = job.next_run_time

        return {
            'running': self.scheduler.running,
            'enabled': self.settings['enabled'],
            'next_backup': next_backup,
            'last_backup': self._get_last_backup_time(),
            'settings': self.settings
        }

    def _get_last_backup_time(self):
        """获取最后一次备份时间"""
        try:
            from backup import DatabaseBackup
            backup_manager = DatabaseBackup(self.config)
            backups = backup_manager.list_backups()

            if backups:
                # 找到最近的备份
                latest_backup = max(backups, key=lambda x: x['created_time'])
                return latest_backup['created_time']

            return None
        except:
            return None

    def update_settings(self, new_settings):
        """更新设置"""
        # 只更新允许的字段
        allowed_fields = ['enabled', 'time', 'backup_type', 'keep_days',
                          'max_backups', 'compress', 'notify_on_error']

        for key in allowed_fields:
            if key in new_settings:
                self.settings[key] = new_settings[key]

        # 保存设置
        self._save_settings()

        # 如果调度器正在运行，重新启动
        if self.is_running:
            self.restart()

        return True

    def get_backup_stats(self):
        """获取备份统计信息"""
        try:
            from backup import DatabaseBackup
            backup_manager = DatabaseBackup(self.config)

            # 获取磁盘使用情况
            disk_usage = backup_manager.get_disk_usage()

            # 获取备份列表
            backups = backup_manager.list_backups()

            # 按月份统计
            monthly_stats = {}
            for backup in backups:
                month_key = backup['created_time'].strftime('%Y-%m')
                if month_key not in monthly_stats:
                    monthly_stats[month_key] = {
                        'count': 0,
                        'month_name': month_key  # 添加月份名称用于显示
                    }
                monthly_stats[month_key]['count'] += 1

            # 获取历史记录
            history = self._get_backup_history()

            return {
                'total_backups': len(backups),
                'disk_usage': disk_usage,
                'monthly_stats': monthly_stats,
                'recent_history': history[-10:] if history else []  # 最近10条记录
            }

        except Exception as e:
            logger.error(f"获取备份统计失败: {str(e)}")
            return None

    def _get_backup_history(self):
        """获取备份历史记录"""
        try:
            history_file = self.backup_dir / 'backup_history.log'
            if not history_file.exists():
                return []

            with open(history_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            history = []
            for line in lines:
                parts = line.strip().split(' | ')
                if len(parts) >= 4:
                    history.append({
                        'time': parts[0],
                        'filename': parts[1],
                        'size': parts[2],
                        'status': parts[3]
                    })

            return history

        except Exception as e:
            logger.error(f"读取备份历史失败: {str(e)}")
            return []

    def manual_backup_now(self):
        """立即执行手动备份"""
        try:
            logger.info("开始执行手动备份...")

            # 在单独的线程中执行备份，避免阻塞
            def backup_thread():
                try:
                    self._perform_backup()
                except Exception as e:
                    logger.error(f"手动备份执行失败: {str(e)}")

            thread = threading.Thread(target=backup_thread)
            thread.daemon = True
            thread.start()

            return {
                'success': True,
                'message': '手动备份已开始执行'
            }

        except Exception as e:
            logger.error(f"启动手动备份失败: {str(e)}")
            return {
                'success': False,
                'message': f'启动手动备份失败: {str(e)}'
            }