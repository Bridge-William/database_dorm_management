"""
数据库备份管理模块
"""
import os
import sys
import subprocess
import zipfile
import tempfile
from datetime import datetime
from pathlib import Path


class DatabaseBackup:
    """数据库备份管理类"""

    def __init__(self, config):
        """
        初始化数据库备份管理器

        Args:
            config: Flask应用配置
        """
        self.config = config
        self.backup_dir = Path("backups")
        self.backup_dir.mkdir(exist_ok=True)

        # MySQL连接参数
        self.db_host = config.get('MYSQL_HOST', 'localhost')
        self.db_user = config.get('MYSQL_USER', 'root')
        self.db_password = config.get('MYSQL_PASSWORD', '')
        self.db_name = config.get('MYSQL_DB', 'dorm_management')

    def create_backup(self, backup_type="full", comment=""):
        """
        创建数据库备份

        Args:
            backup_type: 备份类型 full-全量, data-仅数据, schema-仅结构
            comment: 备份说明

        Returns:
            dict: 备份结果信息
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"backup_{self.db_name}_{timestamp}"

        if comment:
            backup_name = f"{backup_name}_{comment.replace(' ', '_')[:20]}"

        sql_file = self.backup_dir / f"{backup_name}.sql"
        zip_file = self.backup_dir / f"{backup_name}.zip"

        try:
            # 构建mysqldump命令
            dump_options = []
            if backup_type == "data":
                dump_options = ["--no-create-info", "--skip-triggers"]
            elif backup_type == "schema":
                dump_options = ["--no-data"]

            # 执行备份命令
            dump_cmd = [
                "mysqldump",
                f"--host={self.db_host}",
                f"--user={self.db_user}",
                f"--password={self.db_password}",
                "--single-transaction",
                "--routines",
                "--events",
                "--skip-comments",
                *dump_options,
                self.db_name
            ]

            # 执行备份
            with open(sql_file, 'w', encoding='utf-8') as f:
                result = subprocess.run(
                    dump_cmd,
                    stdout=f,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding='utf-8'
                )

                if result.returncode != 0:
                    raise Exception(f"备份失败: {result.stderr}")

            # 压缩备份文件
            with zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
                zipf.write(sql_file, sql_file.name)
                # 添加备份信息文件
                info_content = self._create_backup_info(backup_type, comment)
                info_file = tempfile.NamedTemporaryFile(
                    mode='w',
                    suffix='.txt',
                    encoding='utf-8',
                    delete=False
                )
                info_file.write(info_content)
                info_file.close()
                zipf.write(info_file.name, "backup_info.txt")
                os.unlink(info_file.name)

            # 删除原始的SQL文件
            sql_file.unlink()

            # 记录备份元数据
            metadata = {
                "filename": zip_file.name,
                "size": zip_file.stat().st_size,
                "backup_type": backup_type,
                "comment": comment,
                "created_at": datetime.now().isoformat(),
                "database": self.db_name,
                "tables": self._get_table_count()
            }

            # 保存元数据
            self._save_metadata(metadata)

            return {
                "success": True,
                "filename": zip_file.name,
                "path": str(zip_file),
                "size": self._format_size(zip_file.stat().st_size),
                "message": "备份创建成功",
                "metadata": metadata
            }

        except Exception as e:
            # 清理可能产生的部分文件
            if sql_file.exists():
                sql_file.unlink()
            if zip_file.exists():
                zip_file.unlink()

            return {
                "success": False,
                "message": f"备份失败: {str(e)}",
                "error": str(e)
            }

    def restore_backup(self, backup_file):
        """
        从备份文件恢复数据库

        Args:
            backup_file: 备份文件路径

        Returns:
            dict: 恢复结果
        """
        try:
            backup_path = Path(backup_file)
            if not backup_path.exists():
                return {
                    "success": False,
                    "message": f"备份文件不存在: {backup_file}"
                }

            # 解压备份文件
            temp_dir = tempfile.mkdtemp()
            with zipfile.ZipFile(backup_path, 'r') as zipf:
                zipf.extractall(temp_dir)

            # 查找SQL文件
            sql_files = list(Path(temp_dir).glob("*.sql"))
            if not sql_files:
                return {
                    "success": False,
                    "message": "备份文件中未找到SQL文件"
                }

            sql_file = sql_files[0]

            # 构建恢复命令
            restore_cmd = [
                "mysql",
                f"--host={self.db_host}",
                f"--user={self.db_user}",
                f"--password={self.db_password}",
                self.db_name
            ]

            # 执行恢复
            with open(sql_file, 'r', encoding='utf-8') as f:
                result = subprocess.run(
                    restore_cmd,
                    stdin=f,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding='utf-8'
                )

                if result.returncode != 0:
                    raise Exception(f"恢复失败: {result.stderr}")

            # 清理临时文件
            import shutil
            shutil.rmtree(temp_dir)

            return {
                "success": True,
                "message": "数据库恢复成功"
            }

        except Exception as e:
            return {
                "success": False,
                "message": f"恢复失败: {str(e)}",
                "error": str(e)
            }

    def list_backups(self):
        """
        列出所有备份文件

        Returns:
            list: 备份文件列表
        """
        backups = []

        for file_path in self.backup_dir.glob("*.zip"):
            stat = file_path.stat()
            metadata = self._load_metadata(file_path.name)

            backup_info = {
                "filename": file_path.name,
                "path": str(file_path),
                "size": self._format_size(stat.st_size),
                "created_time": datetime.fromtimestamp(stat.st_mtime),
                "modified_time": datetime.fromtimestamp(stat.st_mtime),
                "metadata": metadata or {}
            }

            backups.append(backup_info)

        # 按修改时间排序（最新的在前面）
        backups.sort(key=lambda x: x["modified_time"], reverse=True)

        return backups

    def delete_backup(self, filename):
        """
        删除备份文件

        Args:
            filename: 备份文件名

        Returns:
            dict: 删除结果
        """
        try:
            backup_file = self.backup_dir / filename
            if not backup_file.exists():
                return {
                    "success": False,
                    "message": f"备份文件不存在: {filename}"
                }

            # 删除文件
            backup_file.unlink()

            # 删除元数据文件
            meta_file = self.backup_dir / f"{filename}.meta"
            if meta_file.exists():
                meta_file.unlink()

            return {
                "success": True,
                "message": f"备份文件已删除: {filename}"
            }

        except Exception as e:
            return {
                "success": False,
                "message": f"删除失败: {str(e)}",
                "error": str(e)
            }

    def get_backup_info(self, filename):
        """
        获取备份文件详细信息

        Args:
            filename: 备份文件名

        Returns:
            dict: 备份信息
        """
        backup_file = self.backup_dir / filename

        if not backup_file.exists():
            return None

        stat = backup_file.stat()
        metadata = self._load_metadata(filename)

        # 尝试从ZIP文件中提取更多信息
        try:
            with zipfile.ZipFile(backup_file, 'r') as zipf:
                file_list = zipf.namelist()
                sql_files = [f for f in file_list if f.endswith('.sql')]

                if sql_files:
                    with zipf.open(sql_files[0]) as f:
                        first_line = f.readline().decode('utf-8', errors='ignore')
        except:
            first_line = ""

        return {
            "filename": filename,
            "path": str(backup_file),
            "size": self._format_size(stat.st_size),
            "created_time": datetime.fromtimestamp(stat.st_ctime),
            "modified_time": datetime.fromtimestamp(stat.st_mtime),
            "metadata": metadata or {},
            "contains_sql": len(sql_files) > 0 if 'sql_files' in locals() else False,
            "preview": first_line[:200] if first_line else ""
        }

    def _create_backup_info(self, backup_type, comment):
        """创建备份信息文件内容"""
        info = f"""数据库备份信息
====================
数据库: {self.db_name}
备份类型: {backup_type}
备份时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
说明: {comment}
主机: {self.db_host}
用户: {self.db_user}
表数量: {self._get_table_count()}
系统版本: 学生公寓交费管理系统 v1.0
====================
注意事项:
1. 此备份文件包含数据库的结构和数据
2. 使用mysql命令进行恢复: mysql -u用户名 -p密码 数据库名 < 备份文件.sql
3. 恢复前请确保数据库已创建
"""
        return info

    def _get_table_count(self):
        """获取数据库表数量"""
        try:
            import pymysql
            conn = pymysql.connect(
                host=self.db_host,
                user=self.db_user,
                password=self.db_password,
                database=self.db_name
            )

            with conn.cursor() as cursor:
                cursor.execute("SHOW TABLES")
                count = len(cursor.fetchall())

            conn.close()
            return count
        except:
            return "未知"

    def _save_metadata(self, metadata):
        """保存备份元数据"""
        meta_file = self.backup_dir / f"{metadata['filename']}.meta"

        import json
        with open(meta_file, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, ensure_ascii=False, indent=2)

    def _load_metadata(self, filename):
        """加载备份元数据"""
        meta_file = self.backup_dir / f"{filename}.meta"

        if not meta_file.exists():
            return None

        try:
            import json
            with open(meta_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return None

    def _format_size(self, size_bytes):
        """格式化文件大小"""
        if size_bytes == 0:
            return "0B"

        size_units = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_units) - 1:
            size_bytes /= 1024
            i += 1

        return f"{size_bytes:.2f} {size_units[i]}"

    def get_disk_usage(self):
        """获取备份磁盘使用情况"""
        total_size = 0
        backup_count = 0

        for file_path in self.backup_dir.glob("*"):
            if file_path.is_file():
                total_size += file_path.stat().st_size
                if file_path.suffix == '.zip':
                    backup_count += 1

        return {
            "total_size": self._format_size(total_size),
            "total_size_bytes": total_size,
            "backup_count": backup_count,
            "backup_dir": str(self.backup_dir.absolute())
        }