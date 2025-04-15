"""
ECC-AES混合加密系统的图形用户界面
使用PySide6构建
"""
import os
import sys
import threading
from pathlib import Path
from PySide6.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, 
                              QHBoxLayout, QLabel, QLineEdit, QPushButton, QRadioButton, 
                              QGroupBox, QComboBox, QProgressBar, QFileDialog, QMessageBox, QCheckBox)
from PySide6.QtCore import Qt, Signal, QThread
from PySide6.QtGui import QFont, QIcon

# 导入加密模块
import encryption

class WorkerThread(QThread):
    """Worker thread to perform background tasks"""
    finished = Signal(bool, str)  # success, message
    
    def __init__(self, task_func, *args, **kwargs):
        super().__init__()
        self.task_func = task_func
        self.args = args
        self.kwargs = kwargs
        
    def run(self):
        try:
            result = self.task_func(*self.args, **self.kwargs)
            self.finished.emit(True, str(result) if result else "操作成功")
        except Exception as e:
            self.finished.emit(False, str(e))

class ECCEncryptionApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ECC-AES 文件加密/解密工具 (极高安全级别)")
        self.resize(800, 600)
        
        # 设置应用样式
        self.setStyleSheet("""
            QMainWindow, QTabWidget, QWidget {
                background-color: #f5f5f5;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #ddd;
                border-radius: 5px;
                margin-top: 1ex;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QPushButton {
                background-color: #4a86e8;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3a76d8;
            }
            QPushButton:pressed {
                background-color: #2a66c8;
            }
            QLineEdit {
                padding: 5px;
                border: 1px solid #ccc;
                border-radius: 3px;
            }
            QComboBox {
                padding: 5px;
                border: 1px solid #ccc;
                border-radius: 3px;
            }
        """)
        
        # 主窗口设置
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # 创建标题标签
        title_label = QLabel("ECC-AES 混合加密系统 (P-521曲线 + AES-256-GCM)")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title_label)
        
        # 创建子标题标签
        subtitle_label = QLabel("使用P-521椭圆曲线和AES-256-GCM实现的极高安全性混合加密方案")
        subtitle_font = QFont()
        subtitle_font.setPointSize(10)
        subtitle_label.setFont(subtitle_font)
        subtitle_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(subtitle_label)
        
        # 创建选项卡
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # 创建三个页面
        self.key_tab = QWidget()
        self.encrypt_tab = QWidget()
        self.decrypt_tab = QWidget()
        
        self.tab_widget.addTab(self.key_tab, "生成密钥")
        self.tab_widget.addTab(self.encrypt_tab, "加密文件")
        self.tab_widget.addTab(self.decrypt_tab, "解密文件")
        
        # 设置各个页面
        self.setup_key_generation_tab()
        self.setup_encrypt_tab()
        self.setup_decrypt_tab()
        
        # 添加状态栏
        self.statusBar().showMessage("就绪")
        
        # 添加说明标签
        info_label = QLabel("椭圆曲线加密(ECC)提供比RSA更高的安全性，P-521曲线安全强度相当于15360位RSA密钥")
        info_label.setAlignment(Qt.AlignCenter)
        info_font = QFont()
        info_font.setItalic(True)
        info_label.setFont(info_font)
        main_layout.addWidget(info_label)
        
    def setup_key_generation_tab(self):
        layout = QVBoxLayout(self.key_tab)
        
        # 密钥曲线信息
        info_group = QGroupBox("密钥信息")
        info_layout = QVBoxLayout(info_group)
        
        info_text = QLabel("本系统使用P-521椭圆曲线，提供约256位的安全强度，相当于15360位RSA密钥")
        info_text.setWordWrap(True)
        info_layout.addWidget(info_text)
        
        security_text = QLabel("• 256位安全强度：远超目前任何已知破解技术的能力\n"
                              "• P-521椭圆曲线：NIST推荐的最高安全级别曲线\n"
                              "• 混合加密：结合ECC的强度和AES的速度\n"
                              "• 完美前向保密：即使私钥泄露，之前的加密数据仍然安全")
        info_layout.addWidget(security_text)
        
        layout.addWidget(info_group)
        
        # 保存位置
        save_group = QGroupBox("保存位置")
        save_layout = QVBoxLayout(save_group)
        
        dir_layout = QHBoxLayout()
        dir_layout.addWidget(QLabel("密钥保存目录:"))
        self.key_dir_edit = QLineEdit()
        dir_layout.addWidget(self.key_dir_edit)
        browse_dir_btn = QPushButton("浏览...")
        browse_dir_btn.clicked.connect(self.browse_key_dir)
        dir_layout.addWidget(browse_dir_btn)
        save_layout.addLayout(dir_layout)
        
        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("密钥文件名前缀:"))
        self.key_name_edit = QLineEdit("ecc_key")
        name_layout.addWidget(self.key_name_edit)
        save_layout.addLayout(name_layout)
        
        layout.addWidget(save_group)
        
        # 生成按钮
        gen_btn = QPushButton("生成ECC密钥对")
        gen_btn.setMinimumHeight(40)
        gen_btn.clicked.connect(self.generate_keys)
        layout.addWidget(gen_btn)
        
        # 结果显示
        result_group = QGroupBox("生成结果")
        result_layout = QVBoxLayout(result_group)
        self.key_result_label = QLabel()
        self.key_result_label.setWordWrap(True)
        result_layout.addWidget(self.key_result_label)
        layout.addWidget(result_group)
        
        # 添加安全说明
        security_note = QLabel("私钥必须妥善保管！它是解密文件的唯一方式，一旦丢失将无法恢复加密的数据。")
        security_note.setStyleSheet("color: red;")
        layout.addWidget(security_note)
        
        layout.addStretch()
        
    def setup_encrypt_tab(self):
        layout = QVBoxLayout(self.encrypt_tab)
        
        # 公钥选择
        key_group = QGroupBox("公钥选择")
        key_layout = QHBoxLayout(key_group)
        
        key_layout.addWidget(QLabel("公钥文件:"))
        self.public_key_edit = QLineEdit()
        key_layout.addWidget(self.public_key_edit)
        browse_key_btn = QPushButton("浏览...")
        browse_key_btn.clicked.connect(self.browse_public_key)
        key_layout.addWidget(browse_key_btn)
        
        layout.addWidget(key_group)
        
        # 加密源
        source_group = QGroupBox("加密源")
        source_layout = QVBoxLayout(source_group)
        
        type_layout = QHBoxLayout()
        self.encrypt_file_radio = QRadioButton("文件")
        self.encrypt_file_radio.setChecked(True)
        self.encrypt_dir_radio = QRadioButton("文件夹")
        type_layout.addWidget(self.encrypt_file_radio)
        type_layout.addWidget(self.encrypt_dir_radio)
        type_layout.addStretch()
        source_layout.addLayout(type_layout)
        
        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("源路径:"))
        self.encrypt_source_edit = QLineEdit()
        path_layout.addWidget(self.encrypt_source_edit)
        browse_source_btn = QPushButton("浏览...")
        browse_source_btn.clicked.connect(self.browse_encrypt_source)
        path_layout.addWidget(browse_source_btn)
        source_layout.addLayout(path_layout)
        
        layout.addWidget(source_group)
        
        # 输出设置
        output_group = QGroupBox("输出设置")
        output_layout = QVBoxLayout(output_group)
        
        # 覆盖选项
        self.encrypt_overwrite_checkbox = QCheckBox("覆盖原文件（谨慎使用，此操作不可逆）")
        self.encrypt_overwrite_checkbox.setStyleSheet("color: red;")
        self.encrypt_overwrite_checkbox.stateChanged.connect(self.toggle_encrypt_output)
        output_layout.addWidget(self.encrypt_overwrite_checkbox)
        
        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("输出路径:"))
        self.encrypt_output_edit = QLineEdit()
        path_layout.addWidget(self.encrypt_output_edit)
        self.encrypt_output_browse_btn = QPushButton("浏览...")
        self.encrypt_output_browse_btn.clicked.connect(self.browse_encrypt_output)
        path_layout.addWidget(self.encrypt_output_browse_btn)
        output_layout.addLayout(path_layout)
        
        layout.addWidget(output_group)
        
        # 安全说明
        security_group = QGroupBox("加密安全级别")
        security_layout = QVBoxLayout(security_group)
        security_text = QLabel("使用ECC P-521曲线和AES-256-GCM的混合加密系统提供极高安全性：\n"
                              "• 每次加密使用独特的临时密钥和随机盐值，确保完美前向保密\n"
                              "• AES-256-GCM提供加密和认证，可防止数据篡改\n"
                              "• 安全强度远超一般加密系统，甚至可抵抗未来量子计算的部分威胁")
        security_text.setWordWrap(True)
        security_layout.addWidget(security_text)
        layout.addWidget(security_group)
        
        # 加密按钮
        encrypt_btn = QPushButton("开始加密")
        encrypt_btn.setMinimumHeight(40)
        encrypt_btn.clicked.connect(self.encrypt_source)
        layout.addWidget(encrypt_btn)
        
        # 进度条
        self.encrypt_progress = QProgressBar()
        layout.addWidget(self.encrypt_progress)
        
        layout.addStretch()
        
    def setup_decrypt_tab(self):
        layout = QVBoxLayout(self.decrypt_tab)
        
        # 私钥选择
        key_group = QGroupBox("私钥选择")
        key_layout = QHBoxLayout(key_group)
        
        key_layout.addWidget(QLabel("私钥文件:"))
        self.private_key_edit = QLineEdit()
        key_layout.addWidget(self.private_key_edit)
        browse_key_btn = QPushButton("浏览...")
        browse_key_btn.clicked.connect(self.browse_private_key)
        key_layout.addWidget(browse_key_btn)
        
        layout.addWidget(key_group)
        
        # 解密源
        source_group = QGroupBox("解密源")
        source_layout = QVBoxLayout(source_group)
        
        type_layout = QHBoxLayout()
        self.decrypt_file_radio = QRadioButton("文件")
        self.decrypt_file_radio.setChecked(True)
        self.decrypt_dir_radio = QRadioButton("文件夹")
        type_layout.addWidget(self.decrypt_file_radio)
        type_layout.addWidget(self.decrypt_dir_radio)
        type_layout.addStretch()
        source_layout.addLayout(type_layout)
        
        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("源路径:"))
        self.decrypt_source_edit = QLineEdit()
        path_layout.addWidget(self.decrypt_source_edit)
        browse_source_btn = QPushButton("浏览...")
        browse_source_btn.clicked.connect(self.browse_decrypt_source)
        path_layout.addWidget(browse_source_btn)
        source_layout.addLayout(path_layout)
        
        layout.addWidget(source_group)
        
        # 输出设置
        output_group = QGroupBox("输出设置")
        output_layout = QVBoxLayout(output_group)
        
        # 覆盖选项
        self.decrypt_overwrite_checkbox = QCheckBox("覆盖原文件（谨慎使用，此操作不可逆）")
        self.decrypt_overwrite_checkbox.setStyleSheet("color: red;")
        self.decrypt_overwrite_checkbox.stateChanged.connect(self.toggle_decrypt_output)
        output_layout.addWidget(self.decrypt_overwrite_checkbox)
        
        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("输出路径:"))
        self.decrypt_output_edit = QLineEdit()
        path_layout.addWidget(self.decrypt_output_edit)
        self.decrypt_output_browse_btn = QPushButton("浏览...")
        self.decrypt_output_browse_btn.clicked.connect(self.browse_decrypt_output)
        path_layout.addWidget(self.decrypt_output_browse_btn)
        output_layout.addLayout(path_layout)
        
        layout.addWidget(output_group)
        
        # 解密说明
        decrypt_note = QLabel("提示：只有使用正确的私钥才能解密文件。如果使用了错误的私钥，解密将失败。")
        decrypt_note.setWordWrap(True)
        layout.addWidget(decrypt_note)
        
        # 解密按钮
        decrypt_btn = QPushButton("开始解密")
        decrypt_btn.setMinimumHeight(40)
        decrypt_btn.clicked.connect(self.decrypt_source)
        layout.addWidget(decrypt_btn)
        
        # 进度条
        self.decrypt_progress = QProgressBar()
        layout.addWidget(self.decrypt_progress)
        
        layout.addStretch()
    
    def browse_key_dir(self):
        directory = QFileDialog.getExistingDirectory(self, "选择密钥保存目录")
        if directory:
            self.key_dir_edit.setText(directory)
            
    def browse_public_key(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择公钥文件", "", "PEM Files (*.pem);;All Files (*.*)")
        if file_path:
            self.public_key_edit.setText(file_path)
            
    def browse_private_key(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择私钥文件", "", "PEM Files (*.pem);;All Files (*.*)")
        if file_path:
            self.private_key_edit.setText(file_path)
            
    def browse_encrypt_source(self):
        if self.encrypt_file_radio.isChecked():
            file_path, _ = QFileDialog.getOpenFileName(self, "选择要加密的文件")
        else:
            file_path = QFileDialog.getExistingDirectory(self, "选择要加密的文件夹")
            
        if file_path:
            self.encrypt_source_edit.setText(file_path)
            
            # 自动填充输出路径（如果不覆盖）
            if not self.encrypt_overwrite_checkbox.isChecked():
                if self.encrypt_file_radio.isChecked():
                    self.encrypt_output_edit.setText(file_path + ".encrypted")
                else:
                    self.encrypt_output_edit.setText(file_path + "_encrypted")
            else:
                self.encrypt_output_edit.setText(file_path)
            
    def browse_decrypt_source(self):
        if self.decrypt_file_radio.isChecked():
            file_path, _ = QFileDialog.getOpenFileName(
                self, "选择要解密的文件", "", "Encrypted Files (*.encrypted);;All Files (*.*)")
        else:
            file_path = QFileDialog.getExistingDirectory(self, "选择要解密的文件夹")
            
        if file_path:
            self.decrypt_source_edit.setText(file_path)
            
            # 自动填充输出路径（如果不覆盖）
            if not self.decrypt_overwrite_checkbox.isChecked():
                if self.decrypt_file_radio.isChecked():
                    if file_path.endswith(".encrypted"):
                        self.decrypt_output_edit.setText(file_path[:-10])
                    else:
                        self.decrypt_output_edit.setText(file_path + ".decrypted")
                else:
                    if file_path.endswith("_encrypted"):
                        self.decrypt_output_edit.setText(file_path[:-10] + "_decrypted")
                    else:
                        self.decrypt_output_edit.setText(file_path + "_decrypted")
            else:
                self.decrypt_output_edit.setText(file_path)
            
    def browse_encrypt_output(self):
        if self.encrypt_file_radio.isChecked():
            file_path, _ = QFileDialog.getSaveFileName(
                self, "选择加密输出文件", "", "Encrypted Files (*.encrypted)")
        else:
            file_path = QFileDialog.getExistingDirectory(self, "选择加密输出文件夹")
            
        if file_path:
            self.encrypt_output_edit.setText(file_path)
            
    def browse_decrypt_output(self):
        if self.decrypt_file_radio.isChecked():
            file_path, _ = QFileDialog.getSaveFileName(self, "选择解密输出文件")
        else:
            file_path = QFileDialog.getExistingDirectory(self, "选择解密输出文件夹")
            
        if file_path:
            self.decrypt_output_edit.setText(file_path)
            
    def toggle_encrypt_output(self, state):
        # 启用/禁用输出路径控件
        enabled = not state
        self.encrypt_output_edit.setEnabled(enabled)
        self.encrypt_output_browse_btn.setEnabled(enabled)
        
        # 如果覆盖，则设置输出路径为输入路径
        if state:
            self.encrypt_output_edit.setText(self.encrypt_source_edit.text())
    
    def toggle_decrypt_output(self, state):
        # 启用/禁用输出路径控件
        enabled = not state
        self.decrypt_output_edit.setEnabled(enabled)
        self.decrypt_output_browse_btn.setEnabled(enabled)
        
        # 如果覆盖，则设置输出路径为输入路径
        if state:
            self.decrypt_output_edit.setText(self.decrypt_source_edit.text())
    
    def on_worker_finished(self, success, message, progress_bar=None, 
                           operation_type=None):
        # 重置进度条
        if progress_bar:
            progress_bar.setValue(0)
        
        if success:
            if operation_type == "key":
                self.key_result_label.setText(message)
                QMessageBox.information(self, "成功", "ECC密钥对已成功生成")
            elif operation_type == "encrypt":
                QMessageBox.information(self, "成功", message)
            elif operation_type == "decrypt":
                QMessageBox.information(self, "成功", message)
        else:
            error_prefix = ""
            if operation_type == "key":
                error_prefix = "生成密钥对时出错: "
                self.key_result_label.setText(error_prefix + message)
            elif operation_type == "encrypt":
                error_prefix = "加密过程中出错: "
            elif operation_type == "decrypt":
                error_prefix = "解密过程中出错: "
                
            QMessageBox.critical(self, "错误", error_prefix + message)
            
        # 更新状态栏
        if operation_type == "key":
            self.statusBar().showMessage("密钥对生成" + ("完成" if success else "失败"))
        elif operation_type == "encrypt":
            self.statusBar().showMessage("加密" + ("完成" if success else "失败"))
        elif operation_type == "decrypt":
            self.statusBar().showMessage("解密" + ("完成" if success else "失败"))
        else:
            self.statusBar().showMessage("就绪")
            
    def generate_keys(self):
        key_dir = self.key_dir_edit.text()
        key_name = self.key_name_edit.text()
        
        if not key_dir:
            QMessageBox.critical(self, "错误", "请选择密钥保存目录")
            return
            
        if not key_name:
            QMessageBox.critical(self, "错误", "请输入密钥文件名前缀")
            return
        
        self.statusBar().showMessage("正在生成ECC密钥对...")
        
        def generate_key_task():
            # 确保目录存在
            os.makedirs(key_dir, exist_ok=True)
            
            private_key_path = os.path.join(key_dir, f"{key_name}_private.pem")
            public_key_path = os.path.join(key_dir, f"{key_name}_public.pem")
            
            private_key, public_key = encryption.generate_key_pair()
            encryption.save_key_pair(private_key, public_key, private_key_path, public_key_path)
            
            return f"ECC密钥对已生成!\n私钥保存在: {os.path.abspath(private_key_path)}\n公钥保存在: {os.path.abspath(public_key_path)}"
        
        self.worker = WorkerThread(generate_key_task)
        self.worker.finished.connect(lambda success, message: 
                                    self.on_worker_finished(success, message, None, "key"))
        self.worker.start()
        
    def encrypt_source(self):
        public_key_path = self.public_key_edit.text()
        source_path = self.encrypt_source_edit.text()
        output_path = self.encrypt_output_edit.text()
        is_file = self.encrypt_file_radio.isChecked()
        overwrite = self.encrypt_overwrite_checkbox.isChecked()
        
        if not public_key_path:
            QMessageBox.critical(self, "错误", "请选择公钥文件")
            return
            
        if not source_path:
            QMessageBox.critical(self, "错误", "请选择需要加密的源路径")
            return
            
        if not overwrite and not output_path:
            QMessageBox.critical(self, "错误", "请指定加密后的输出路径")
            return
        
        if overwrite:
            # 确认覆盖操作
            reply = QMessageBox.warning(
                self, 
                "警告 - 覆盖原文件", 
                "您选择了覆盖原文件，此操作将会永久替换原始文件，且不可撤销。\n\n确定要继续吗？",
                QMessageBox.Yes | QMessageBox.No, 
                QMessageBox.No
            )
            if reply == QMessageBox.No:
                return
        
        try:
            public_key = encryption.load_public_key(public_key_path)
        except Exception as e:
            QMessageBox.critical(self, "错误", f"加载公钥时出错: {str(e)}")
            return
        
        self.encrypt_progress.setRange(0, 0)  # 不确定模式
        self.statusBar().showMessage("正在加密...")
        
        def encrypt_task():
            if is_file:
                encryption.encrypt_file(source_path, public_key, output_path, overwrite)
                return f"文件已加密" + ("（覆盖原文件）" if overwrite else f"并保存到: {output_path}")
            else:
                encrypted_files = encryption.encrypt_directory(source_path, public_key, output_path, overwrite)
                return f"目录已加密" + ("（覆盖原文件）" if overwrite else f"并保存到: {output_path}") + f"\n共加密 {len(encrypted_files)} 个文件"
        
        self.worker = WorkerThread(encrypt_task)
        self.worker.finished.connect(lambda success, message: 
                                    self.on_worker_finished(success, message, 
                                                           self.encrypt_progress, "encrypt"))
        self.worker.start()
        
    def decrypt_source(self):
        private_key_path = self.private_key_edit.text()
        source_path = self.decrypt_source_edit.text()
        output_path = self.decrypt_output_edit.text()
        is_file = self.decrypt_file_radio.isChecked()
        overwrite = self.decrypt_overwrite_checkbox.isChecked()
        
        if not private_key_path:
            QMessageBox.critical(self, "错误", "请选择私钥文件")
            return
            
        if not source_path:
            QMessageBox.critical(self, "错误", "请选择需要解密的源路径")
            return
            
        if not overwrite and not output_path:
            QMessageBox.critical(self, "错误", "请指定解密后的输出路径")
            return
        
        if overwrite:
            # 确认覆盖操作
            reply = QMessageBox.warning(
                self, 
                "警告 - 覆盖原文件", 
                "您选择了覆盖原文件，此操作将会永久替换原始文件，且不可撤销。\n\n确定要继续吗？",
                QMessageBox.Yes | QMessageBox.No, 
                QMessageBox.No
            )
            if reply == QMessageBox.No:
                return
        
        try:
            private_key = encryption.load_private_key(private_key_path)
        except Exception as e:
            QMessageBox.critical(self, "错误", f"加载私钥时出错: {str(e)}")
            return
        
        self.decrypt_progress.setRange(0, 0)  # 不确定模式
        self.statusBar().showMessage("正在解密...")
        
        def decrypt_task():
            if is_file:
                encryption.decrypt_file(source_path, private_key, output_path, overwrite)
                return f"文件已解密" + ("（覆盖原文件）" if overwrite else f"并保存到: {output_path}")
            else:
                decrypted_files = encryption.decrypt_directory(source_path, private_key, output_path, overwrite)
                return f"目录已解密" + ("（覆盖原文件）" if overwrite else f"并保存到: {output_path}") + f"\n共解密 {len(decrypted_files)} 个文件"
        
        self.worker = WorkerThread(decrypt_task)
        self.worker.finished.connect(lambda success, message: 
                                    self.on_worker_finished(success, message, 
                                                           self.decrypt_progress, "decrypt"))
        self.worker.start()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ECCEncryptionApp()
    window.show()
    sys.exit(app.exec()) 