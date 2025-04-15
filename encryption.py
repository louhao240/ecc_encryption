"""
ECC-AES混合加密系统（最高安全级别）
使用椭圆曲线加密(ECC P-521)和AES-256-GCM实现的极高安全性混合加密系统
"""
import os
import base64
import json
from typing import Tuple, Dict, List, Optional, Union
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# 常量定义 - 最高安全级别设置
ECC_CURVE = ec.SECP521R1()  # P-521曲线，提供极高安全强度（约256位安全强度，相当于15000+位RSA）
AES_KEY_SIZE = 32  # AES-256需要32字节密钥
AES_NONCE_SIZE = 16  # 增加GCM nonce为16字节（最大值）
AUTH_TAG_SIZE = 16  # GCM验证标签大小，16字节为最大值
HASH_ALGORITHM = hashes.SHA512()  # 升级到SHA-512提供512位摘要
KDF_INFO = b'ECC-P521-AES-256-GCM-Encryption-v2'  # 密钥派生信息，确保唯一性

# 安全随机生成增强函数
def secure_random(size):
    """生成高质量随机数据"""
    return os.urandom(size)


def generate_key_pair() -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """生成P-521椭圆曲线加密的密钥对（最高安全强度）"""
    private_key = ec.generate_private_key(
        curve=ECC_CURVE,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_key_pair(private_key: ec.EllipticCurvePrivateKey,
                  public_key: ec.EllipticCurvePublicKey,
                  private_key_path: str,
                  public_key_path: str):
    """保存ECC密钥对到文件，使用最安全的序列化选项"""
    # 序列化私钥（使用最安全的序列化格式）
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # 序列化公钥
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # 写入文件
    with open(private_key_path, 'wb') as f:
        f.write(pem_private)
    
    with open(public_key_path, 'wb') as f:
        f.write(pem_public)


def load_public_key(public_key_path: str) -> ec.EllipticCurvePublicKey:
    """从文件加载ECC公钥"""
    with open(public_key_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise TypeError("提供的密钥不是椭圆曲线公钥")
    return public_key


def load_private_key(private_key_path: str) -> ec.EllipticCurvePrivateKey:
    """从文件加载ECC私钥"""
    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise TypeError("提供的密钥不是椭圆曲线私钥")
    return private_key


def derive_key_with_enhanced_kdf(shared_key: bytes, salt: bytes) -> bytes:
    """
    增强的密钥派生函数，将共享密钥转换为适合AES的密钥
    使用HKDF与SHA-512和额外的安全参数
    """
    # 使用HKDF与SHA-512，增加安全强度
    derived_key = HKDF(
        algorithm=HASH_ALGORITHM,
        length=AES_KEY_SIZE,
        salt=salt,
        info=KDF_INFO,
        backend=default_backend()
    ).derive(shared_key)
    
    return derived_key


def encrypt_data(data: bytes, public_key: ec.EllipticCurvePublicKey) -> bytes:
    """
    使用增强版混合加密（ECC P-521 + AES-256-GCM）加密数据
    
    过程:
    1. 为此次加密生成随机的ECC临时密钥对
    2. 与接收方公钥进行ECDH密钥协商，生成共享密钥
    3. 使用增强KDF派生AES密钥
    4. 生成高强度随机nonce和salt
    5. 使用AES-256-GCM加密数据及认证标签
    6. 返回临时公钥和加密数据的组合
    
    提供极高安全性和完美前向保密
    """
    # 为此次加密生成临时ECC密钥对（每次加密使用新密钥对，确保前向保密）
    ephemeral_private_key = ec.generate_private_key(
        curve=ECC_CURVE,
        backend=default_backend()
    )
    ephemeral_public_key = ephemeral_private_key.public_key()
    
    # 密钥协商 - 计算共享密钥
    shared_key = ephemeral_private_key.exchange(
        ec.ECDH(),
        public_key
    )
    
    # 生成随机salt，增强KDF安全性
    salt = secure_random(32)
    
    # 使用增强KDF从共享密钥派生出AES密钥
    derived_key = derive_key_with_enhanced_kdf(shared_key, salt)
    
    # 生成随机nonce，使用增强的长度
    nonce = secure_random(AES_NONCE_SIZE)
    
    # 使用AES-256-GCM加密数据，提供认证和加密
    aesgcm = AESGCM(derived_key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    
    # 序列化临时公钥
    ephemeral_public_bytes = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )
    
    # 构建包含版本信息的头
    version = b'\x01'  # 版本标记，便于未来识别不同加密格式
    
    # 组合结果: {版本(1字节) | 公钥长度(2字节) | 临时公钥 | salt(32字节) | nonce | 密文}
    key_length = len(ephemeral_public_bytes).to_bytes(2, byteorder='big')
    result = version + key_length + ephemeral_public_bytes + salt + nonce + ciphertext
    
    return result


def decrypt_data(encrypted_data: bytes, private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """
    使用私钥解密混合加密的数据
    
    过程:
    1. 解析加密数据结构，提取所有组件
    2. 验证版本信息
    3. 提取临时公钥、salt和nonce
    4. 使用私钥和临时公钥进行ECDH密钥协商
    5. 使用相同的KDF参数派生AES密钥
    6. 使用AES-GCM解密数据，同时验证数据完整性
    """
    try:
        # 解析数据结构
        version = encrypted_data[0:1]
        
        # 检查版本兼容性
        if version != b'\x01':
            raise ValueError(f"不支持的加密版本: {version.hex()}")
        
        # 继续解析数据
        key_length = int.from_bytes(encrypted_data[1:3], byteorder='big')
        key_end_pos = 3 + key_length
        ephemeral_public_bytes = encrypted_data[3:key_end_pos]
        
        # 提取salt (32字节)
        salt = encrypted_data[key_end_pos:key_end_pos+32]
        
        # 提取nonce
        nonce = encrypted_data[key_end_pos+32:key_end_pos+32+AES_NONCE_SIZE]
        
        # 提取密文
        ciphertext = encrypted_data[key_end_pos+32+AES_NONCE_SIZE:]
        
        # 重构临时公钥
        ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            curve=ECC_CURVE,
            data=ephemeral_public_bytes
        )
        
        # 密钥协商 - 计算共享密钥
        shared_key = private_key.exchange(
            ec.ECDH(),
            ephemeral_public_key
        )
        
        # 用相同的KDF参数派生AES密钥
        derived_key = derive_key_with_enhanced_kdf(shared_key, salt)
        
        # 使用AES-GCM解密数据
        aesgcm = AESGCM(derived_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        return plaintext
    except Exception as e:
        raise ValueError(f"解密失败 (可能是密钥不匹配或数据损坏): {str(e)}")


def encrypt_file(file_path: str, public_key: ec.EllipticCurvePublicKey, 
                output_path: Optional[str] = None, overwrite: bool = False) -> str:
    """
    使用ECC混合加密系统加密文件
    
    参数:
        file_path: 要加密的文件路径
        public_key: 接收方公钥
        output_path: 输出文件路径，默认为原文件路径加.encrypted后缀
        overwrite: 是否覆盖原文件
    
    返回:
        输出文件路径
    """
    # 设置输出路径
    if overwrite:
        output_path = file_path
    elif output_path is None:
        output_path = file_path + '.encrypted'
    
    # 读取文件内容
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # 加密数据
    encrypted_data = encrypt_data(data, public_key)
    
    # 写入加密后的数据
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)
    
    return output_path


def decrypt_file(encrypted_file_path: str, private_key: ec.EllipticCurvePrivateKey,
                output_path: Optional[str] = None, overwrite: bool = False) -> str:
    """
    使用ECC混合加密系统解密文件
    
    参数:
        encrypted_file_path: 要解密的文件路径
        private_key: 接收方私钥
        output_path: 输出文件路径，默认为去掉.encrypted后缀
        overwrite: 是否覆盖原文件
    
    返回:
        输出文件路径
    """
    # 设置输出路径
    if overwrite:
        output_path = encrypted_file_path
    elif output_path is None:
        # 移除.encrypted后缀（如果有）
        if encrypted_file_path.endswith('.encrypted'):
            output_path = encrypted_file_path[:-10]
        else:
            output_path = encrypted_file_path + '.decrypted'
    
    # 读取加密的文件内容
    with open(encrypted_file_path, 'rb') as f:
        encrypted_data = f.read()
    
    # 解密数据
    decrypted_data = decrypt_data(encrypted_data, private_key)
    
    # 写入解密后的数据
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)
    
    return output_path


def encrypt_directory(directory_path: str, public_key: ec.EllipticCurvePublicKey,
                     output_directory: Optional[str] = None, overwrite: bool = False) -> List[Tuple[str, str]]:
    """
    加密目录中的所有文件
    
    参数:
        directory_path: 要加密的目录路径
        public_key: 接收方公钥
        output_directory: 输出目录路径，默认为原目录路径加_encrypted后缀
        overwrite: 是否覆盖原文件
    
    返回:
        (源文件路径, 加密后文件路径)列表
    """
    # 设置输出目录
    if overwrite:
        output_directory = directory_path
    elif output_directory is None:
        output_directory = directory_path + '_encrypted'
    
    # 创建输出目录（如果不是覆盖模式）
    if not overwrite and not os.path.exists(output_directory):
        os.makedirs(output_directory, exist_ok=True)
    
    encrypted_files = []
    
    for root, _, files in os.walk(directory_path):
        # 创建对应的子目录（如果不是覆盖模式）
        if not overwrite:
            rel_path = os.path.relpath(root, directory_path)
            if rel_path != '.':
                os.makedirs(os.path.join(output_directory, rel_path), exist_ok=True)
        
        for file in files:
            file_path = os.path.join(root, file)
            
            # 设置输出文件路径
            if overwrite:
                output_file_path = file_path
            else:
                rel_file_path = os.path.relpath(file_path, directory_path)
                output_file_path = os.path.join(output_directory, rel_file_path + '.encrypted')
            
            try:
                # 加密文件
                encrypt_file(file_path, public_key, output_file_path, overwrite)
                encrypted_files.append((file_path, output_file_path))
            except Exception as e:
                print(f"加密文件 {file_path} 时出错: {e}")
    
    return encrypted_files


def decrypt_directory(encrypted_directory_path: str, private_key: ec.EllipticCurvePrivateKey,
                     output_directory: Optional[str] = None, overwrite: bool = False) -> List[Tuple[str, str]]:
    """
    解密目录中的所有文件
    
    参数:
        encrypted_directory_path: 要解密的目录路径
        private_key: 接收方私钥
        output_directory: 输出目录路径，默认为原目录路径替换_encrypted为_decrypted
        overwrite: 是否覆盖原文件
    
    返回:
        (加密文件路径, 解密后文件路径)列表
    """
    # 设置输出目录
    if overwrite:
        output_directory = encrypted_directory_path
    elif output_directory is None:
        if encrypted_directory_path.endswith('_encrypted'):
            output_directory = encrypted_directory_path[:-10] + '_decrypted'
        else:
            output_directory = encrypted_directory_path + '_decrypted'
    
    # 创建输出目录（如果不是覆盖模式）
    if not overwrite and not os.path.exists(output_directory):
        os.makedirs(output_directory, exist_ok=True)
    
    decrypted_files = []
    
    for root, _, files in os.walk(encrypted_directory_path):
        # 创建对应的子目录（如果不是覆盖模式）
        if not overwrite:
            rel_path = os.path.relpath(root, encrypted_directory_path)
            if rel_path != '.':
                os.makedirs(os.path.join(output_directory, rel_path), exist_ok=True)
        
        for file in files:
            file_path = os.path.join(root, file)
            
            # 设置输出文件路径
            if overwrite:
                output_file_path = file_path
            elif file.endswith('.encrypted'):
                rel_file_path = os.path.relpath(file_path, encrypted_directory_path)
                output_file_path = os.path.join(output_directory, rel_file_path[:-10])  # 移除.encrypted后缀
            else:
                # 跳过没有.encrypted后缀的文件（如果不是覆盖模式）
                continue
            
            try:
                # 解密文件
                decrypt_file(file_path, private_key, output_file_path, overwrite)
                decrypted_files.append((file_path, output_file_path))
            except Exception as e:
                print(f"解密文件 {file_path} 时出错: {e}")
    
    return decrypted_files 