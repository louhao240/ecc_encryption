# ECC-AES 高安全性混合加密系统

这是一个基于椭圆曲线加密(ECC)和AES-256-GCM的混合加密系统，提供极高安全性的文件和目录加密。

## 安全性特点

- **椭圆曲线加密(P-384)**：提供192位安全强度，相当于7680位RSA密钥
- **AES-256-GCM**：最强的对称加密算法，带有消息认证功能，能检测数据篡改
- **临时密钥交换**：每次加密都使用新的临时密钥，提供完美前向保密性
- **安全密钥派生**：使用HKDF算法基于SHA-384安全推导加密密钥

## 系统优势

1. **更高安全性**：比RSA提供更高的安全等级
2. **更小的密钥**：ECC公钥只需RSA公钥的一小部分大小
3. **前向保密**：即使私钥泄露，之前加密的内容仍然安全
4. **公钥分发机制**：公钥可以安全分发，只有持有私钥者才能解密
5. **可处理任何类型文件**：不区分文件后缀，可加密任何文件或整个目录

## 安装

1. 确保已安装Python 3.7或更高版本
2. 安装所需依赖：

```bash
pip install -r requirements.txt
```

## 使用方法

### 图形界面

运行以下命令启动图形界面：

```bash
python gui.py
```

图形界面分为三个选项卡：

1. **生成密钥**：创建ECC密钥对
2. **加密文件**：使用公钥加密文件或目录
3. **解密文件**：使用私钥解密文件或目录

### 命令行工具

也提供命令行工具，适用于GUI不可用的环境：

#### 生成密钥对

```bash
python cli.py --generate-keys --key-dir ./keys --key-name ecc_key
```

#### 加密文件或目录

```bash
# 加密文件（覆盖原文件）
python cli.py --public-key ./keys/ecc_key_public.pem --path ./document.docx --overwrite

# 加密文件（不覆盖原文件）
python cli.py --public-key ./keys/ecc_key_public.pem --path ./document.docx --output ./document.docx.encrypted

# 加密目录
python cli.py --public-key ./keys/ecc_key_public.pem --path ./my_folder --output ./encrypted_folder
```

#### 解密文件或目录

```bash
# 解密文件（不覆盖原文件）
python decrypt_cli.py --private-key ./keys/ecc_key_private.pem --path ./document.docx.encrypted

# 解密文件（覆盖原文件）
python decrypt_cli.py --private-key ./keys/ecc_key_private.pem --path ./document.docx.encrypted --overwrite

# 解密目录
python decrypt_cli.py --private-key ./keys/ecc_key_private.pem --path ./encrypted_folder --output ./decrypted_folder
```

## 安全提示

- 私钥必须妥善保管，一旦丢失将无法恢复加密的数据
- 公钥可以自由分发给需要加密数据的各方
- 覆盖原文件操作不可逆，请谨慎使用
- 使用P-384曲线的安全强度远超目前已知的所有破解手段

## 技术实现

- 使用P-384椭圆曲线（SECP384R1）
- 混合加密流程：
  1. 为每次加密生成临时ECC密钥对
  2. 用接收方公钥与临时私钥进行ECDH密钥协商
  3. 用HKDF算法从共享密钥派生AES-256密钥
  4. 使用AES-256-GCM加密数据
  5. 组合临时公钥和加密数据，构成最终密文 