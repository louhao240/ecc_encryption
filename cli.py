#!/usr/bin/env python
"""
ECC-AES混合加密系统的命令行工具
支持生成密钥对、加密文件/目录
"""
import os
import sys
import argparse
import encryption

def main():
    """
    命令行工具，用于生成ECC密钥对、加密文件或目录。
    """
    parser = argparse.ArgumentParser(
        description="ECC-AES混合加密系统命令行工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 生成密钥对
  python cli.py --generate-keys --key-dir ./keys --key-name ecc_key

  # 加密文件（覆盖原文件）
  python cli.py --public-key ./keys/ecc_key_public.pem --path ./document.docx --overwrite

  # 加密文件（不覆盖原文件）
  python cli.py --public-key ./keys/ecc_key_public.pem --path ./document.docx --output ./document.docx.encrypted

  # 加密目录
  python cli.py --public-key ./keys/ecc_key_public.pem --path ./my_folder --output ./encrypted_folder
"""
    )
    parser.add_argument("--public-key", "-k", help="ECC公钥文件路径")
    parser.add_argument("--path", "-p", help="要加密的文件或目录路径")
    parser.add_argument("--overwrite", "-o", action="store_true", default=False, 
                        help="覆盖原文件（谨慎使用）")
    parser.add_argument("--output", "-out", help="指定输出路径（如果不想覆盖原文件）")
    
    # 密钥生成选项
    parser.add_argument("--generate-keys", "-g", action="store_true", 
                        help="生成新的ECC密钥对")
    parser.add_argument("--key-dir", "-d", default=".", 
                        help="密钥保存目录")
    parser.add_argument("--key-name", "-n", default="ecc_key", 
                        help="密钥文件名前缀")
    
    args = parser.parse_args()
    
    # 验证参数
    if not args.generate_keys and not args.public_key:
        parser.error("必须提供--public-key参数或使用--generate-keys生成新密钥")
        return 1
    
    # 生成密钥对
    if args.generate_keys:
        print(f"正在生成ECC密钥对...")
        return generate_keys(args.key_dir, args.key_name)
    
    # 验证加密参数
    if not args.path:
        parser.error("必须提供--path参数指定要加密的文件或目录")
        return 1
    
    # 如果指定了输出路径，则不覆盖
    if args.output:
        args.overwrite = False
    
    # 检查文件或目录是否存在
    if not os.path.exists(args.path):
        print(f"错误: 路径 '{args.path}' 不存在。")
        return 1
    
    # 检查公钥文件是否存在
    if not os.path.isfile(args.public_key):
        print(f"错误: 公钥文件 '{args.public_key}' 不存在。")
        return 1
    
    # 加载公钥
    try:
        public_key = encryption.load_public_key(args.public_key)
    except Exception as e:
        print(f"错误: 加载公钥时出错: {str(e)}")
        return 1
    
    # 确认覆盖操作
    if args.overwrite and not confirm_overwrite():
        print("操作已取消。")
        return 0
    
    # 执行加密
    try:
        if os.path.isfile(args.path):
            # 加密单个文件
            output = encryption.encrypt_file(args.path, public_key, args.output, args.overwrite)
            print(f"文件加密" + ("（已覆盖原文件）" if args.overwrite else f"完成，输出到: {output}"))
        else:
            # 加密整个目录
            encrypted_files = encryption.encrypt_directory(args.path, public_key, args.output, args.overwrite)
            print(f"目录加密" + ("（已覆盖原文件）" if args.overwrite else f"完成，输出到: {args.output if args.output else args.path + '_encrypted'}"))
            print(f"共加密 {len(encrypted_files)} 个文件。")
        
        return 0
    except Exception as e:
        print(f"错误: 加密过程中出错: {str(e)}")
        return 1

def generate_keys(key_dir, key_name):
    """生成ECC密钥对并保存到文件"""
    try:
        # 确保目录存在
        os.makedirs(key_dir, exist_ok=True)
        
        # 生成文件路径
        private_key_path = os.path.join(key_dir, f"{key_name}_private.pem")
        public_key_path = os.path.join(key_dir, f"{key_name}_public.pem")
        
        # 生成密钥对
        private_key, public_key = encryption.generate_key_pair()
        
        # 保存密钥对
        encryption.save_key_pair(private_key, public_key, private_key_path, public_key_path)
        
        print(f"ECC密钥对已生成:")
        print(f"私钥保存在: {os.path.abspath(private_key_path)}")
        print(f"公钥保存在: {os.path.abspath(public_key_path)}")
        print("\n提示: 公钥可以分发给需要加密数据的各方，私钥必须安全保管！")
        print("安全信息: 使用P-384椭圆曲线，安全强度相当于7680位RSA密钥")
    except Exception as e:
        print(f"错误: 生成密钥对时出错: {str(e)}")
        return 1
    
    return 0

def confirm_overwrite():
    """确认覆盖操作"""
    print("\n⚠️  警告: 覆盖操作将会永久替换原始文件，且不可逆！")
    while True:
        response = input("确认继续吗? (y/n): ").lower()
        if response in ['y', 'yes']:
            return True
        elif response in ['n', 'no']:
            return False
        print("请输入 'y' 或 'n'")

if __name__ == "__main__":
    sys.exit(main()) 