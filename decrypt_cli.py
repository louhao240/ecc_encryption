#!/usr/bin/env python
"""
ECC-AES混合加密系统的解密命令行工具
用于解密使用ECC加密的文件/目录
"""
import os
import sys
import argparse
import encryption

def main():
    """
    命令行工具，用于使用ECC私钥解密文件或目录。
    """
    parser = argparse.ArgumentParser(
        description="ECC-AES混合加密系统解密工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 解密文件（不覆盖原文件）
  python decrypt_cli.py --private-key ./keys/ecc_key_private.pem --path ./document.docx.encrypted

  # 解密文件（覆盖原文件）
  python decrypt_cli.py --private-key ./keys/ecc_key_private.pem --path ./document.docx.encrypted --overwrite

  # 解密目录
  python decrypt_cli.py --private-key ./keys/ecc_key_private.pem --path ./encrypted_folder --output ./decrypted_folder
"""
    )
    parser.add_argument("--private-key", "-k", required=True, help="ECC私钥文件路径")
    parser.add_argument("--path", "-p", required=True, help="要解密的文件或目录路径")
    parser.add_argument("--overwrite", "-o", action="store_true", default=False, 
                        help="覆盖原文件（谨慎使用）")
    parser.add_argument("--output", "-out", help="指定输出路径（如果不想覆盖原文件）")
    
    args = parser.parse_args()
    
    # 如果指定了输出路径，则不覆盖
    if args.output:
        args.overwrite = False
    
    # 检查文件或目录是否存在
    if not os.path.exists(args.path):
        print(f"错误: 路径 '{args.path}' 不存在。")
        return 1
    
    # 检查私钥文件是否存在
    if not os.path.isfile(args.private_key):
        print(f"错误: 私钥文件 '{args.private_key}' 不存在。")
        return 1
    
    # 加载私钥
    try:
        private_key = encryption.load_private_key(args.private_key)
    except Exception as e:
        print(f"错误: 加载私钥时出错: {str(e)}")
        return 1
    
    # 确认覆盖操作
    if args.overwrite and not confirm_overwrite():
        print("操作已取消。")
        return 0
    
    # 执行解密
    try:
        if os.path.isfile(args.path):
            # 解密单个文件
            output = encryption.decrypt_file(args.path, private_key, args.output, args.overwrite)
            print(f"文件解密" + ("（已覆盖原文件）" if args.overwrite else f"完成，输出到: {output}"))
        else:
            # 解密整个目录
            decrypted_files = encryption.decrypt_directory(args.path, private_key, args.output, args.overwrite)
            
            # 确定输出目录路径以显示
            if args.output:
                out_dir = args.output
            elif args.overwrite:
                out_dir = args.path
            elif args.path.endswith('_encrypted'):
                out_dir = args.path[:-10] + '_decrypted'
            else:
                out_dir = args.path + '_decrypted'
            
            print(f"目录解密" + ("（已覆盖原文件）" if args.overwrite else f"完成，输出到: {out_dir}"))
            print(f"共解密 {len(decrypted_files)} 个文件。")
        
        return 0
    except Exception as e:
        print(f"错误: 解密过程中出错: {str(e)}")
        print("提示: 确保使用了正确的私钥，且文件是使用对应的ECC公钥加密的。")
        return 1

def confirm_overwrite():
    """确认覆盖操作"""
    print("\n⚠️  警告: 覆盖操作将会永久替换原始加密文件，且不可逆！")
    print("如果使用了错误的私钥，可能会导致数据丢失。")
    while True:
        response = input("确认继续吗? (y/n): ").lower()
        if response in ['y', 'yes']:
            return True
        elif response in ['n', 'no']:
            return False
        print("请输入 'y' 或 'n'")

if __name__ == "__main__":
    sys.exit(main()) 