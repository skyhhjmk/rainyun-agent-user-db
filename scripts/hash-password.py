#!/usr/bin/env python3
import base64
import getpass
import hashlib
import secrets
import sys

password = getpass.getpass("管理员密码: ")
confirm = getpass.getpass("再次输入: ")
if not password or password != confirm:
    print("密码为空或两次输入不一致", file=sys.stderr)
    sys.exit(1)
salt = secrets.token_bytes(16)
derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000, dklen=32)
encode = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")
print(f"pbkdf2-sha256$310000${encode(salt)}${encode(derived)}")
