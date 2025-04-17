from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib
import binascii

def one_way_encryption_example():
    # 单向加密（哈希）示例
    print("\n=== 单向加密（哈希）示例 ===")
    
    data = b"Hello, this is a one-way encryption example!"
    
    # 1. SHA-256
    print("\n1. SHA-256:")
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    hash_value = digest.finalize()
    print("SHA-256:", hash_value.hex())
    
    # 2. SHA-3-512
    print("\n2. SHA-3-512:")
    digest = hashes.Hash(hashes.SHA3_512(), backend=default_backend())
    digest.update(data)
    hash_value = digest.finalize()
    print("SHA3-512:", hash_value.hex())
    
    # 3. MD5 (不推荐用于安全用途)
    print("\n3. MD5 (不推荐用于安全用途):")
    digest = hashes.Hash(hashes.MD5(), backend=default_backend())
    digest.update(data)
    hash_value = digest.finalize()
    print("MD5:", hash_value.hex())
    
    # 4. BLAKE2
    print("\n4. BLAKE2:")
    digest = hashes.Hash(hashes.BLAKE2s(32), backend=default_backend())
    digest.update(data)
    hash_value = digest.finalize()
    print("BLAKE2s:", hash_value.hex())
    
    # 5. PBKDF2 (密码派生函数)
    print("\n5. PBKDF2 (密码派生函数):")
    password = b"my_secure_password"
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    print("Derived key:", key.hex())
    
    # 6. Argon2 (更安全的密码哈希)
    try:
        from argon2 import PasswordHasher
        print("\n6. Argon2 (更安全的密码哈希):")
        ph = PasswordHasher(
            time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16
        )
        hash = ph.hash(password)
        print("Argon2 hash:", hash)
    except ImportError:
        print("\n6. Argon2 示例需要安装argon2-cffi包")

# 调用单向加密示例
one_way_encryption_example()
