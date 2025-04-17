from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64
import hashlib

def kdf_demo():
    print("\n=== 密钥推导函数(KDF)演示 ===")
    
    # 原始密钥材料(密码或共享密钥)
    password = b"my_secure_password"
    shared_secret = os.urandom(32)  # 例如来自DH交换的共享密钥
    
    # 1. PBKDF2 (Password-Based Key Derivation Function 2)
    print("\n1. PBKDF2-HMAC:")
    salt = os.urandom(16)  # 应该为每个密码唯一存储
    iterations = 100000    # 迭代次数应根据硬件调整
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,         # 输出密钥长度
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(password)
    print(f"Derived key: {key.hex()}")
    print(f"Salt: {salt.hex()}")
    print(f"Iterations: {iterations}")
    
    # 验证(使用相同参数)
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        kdf.verify(password, key)
        print("PBKDF2 verification succeeded")
    except Exception as e:
        print(f"PBKDF2 verification failed: {e}")
    
    # 2. HKDF (HMAC-based Extract-and-Expand Key Derivation Function)
    print("\n2. HKDF:")
    # 通常用于从DH交换的共享密钥派生密钥
    
    # a) 完整HKDF (提取+扩展)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,         # 可选上下文/应用信息
        info=b'my_app',   # 可选上下文
        backend=default_backend()
    )
    key = hkdf.derive(shared_secret)
    print(f"HKDF derived key: {key.hex()}")
    
    # b) 仅HKDF扩展(已有提取密钥)
    hkdf_expand = HKDFExpand(
        algorithm=hashes.SHA256(),
        length=32,
        info=b'my_app',
        backend=default_backend()
    )
    key = hkdf_expand.derive(shared_secret)
    print(f"HKDF-Expand derived key: {key.hex()}")
    
    # 3. scrypt
    print("\n3. scrypt:")
    # 内存密集型KDF，抵抗硬件加速攻击
    
    salt = os.urandom(16)
    length = 32
    n = 2**14  # CPU/内存成本参数
    r = 8      # 块大小参数
    p = 1      # 并行化参数
    
    kdf = Scrypt(
        salt=salt,
        length=length,
        n=n,
        r=r,
        p=p,
        backend=default_backend()
    )
    key = kdf.derive(password)
    print(f"scrypt derived key: {key.hex()}")
    print(f"Parameters: n={n}, r={r}, p={p}")
    
    # 验证
    try:
        kdf = Scrypt(
            salt=salt,
            length=length,
            n=n,
            r=r,
            p=p,
            backend=default_backend()
        )
        kdf.verify(password, key)
        print("scrypt verification succeeded")
    except Exception as e:
        print(f"scrypt verification failed: {e}")
    
    # 4. Argon2 (需要argon2-cffi包)
    print("\n4. Argon2:")
    try:
        from argon2.low_level import hash_secret_raw, Type
        salt = os.urandom(16)
        time_cost = 3
        memory_cost = 65536  # 64MB
        parallelism = 4
        hash_len = 32
        argon_type = Type.ID
        
        key = hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            type=argon_type
        )
        print(f"Argon2 derived key: {key.hex()}")
        print(f"Parameters: t={time_cost}, m={memory_cost}, p={parallelism}")
    except ImportError:
        print("Argon2需要安装argon2-cffi包")

def integrate_kdf_with_encryption():
    print("\n=== KDF与加密集成示例 ===")
    
    # 场景: 使用密码保护数据
    
    # 1. 从密码派生密钥
    password = b"my_password"
    salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    encryption_key = kdf.derive(password)
    
    # 2. 使用派生密钥进行加密
    print("\n使用KDF派生密钥进行AES加密:")
    iv = os.urandom(16)
    cipher = Cipher(
        algorithms.AES(encryption_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    plaintext = b"Secret message protected by password"
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    print(f"Ciphertext: {ciphertext.hex()}")
    
    # 3. 解密时重新派生密钥
    print("\n解密时重新派生相同密钥:")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    try:
        kdf.verify(password, encryption_key)
        print("Password verification succeeded")
        
        # 实际应用中，这里会使用验证后的密码重新派生密钥
        decryption_key = kdf.derive(password)
        
        cipher = Cipher(
            algorithms.AES(decryption_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
        print(f"Decrypted: {decrypted.decode()}")
    except Exception as e:
        print(f"Password verification failed: {e}")

if __name__ == "__main__":
    kdf_demo()
    integrate_kdf_with_encryption()

"""
密钥推导函数类型说明
1. PBKDF2 (Password-Based Key Derivation Function 2)
用途: 从密码派生密钥
特点:
使用盐值防止彩虹表攻击
可配置迭代次数增加计算成本
使用HMAC作为伪随机函数
参数选择:
迭代次数: 至少100,000次(SHA-256)
盐长度: 至少64位(8字节)，推荐128位(16字节)
哈希算法: SHA-256或更强
2. HKDF (HMAC-based Extract-and-Expand Key Derivation Function)
用途: 从已有密钥材料(如DH交换结果)派生密钥
特点:
两阶段过程: 提取(可选)和扩展
可使用上下文信息(info)派生不同密钥
设计用于已有高熵输入
典型用途:
从Diffie-Hellman共享密钥派生加密密钥
密钥分层派生
3. scrypt
用途: 从密码派生密钥
特点:
内存密集型设计，抵抗ASIC/GPU攻击
提供CPU成本(n)、内存成本(r)和并行化参数(p)
参数选择:
n: 2^14-2^20(根据硬件调整)
r: 8-16
p: 1-4
4. Argon2
用途: 密码哈希和密钥派生
特点:
2015年密码哈希竞赛获胜者
提供抗GPU/ASIC设计
三种变体: Argon2d, Argon2i, Argon2id(推荐)
参数选择:
时间成本: 至少3次迭代
内存成本: 至少64MB
并行度: 根据CPU核心数
"""
