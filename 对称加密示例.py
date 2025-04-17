from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def symmetric_encryption_example():
    # 对称加密示例 (AES算法)
    print("\n=== 对称加密示例 (AES) ===")
    
    # 生成随机密钥 (AES-256需要32字节密钥)
    key = os.urandom(32)
    
    # 需要加密的明文
    plaintext = b"Hello, this is a symmetric encryption example!"
    
    # 展示所有支持的加密模式和填充方式
    print("\n支持的加密模式:")
    print("- ECB (电子密码本模式)")
    print("- CBC (密码块链接模式)")
    print("- CFB (密码反馈模式)")
    print("- OFB (输出反馈模式)")
    print("- CTR (计数器模式)")
    print("- GCM (伽罗瓦/计数器模式)")
    
    # 使用不同模式和填充方式加密
    
    # 1. AES-CBC with PKCS7 padding
    print("\n1. AES-CBC with PKCS7 padding:")
    iv = os.urandom(16)  # 初始化向量
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # 添加PKCS7填充
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    print("Ciphertext:", ciphertext.hex())
    
    # 解密
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    # 去除填充
    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    print("Decrypted:", decrypted.decode())
    
    # 2. AES-GCM (认证加密)
    print("\n2. AES-GCM (认证加密):")
    iv = os.urandom(12)  # GCM通常使用12字节IV
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # GCM不需要填充，因为它使用流加密模式
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag  # 认证标签
    print("Ciphertext:", ciphertext.hex())
    print("Tag:", tag.hex())
    
    # 解密
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    print("Decrypted:", decrypted.decode())
    
    # 3. AES-CTR (不需要填充)
    print("\n3. AES-CTR (不需要填充):")
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    print("Ciphertext:", ciphertext.hex())
    
    # 解密
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    print("Decrypted:", decrypted.decode())

# 调用对称加密示例
symmetric_encryption_example()
