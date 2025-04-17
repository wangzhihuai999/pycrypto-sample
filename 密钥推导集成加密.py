def secure_encrypt_with_password(password, plaintext):
    """使用密码安全加密数据"""
    # 1. 生成随机盐
    salt = os.urandom(16)
    
    # 2. 使用Argon2派生密钥
    try:
        from argon2.low_level import hash_secret_raw, Type
        encryption_key = hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=3,
            memory_cost=65536,  # 64MB
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )
    except ImportError:
        # 回退到PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=600000,  # 更高的迭代次数补偿安全性
            backend=default_backend()
        )
        encryption_key = kdf.derive(password)
    
    # 3. 使用AES-GCM加密
    iv = os.urandom(12)
    cipher = Cipher(
        algorithms.AES(encryption_key),
        modes.GCM(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    
    # 返回盐、IV、认证标签和密文
    return {
        'salt': base64.b64encode(salt).decode(),
        'iv': base64.b64encode(iv).decode(),
        'tag': base64.b64encode(tag).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'kdf': 'argon2id' if 'argon2' in locals() else 'pbkdf2-sha512'
    }

def secure_decrypt_with_password(password, encrypted_data):
    """使用密码解密数据"""
    # 解码base64数据
    salt = base64.b64decode(encrypted_data['salt'])
    iv = base64.b64decode(encrypted_data['iv'])
    tag = base64.b64decode(encrypted_data['tag'])
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])
    
    # 根据KDF类型派生密钥
    if encrypted_data.get('kdf') == 'argon2id':
        try:
            from argon2.low_level import hash_secret_raw, Type
            encryption_key = hash_secret_raw(
                secret=password,
                salt=salt,
                time_cost=3,
                memory_cost=65536,
                parallelism=4,
                hash_len=32,
                type=Type.ID
            )
        except ImportError:
            raise ValueError("Argon2 required but not available")
    else:  # 默认为PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=600000,
            backend=default_backend()
        )
        encryption_key = kdf.derive(password)
    
    # 解密
    cipher = Cipher(
        algorithms.AES(encryption_key),
        modes.GCM(iv, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    try:
        return decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag:
        raise ValueError("Decryption failed - incorrect password or corrupted data")

# 使用示例
if __name__ == "__main__":
    print("\n=== 密码保护加密集成示例 ===")
    
    password = b"my_secure_password"
    plaintext = b"Very secret message"
    
    print("\n加密:")
    encrypted = secure_encrypt_with_password(password, plaintext)
    print(f"Salt: {encrypted['salt']}")
    print(f"IV: {encrypted['iv']}")
    print(f"Tag: {encrypted['tag']}")
    print(f"Ciphertext: {encrypted['ciphertext']}")
    print(f"KDF used: {encrypted['kdf']}")
    
    print("\n解密:")
    try:
        decrypted = secure_decrypt_with_password(password, encrypted)
        print(f"Decrypted: {decrypted.decode()}")
    except Exception as e:
        print(f"Decryption failed: {e}")
    
    # 测试错误密码
    print("\n测试错误密码:")
    try:
        decrypted = secure_decrypt_with_password(b"wrong_password", encrypted)
        print(f"Decrypted: {decrypted.decode()}")
    except Exception as e:
        print(f"Expected failure: {e}")
