from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def asymmetric_encryption_example():
    # 非对称加密示例
    print("\n=== 非对称加密示例 ===")
    
    # 生成RSA密钥对
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # 需要加密的明文
    plaintext = b"Hello, this is an asymmetric encryption example!"
    
    # 1. RSA加密 (使用OAEP填充)
    print("\n1. RSA with OAEP padding:")
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("Ciphertext:", ciphertext.hex())
    
    # 解密
    decrypted = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("Decrypted:", decrypted.decode())
    
    # 2. RSA加密 (使用PKCS1v15填充)
    print("\n2. RSA with PKCS1v15 padding:")
    ciphertext = public_key.encrypt(
        plaintext,
        padding.PKCS1v15()
    )
    print("Ciphertext:", ciphertext.hex())
    
    # 解密
    decrypted = private_key.decrypt(
        ciphertext,
        padding.PKCS1v15()
    )
    print("Decrypted:", decrypted.decode())
    
    # 3. ECC加密 (ECDH + AES)
    print("\n3. ECC encryption (ECDH + AES):")
    # 生成ECC密钥对
    private_key_ecc = ec.generate_private_key(
        ec.SECP384R1(), default_backend()
    )
    public_key_ecc = private_key_ecc.public_key()
    
    # 另一方也生成密钥对
    peer_private_key = ec.generate_private_key(
        ec.SECP384R1(), default_backend()
    )
    peer_public_key = peer_private_key.public_key()
    
    # 生成共享密钥
    shared_key = private_key_ecc.exchange(ec.ECDH(), peer_public_key)
    
    # 使用共享密钥进行对称加密
    # 这里我们使用HKDF从共享密钥派生出合适的密钥
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecdh key',
        backend=default_backend()
    ).derive(shared_key)
    
    # 使用派生出的密钥进行AES加密
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    print("ECC derived key ciphertext:", ciphertext.hex())
    
    # 解密方也需要派生相同的密钥
    peer_shared_key = peer_private_key.exchange(ec.ECDH(), public_key_ecc)
    peer_derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecdh key',
        backend=default_backend()
    ).derive(peer_shared_key)
    
    cipher = Cipher(algorithms.AES(peer_derived_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    print("Decrypted with ECC derived key:", decrypted.decode())

# 调用非对称加密示例
asymmetric_encryption_example()
