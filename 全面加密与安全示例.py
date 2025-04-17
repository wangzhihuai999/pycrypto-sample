import os
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519, dh
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key, load_pem_private_key,
    Encoding, PrivateFormat, PublicFormat, NoEncryption
)
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature, InvalidTag
import hashlib
from getpass import getpass
try:
    from argon2 import PasswordHasher
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False
import bcrypt
import nacl.secret
import nacl.utils
import nacl.pwhash

def print_header(title):
    print(f"\n{'='*50}\n{title}\n{'='*50}")

def symmetric_encryption_demo():
    print_header("对称加密演示")
    
    # 生成随机密钥
    key_aes256 = os.urandom(32)  # AES-256需要32字节密钥
    key_aes128 = os.urandom(16)  # AES-128需要16字节密钥
    key_chacha20 = os.urandom(32)  # ChaCha20需要32字节密钥
    
    plaintext = b"This is a secret message that needs to be encrypted!"
    
    # 1. AES加密 (各种模式)
    print("\n1. AES加密 (各种模式):")
    
    # AES-CBC with PKCS7 padding
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key_aes256), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    print(f"AES-256-CBC: {ciphertext.hex()}")
    
    # AES-GCM (认证加密)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key_aes256), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    print(f"AES-256-GCM: {ciphertext.hex()}, Tag: {tag.hex()}")
    
    # AES-CTR (流加密模式)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key_aes256), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    print(f"AES-256-CTR: {ciphertext.hex()}")
    
    # 2. ChaCha20-Poly1305
    print("\n2. ChaCha20-Poly1305:")
    iv = os.urandom(12)
    cipher = Cipher(algorithms.ChaCha20(key_chacha20, iv), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)
    print(f"ChaCha20: {ciphertext.hex()}")
    
    # 使用PyNaCL的ChaCha20-Poly1305实现
    box = nacl.secret.SecretBox(key_chacha20)
    encrypted = box.encrypt(plaintext)
    print(f"ChaCha20-Poly1305 (PyNaCL): {encrypted.hex()}")
    
    # 3. 其他对称算法
    print("\n3. 其他对称算法:")
    
    # DES (不推荐使用，仅演示)
    key_des = os.urandom(8)
    iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(key_des), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(64).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    print(f"3DES-CBC: {ciphertext.hex()}")

def asymmetric_encryption_demo():
    print_header("非对称加密演示")
    
    plaintext = b"This is a message to be encrypted with asymmetric crypto!"
    
    # 1. RSA加密
    print("\n1. RSA加密:")
    
    # 生成RSA密钥对
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # RSA-OAEP加密
    ciphertext = public_key.encrypt(
        plaintext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"RSA-OAEP ciphertext: {ciphertext.hex()}")
    
    # RSA-OAEP解密
    decrypted = private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"Decrypted: {decrypted.decode()}")
    
    # 2. ECC加密 (ECDH密钥交换 + AES加密)
    print("\n2. ECC加密 (ECDH密钥交换):")
    
    # 生成ECC密钥对
    private_key_ec = ec.generate_private_key(
        ec.SECP384R1(), default_backend()
    )
    public_key_ec = private_key_ec.public_key()
    
    # 另一方生成密钥对
    peer_private_key = ec.generate_private_key(
        ec.SECP384R1(), default_backend()
    )
    peer_public_key = peer_private_key.public_key()
    
    # 生成共享密钥
    shared_key = private_key_ec.exchange(ec.ECDH(), peer_public_key)
    
    # 使用HKDF派生密钥
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecdh key derivation',
        backend=default_backend()
    ).derive(shared_key)
    
    # 使用派生密钥进行AES加密
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    print(f"ECDH+AES-GCM ciphertext: {ciphertext.hex()}, tag: {tag.hex()}")
    
    # 3. X25519密钥交换
    print("\n3. X25519密钥交换:")
    
    # 生成X25519密钥对
    private_key_x = x25519.X25519PrivateKey.generate()
    public_key_x = private_key_x.public_key()
    
    # 另一方生成密钥对
    peer_private_key_x = x25519.X25519PrivateKey.generate()
    peer_public_key_x = peer_private_key_x.public_key()
    
    # 生成共享密钥
    shared_key_x = private_key_x.exchange(peer_public_key_x)
    
    # 使用派生密钥
    derived_key_x = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'x25519 key derivation',
        backend=default_backend()
    ).derive(shared_key_x)
    
    print(f"X25519 derived key: {derived_key_x.hex()}")

def hashing_demo():
    print_header("哈希与密码哈希演示")
    
    data = b"This is some data to be hashed"
    password = b"my_secure_password"
    
    # 1. 标准哈希算法
    print("\n1. 标准哈希算法:")
    
    # SHA-2系列
    sha256 = hashlib.sha256(data).hexdigest()
    print(f"SHA-256: {sha256}")
    
    sha512 = hashlib.sha512(data).hexdigest()
    print(f"SHA-512: {sha512}")
    
    # SHA-3系列
    sha3_256 = hashlib.sha3_256(data).hexdigest()
    print(f"SHA3-256: {sha3_256}")
    
    # BLAKE2
    blake2s = hashlib.blake2s(data).hexdigest()
    print(f"BLAKE2s: {blake2s}")
    
    # 2. 密码哈希
    print("\n2. 密码哈希:")
    
    # PBKDF2
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    pbkdf2_key = kdf.derive(password)
    print(f"PBKDF2-HMAC-SHA256: {pbkdf2_key.hex()}")
    
    # bcrypt
    bcrypt_hash = bcrypt.hashpw(password, bcrypt.gensalt(rounds=12))
    print(f"bcrypt: {bcrypt_hash.decode()}")
    
    # Argon2
    if HAS_ARGON2:
        ph = PasswordHasher(
            time_cost=3, memory_cost=65536, parallelism=4, 
            hash_len=32, salt_len=16
        )
        argon2_hash = ph.hash(password)
        print(f"Argon2: {argon2_hash}")
    else:
        print("Argon2: 需要安装argon2-cffi包")
    
    # scrypt (通过PyNaCL)
    scrypt_hash = nacl.pwhash.scrypt.str(password)
    print(f"scrypt: {scrypt_hash.decode()}")

def digital_signatures_demo():
    print_header("数字签名演示")
    
    data = b"This is a message to be signed"
    
    # 1. RSA签名
    print("\n1. RSA签名:")
    
    private_key_rsa = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key_rsa = private_key_rsa.public_key()
    
    # RSA-PSS签名
    signature = private_key_rsa.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print(f"RSA-PSS signature: {signature.hex()}")
    
    # 验证签名
    try:
        public_key_rsa.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("RSA-PSS signature is valid")
    except InvalidSignature:
        print("RSA-PSS signature is invalid")
    
    # 2. ECDSA签名
    print("\n2. ECDSA签名:")
    
    private_key_ec = ec.generate_private_key(
        ec.SECP384R1(), default_backend()
    )
    public_key_ec = private_key_ec.public_key()
    
    signature = private_key_ec.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    print(f"ECDSA signature: {signature.hex()}")
    
    # 验证签名
    try:
        public_key_ec.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        print("ECDSA signature is valid")
    except InvalidSignature:
        print("ECDSA signature is invalid")
    
    # 3. Ed25519签名
    print("\n3. Ed25519签名:")
    
    private_key_ed = ed25519.Ed25519PrivateKey.generate()
    public_key_ed = private_key_ed.public_key()
    
    signature = private_key_ed.sign(data)
    print(f"Ed25519 signature: {signature.hex()}")
    
    # 验证签名
    try:
        public_key_ed.verify(signature, data)
        print("Ed25519 signature is valid")
    except InvalidSignature:
        print("Ed25519 signature is invalid")

def key_management_demo():
    print_header("密钥管理演示")
    
    # 1. 生成密钥
    print("\n1. 密钥生成与序列化:")
    
    # 生成RSA密钥
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # 序列化为PEM格式
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    print("RSA Private Key (PEM):")
    print(private_pem.decode())
    
    public_pem = private_key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    print("\nRSA Public Key (PEM):")
    print(public_pem.decode())
    
    # 2. 密码保护的密钥
    print("\n2. 密码保护的密钥:")
    
    password = getpass("Enter password for key encryption: ").encode()
    
    encrypted_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )
    print("\nEncrypted Private Key:")
    print(encrypted_pem.decode())
    
    # 3. 密钥加载
    print("\n3. 密钥加载:")
    
    loaded_private = serialization.load_pem_private_key(
        encrypted_pem,
        password=password,
        backend=default_backend()
    )
    print("Private key loaded successfully")
    
    loaded_public = serialization.load_pem_public_key(
        public_pem,
        backend=default_backend()
    )
    print("Public key loaded successfully")
    
    # 4. JWK格式
    print("\n4. JWK格式 (需要PyJWT):")
    try:
        import jwt
        from jwt.algorithms import RSAAlgorithm
        
        jwk_dict = RSAAlgorithm.to_jwk(loaded_public)
        print("Public Key JWK:")
        print(json.dumps(jwk_dict, indent=2))
    except ImportError:
        print("JWK示例需要安装PyJWT包")

def message_authentication_demo():
    print_header("消息认证演示")
    
    key = os.urandom(32)  # HMAC密钥
    data = b"Message to be authenticated"
    
    # 1. HMAC
    print("\n1. HMAC:")
    
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    mac = h.finalize()
    print(f"SHA256-HMAC: {mac.hex()}")
    
    # 验证HMAC
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    try:
        h.verify(mac)
        print("HMAC verification succeeded")
    except InvalidSignature:
        print("HMAC verification failed")
    
    # 2. Poly1305 (通过ChaCha20-Poly1305)
    print("\n2. Poly1305 (通过ChaCha20-Poly1305):")
    
    box = nacl.secret.SecretBox(key)
    encrypted = box.encrypt(data)
    print(f"ChaCha20-Poly1305 MAC (tag): {encrypted.tag.hex()}")
    
    try:
        box.decrypt(encrypted)
        print("Poly1305 verification succeeded")
    except nacl.exceptions.CryptoError:
        print("Poly1305 verification failed")
    
    # 3. AES-GCM认证
    print("\n3. AES-GCM认证:")
    
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag
    print(f"AES-GCM tag: {tag.hex()}")
    
    # 验证
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        decryptor.update(ciphertext) + decryptor.finalize()
        print("AES-GCM authentication succeeded")
    except InvalidTag:
        print("AES-GCM authentication failed")

def diffie_hellman_demo():
    print_header("Diffie-Hellman密钥交换演示")
    
    # 1. 传统DH
    print("\n1. 传统Diffie-Hellman:")
    
    # DH参数 - 通常使用预定义的或生成新的
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    
    # 双方生成密钥对
    private_key_a = parameters.generate_private_key()
    public_key_a = private_key_a.public_key()
    
    private_key_b = parameters.generate_private_key()
    public_key_b = private_key_b.public_key()
    
    # 交换公钥并生成共享密钥
    shared_key_a = private_key_a.exchange(public_key_b)
    shared_key_b = private_key_b.exchange(public_key_a)
    
    print(f"Party A shared key: {shared_key_a.hex()}")
    print(f"Party B shared key: {shared_key_b.hex()}")
    print(f"Keys match: {shared_key_a == shared_key_b}")
    
    # 2. ECDH (之前已经演示过)
    print("\n2. ECDH (参见非对称加密部分)")

def main():
    # 执行所有演示
    symmetric_encryption_demo()
    asymmetric_encryption_demo()
    hashing_demo()
    digital_signatures_demo()
    key_management_demo()
    message_authentication_demo()
    diffie_hellman_demo()

if __name__ == "__main__":
    main()
