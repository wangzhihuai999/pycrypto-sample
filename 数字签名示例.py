from cryptography.hazmat.primitives.asymmetric import utils

def digital_signature_example():
    # 数字签名示例
    print("\n=== 数字签名示例 ===")
    
    data = b"Hello, this is a digital signature example!"
    
    # 1. RSA签名 (PSS填充)
    print("\n1. RSA with PSS padding:")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Signature:", signature.hex())
    
    # 验证签名
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature is valid.")
    except Exception as e:
        print("Signature is invalid:", e)
    
    # 2. RSA签名 (PKCS1v15填充)
    print("\n2. RSA with PKCS1v15 padding:")
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    print("Signature:", signature.hex())
    
    # 验证签名
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("Signature is valid.")
    except Exception as e:
        print("Signature is invalid:", e)
    
    # 3. ECDSA签名
    print("\n3. ECDSA signature:")
    private_key_ec = ec.generate_private_key(
        ec.SECP384R1(), default_backend()
    )
    public_key_ec = private_key_ec.public_key()
    
    signature = private_key_ec.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )
    print("Signature:", signature.hex())
    
    # 验证签名
    try:
        public_key_ec.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        print("Signature is valid.")
    except Exception as e:
        print("Signature is invalid:", e)
    
    # 4. Ed25519签名
    print("\n4. Ed25519 signature:")
    private_key_ed = ed25519.Ed25519PrivateKey.generate()
    public_key_ed = private_key_ed.public_key()
    
    signature = private_key_ed.sign(data)
    print("Signature:", signature.hex())
    
    # 验证签名
    try:
        public_key_ed.verify(signature, data)
        print("Signature is valid.")
    except Exception as e:
        print("Signature is invalid:", e)

# 调用数字签名示例
digital_signature_example()

