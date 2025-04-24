from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64

# 模拟 HTTPS 的加密和解密过程

# 1. 服务器生成 RSA 密钥对 (在实际HTTPS中，这通常是证书中的公钥和服务器私钥)
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

print("=== 模拟 HTTPS 加密解密过程 ===")

# 2. 客户端获取服务器的公钥 (模拟)
server_public_key = RSA.import_key(public_key)

# 3. 客户端生成一个随机的对称密钥 (AES密钥) 用于后续通信
session_key = get_random_bytes(16)  # AES-128

# 4. 客户端用服务器的公钥加密这个对称密钥
cipher_rsa = PKCS1_OAEP.new(server_public_key)
enc_session_key = cipher_rsa.encrypt(session_key)

print("\n加密的会话密钥 (Base64):", base64.b64encode(enc_session_key).decode('utf-8'))

# 5. 服务器用自己的私钥解密获取对称密钥
server_private_key = RSA.import_key(private_key)
cipher_rsa = PKCS1_OAEP.new(server_private_key)
decrypted_session_key = cipher_rsa.decrypt(enc_session_key)

print("\n解密后的会话密钥:", decrypted_session_key.hex())

# 6. 现在双方都有了相同的会话密钥，可以开始安全通信

# 客户端准备要发送的数据
data = "这是一条通过HTTPS安全传输的秘密消息".encode('utf-8')

# 客户端加密数据 (使用AES)
# 生成随机IV
iv = get_random_bytes(16)
cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
# 填充数据以满足AES块大小
pad_len = 16 - (len(data) % 16)
data += bytes([pad_len]) * pad_len
encrypted_data = cipher_aes.encrypt(data)

print("\n加密的数据 (Base64):", base64.b64encode(iv + encrypted_data).decode('utf-8'))

# 服务器接收并解密数据
iv = encrypted_data[:16]  # 前16字节是IV
encrypted_data = encrypted_data[16:]
cipher_aes = AES.new(decrypted_session_key, AES.MODE_CBC, iv)
decrypted_data = cipher_aes.decrypt(encrypted_data)
# 去除填充
pad_len = decrypted_data[-1]
decrypted_data = decrypted_data[:-pad_len]

print("\n解密后的数据:", decrypted_data.decode('utf-8'))
