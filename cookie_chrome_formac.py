import os
import sqlite3
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
import keyring
def get_chrome_encryption_key():
    """从 macOS 钥匙串获取 Chrome 加密密钥"""
    # 提取密码（默认空字符串）
    password = keyring.get_password("Chrome Safe Storage", "Chrome")
    
    # Cookies 使用特定 PBKDF2 参数
    key = PBKDF2(
        password=password,
        salt=b"saltysalt",
        dkLen=16,  # AES-128 密钥长度
        count=1003  # 注意：Cookies 迭代次数为 1003（密码解密是 1000）
    )
    return key

def decrypt_cookie(encrypted_value: bytes, key: bytes) -> str:
    """解密 Chrome 的 encrypted_value 字段"""
    try:
        cipher = AES.new(key, AES.MODE_CBC, encrypted_value[:16])
        data = cipher.decrypt(encrypted_value[3:])
        tmpdata = bytes(data[32:]).decode()
        tmpdata2 = tmpdata.split(tmpdata[-1:])[0]
        return tmpdata2
    except Exception as e:
        print(f"解密失败: {str(e)}")

def read_chrome_cookies(domain_filter: str = "example.com"):
    """读取并解密指定域名的 Cookies"""
    db_path = os.path.expanduser(
        "~/Library/Application Support/Google/Chrome/Default/Cookies"
    )
    if not os.path.exists(db_path):
        raise FileNotFoundError("Chrome Cookies 数据库未找到")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # 查询 Cookies
    cursor.execute(
        """
        SELECT host_key, name, encrypted_value 
        FROM cookies 
        WHERE host_key LIKE ?
        """,
        (f"%{domain_filter}%",),
    )

    key = get_chrome_encryption_key()
    data = {}
    for host, name, encrypted_value in cursor.fetchall():
        decrypted = decrypt_cookie(encrypted_value, key)
        if host not in data.keys():
            data[host] = {}
        if name not in data[host].keys():
            # data[host][name] = [],,,,,,,,
            data[host][name] = decrypted
        # print(f"域名: {host}\n名称: {name}\n值: {decrypted}\n{'-'*30}")
        # print(data)
    conn.close()
    return data
from http.cookies import SimpleCookie

def dict_to_cookie(cookie_dict):
    """将字典转换为 Set-Cookie 格式字符串"""
    cookie = SimpleCookie()
    for key, value in cookie_dict.items():
        cookie[key] = value
    return cookie.output(header='', sep=';').replace(" ","")
def make_chrom_cookie(domainname = ".net"):
    cookie_dict = {}
    data = read_chrome_cookies(domain_filter=domainname) 
    cookie_dict = data[".bytedance.net"]
    cookie_dict['_devsre_auth'] = data['.net']['cookiename']
    cookie_str=dict_to_cookie(cookie_dict)
    return cookie_str

