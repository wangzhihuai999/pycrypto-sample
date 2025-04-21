import jwt
import datetime
from jwt.exceptions import InvalidSignatureError, ExpiredSignatureError, DecodeError

# 加密密钥，实际应用中应该使用更复杂且保密的密钥
SECRET_KEY = "your-256-bit-secret"  # 请替换为你的密钥
ALGORITHM = "HS256"  # 使用的算法

# 生成JWT令牌
def create_jwt_token(data: dict, expires_delta: datetime.timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# 验证并解码JWT令牌
def verify_jwt_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except ExpiredSignatureError:
        print("Token has expired")
        return None
    except InvalidSignatureError:
        print("Invalid token signature")
        return None
    except DecodeError:
        print("Invalid token")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None

# 使用示例
if __name__ == "__main__":
    # 创建包含用户ID的JWT令牌，有效期为1小时
    user_data = {"user_id": 123, "username": "john_doe"}
    token = create_jwt_token(user_data, datetime.timedelta(hours=1))
    print(f"Generated JWT Token: {token}")

    # 验证和解码令牌
    decoded_data = verify_jwt_token(token)
    if decoded_data:
        print(f"Decoded JWT Data: {decoded_data}")
    else:
        print("Token verification failed")

    # 测试过期令牌
    expired_token = create_jwt_token(user_data, datetime.timedelta(seconds=-1))  # 已过期的令牌
    decoded_expired = verify_jwt_token(expired_token)
    if not decoded_expired:
        print("Expired token test passed")
