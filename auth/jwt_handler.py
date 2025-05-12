from datetime import datetime, timedelta
from jose import jwt, JWTError
from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext

# Şifreleme
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

# JWT Ayarları
SECRET_KEY = "supersecretjwtkey123456"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# JWT Token oluştur
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# JWT Token çöz ve kimliği döndür
def get_current_voter(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Geçersiz kimlik bilgisi",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # Token blacklist kontrolü
    if is_token_blacklisted(token):
        raise credentials_exception
        
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        sub = payload.get("sub")
        role = payload.get("role", "voter")
        
        if sub is None:
            raise credentials_exception
            
        if role == "voter":
            tc = sub
            region = payload.get("region")
            if region is None:
                raise credentials_exception
            return {"tc": tc, "region": region, "role": role}
        elif role == "admin":
            username = sub
            return {"username": username, "role": role}
        else:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

# Admin rolünü kontrol et
def admin_required(current_user: dict = Depends(get_current_voter)):
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="Bu işlem için admin yetkisi gerekiyor"
        )
    return current_user

# Token blacklist için basit bir in-memory çözüm
# Gerçek uygulamada Redis veya veritabanı kullanılabilir
BLACKLISTED_TOKENS = set()

def blacklist_token(token: str):
    """Token'ı blacklist'e ekler"""
    BLACKLISTED_TOKENS.add(token)

def is_token_blacklisted(token: str) -> bool:
    """Token'ın blacklist'te olup olmadığını kontrol eder"""
    return token in BLACKLISTED_TOKENS
