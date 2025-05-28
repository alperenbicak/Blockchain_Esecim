from datetime import datetime, timedelta
from jose import jwt, JWTError
from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from cryptography.fernet import Fernet
import base64
import hashlib

# Şifreleme
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# TC Kimlik için şifreleme anahtarı
TC_ENCRYPT_KEY = b'Vit3b_JeRFpDIiN9sNmiRNV3-xQvz6feIq85aq1zTXI='
fernet = Fernet(TC_ENCRYPT_KEY)

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

def encrypt_tc(tc: str) -> str:
    """TC kimlik numarasını şifreler"""
    tc_bytes = tc.encode()
    encrypted_tc = fernet.encrypt(tc_bytes)
    return base64.urlsafe_b64encode(encrypted_tc).decode()

def decrypt_tc(encrypted_tc: str) -> str:
    """Şifrelenmiş TC kimlik numarasını çözer"""
    try:
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_tc.encode())
        decrypted_tc = fernet.decrypt(encrypted_bytes).decode()
        return decrypted_tc
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"TC kimlik çözülemedi: {str(e)}")

def hash_tc_for_storage(tc: str) -> str:
    """TC kimlik numarasını saklamak için hashler"""
    # TC numarasını string olduğundan emin ol ve boşlukları temizle
    tc_str = str(tc).strip()
    
    # TC numarası 11 haneli mi kontrol et (normal TC kimlik numarası ise)
    if len(tc_str) == 11 and tc_str.isdigit():
        hash_value = hashlib.sha256(tc_str.encode('utf-8')).hexdigest()
        return hash_value
    
    # Eğer zaten hash ise (64 karakter hex ise), aynen döndür
    if len(tc_str) == 64 and all(c in '0123456789abcdef' for c in tc_str.lower()):
        return tc_str
    
    # Diğer durumlar için yine hash hesapla
    hash_value = hashlib.sha256(tc_str.encode('utf-8')).hexdigest()
    return hash_value

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
            # sub artık TC hash değeri
            tc_hash = sub
            region = payload.get("region")
            if region is None:
                raise credentials_exception
            return {"tc": tc_hash, "region": region, "role": role}
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
