from fastapi import APIRouter, HTTPException, Depends
from auth.schemas import RegisterRequest, LoginRequest, AdminLoginRequest
from db.crud_voters import create_voter, get_voter, voter_exists, get_admin, update_existing_voters_to_hashed
from auth.jwt_handler import hash_password, verify_password, create_access_token, get_current_voter, blacklist_token, hash_tc_for_storage
from fastapi.security import OAuth2PasswordRequestForm

router = APIRouter()

@router.post("/register")
def register_user(request: RegisterRequest):
    if len(request.tc) != 11 or not request.tc.isdigit():
        raise HTTPException(status_code=400, detail="Geçersiz TC Kimlik Numarası")

    if voter_exists(request.tc):
        raise HTTPException(status_code=400, detail="Bu TC zaten kayıtlı")

    hashed_pw = hash_password(request.password)

    create_voter(
        tc=request.tc,
        full_name=request.full_name,
        region=request.region,
        hashed_password=hashed_pw
    )

    return {"message": "Kayıt başarılı"}

@router.post("/login")
def login_user(request: LoginRequest):
    # TC hash'ini hesapla - bu hash değeri veritabanında arama için kullanılacak
    tc_hash = hash_tc_for_storage(request.tc)
    
    # Önce hash ile sorgulama yap
    voter = get_voter(request.tc, request.region)

    if not voter:
        # Eğer bulunamazsa, direkt TC ile sorgulama yapılıyor olabilir (eski kayıtlar)
        raise HTTPException(status_code=401, detail="Hatalı TC veya bölge")

    db_password = voter.Password if hasattr(voter, "Password") else voter[4]  # pyodbc row objesi ise indexle
    if not verify_password(request.password, db_password):
        raise HTTPException(status_code=401, detail="Şifre hatalı")

    # Token'a eklemek için hash değerini kullan
    token = create_access_token(data={"sub": tc_hash, "region": request.region, "role": "voter"})
    
    return {"access_token": token, "token_type": "bearer"}

@router.post("/admin/login")
def login_admin(request: AdminLoginRequest):
    admin = get_admin(request.username)
    
    if not admin:
        raise HTTPException(status_code=401, detail="Hatalı kullanıcı adı")
    
    db_password = admin.Password if hasattr(admin, "Password") else admin[1]  # pyodbc row objesi ise indexle
    if not verify_password(request.password, db_password):
        raise HTTPException(status_code=401, detail="Şifre hatalı")
    
    token = create_access_token(data={"sub": request.username, "role": "admin"})
    return {"access_token": token, "token_type": "bearer"}

@router.get("/me")
def get_my_info(current_user: dict = Depends(get_current_voter)):
    return {
        "tc": current_user.get("tc"),
        "region": current_user.get("region"),
        "role": current_user.get("role", "voter")
    }

@router.get("/admin/verify")
def verify_admin_token(current_user: dict = Depends(get_current_voter)):
    """Admin token'ını doğrular"""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="Bu işlem için admin yetkisi gerekiyor"
        )
    return {"valid": True, "username": current_user.get("username")}

@router.post("/admin/logout")
def logout_admin(token: str = Depends(OAuth2PasswordRequestForm), current_user: dict = Depends(get_current_voter)):
    """Admin çıkış işlemi"""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="Bu işlem için admin yetkisi gerekiyor"
        )
    
    # Token'ı blacklist'e ekle
    blacklist_token(token)
    
    return {"message": "Başarıyla çıkış yapıldı"}

@router.post("/admin/update-tc-hash")
def update_tc_hash(current_user: dict = Depends(get_current_voter)):
    """Mevcut tüm kullanıcıların TC kimlik numaralarını hash formatına dönüştürür"""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="Bu işlem için admin yetkisi gerekiyor"
        )
    
    result = update_existing_voters_to_hashed()
    return result
