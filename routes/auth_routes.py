from fastapi import APIRouter, HTTPException, Depends
from auth.schemas import RegisterRequest, LoginRequest
from db.crud_voters import create_voter, get_voter, voter_exists
from auth.jwt_handler import hash_password, verify_password, create_access_token, get_current_voter

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
    voter = get_voter(request.tc, request.region)

    if not voter:
        raise HTTPException(status_code=401, detail="Hatalı TC veya bölge")

    db_password = voter.Password if hasattr(voter, "Password") else voter[4]  # pyodbc row objesi ise indexle
    if not verify_password(request.password, db_password):
        raise HTTPException(status_code=401, detail="Şifre hatalı")

    token = create_access_token(data={"sub": request.tc, "region": request.region})
    return {"access_token": token, "token_type": "bearer"}

@router.get("/me")
def get_my_info(current_user: dict = Depends(get_current_voter)):
    return {
        "tc": current_user["tc"],
        "region": current_user["region"]
    }
