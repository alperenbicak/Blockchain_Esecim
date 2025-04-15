from pydantic import BaseModel

class RegisterRequest(BaseModel):
    tc: str
    full_name: str
    region: str
    password: str

class LoginRequest(BaseModel):
    tc: str
    region: str
    password: str
