from fastapi import FastAPI
from routes.auth_routes import router as auth_router
from routes.vote_routes import router as vote_router
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Blockchain E-Seçim Sistemi",
    description="7 bölgeye ayrılmış blockchain tabanlı güvenli elektronik oylama sistemi",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # herkes erişebilir
    allow_methods=["*"],  # GET, POST, PUT, DELETE vs hepsi izinli
    allow_headers=["*"],  # Content-Type, Authorization vs izinli
)

app.include_router(auth_router, prefix="", tags=["Authentication"])

app.include_router(vote_router, tags=["Voting"])

