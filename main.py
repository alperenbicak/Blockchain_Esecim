from fastapi import FastAPI
from routes.auth_routes import router as auth_router
from routes.vote_routes import router as vote_router

app = FastAPI(
    title="E-Seçim Sistemi",
    description="7 bölgeye ayrılmış blockchain tabanlı güvenli elektronik oylama sistemi",
    version="1.0.0"
)

app.include_router(auth_router, prefix="", tags=["Authentication"])

app.include_router(vote_router, tags=["Voting"])

