# db/connection.py
import sqlite3
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from contextlib import contextmanager

# SQLite veritabanı dosya yolunu belirle
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "esecim.db")

# SQLAlchemy engine oluştur
engine = create_engine(f"sqlite:///{DB_PATH}", echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Eski SQLite bağlantısı için (geriye uyumluluk)
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# SQLAlchemy session context manager
@contextmanager
def get_db_session():
    session = scoped_session(SessionLocal)
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

# SQLAlchemy session (FastAPI dependency kullanımı için)
def get_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
