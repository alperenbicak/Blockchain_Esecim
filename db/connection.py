# db/connection.py
import sqlite3
import os
print("🔍 Aktif veritabanı:", os.path.abspath("esecim.db"))

def get_db_connection():
    conn = sqlite3.connect("esecim.db")  # Dosya tabanlı veritabanı
    conn.row_factory = sqlite3.Row  # Satırları dict gibi döndürmek için
    return conn
