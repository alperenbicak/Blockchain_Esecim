from db.connection import get_db_connection

# Kullanıcıyı veritabanına ekle
def create_voter(tc: str, full_name: str, region: str, hashed_password: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO Voters (TC, FullName, Region, Password, HasVoted) VALUES (?, ?, ?, ?, 0)",
        (tc, full_name, region, hashed_password)
    )
    conn.commit()
    conn.close()

# TC'ye göre kullanıcı var mı kontrol et
def voter_exists(tc: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM Voters WHERE TC = ?", (tc,))
    exists = cursor.fetchone()
    conn.close()
    return bool(exists)

# TC ve bölgeye göre kullanıcıyı getir (şifre doğrulama için)
def get_voter(tc: str, region: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Voters WHERE TC = ? AND Region = ?", (tc, region))
    voter = cursor.fetchone()
    conn.close()
    return voter  # pyodbc Row objesi döner
