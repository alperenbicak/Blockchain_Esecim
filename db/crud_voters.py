from db.connection import get_db_connection
import hashlib
from collections import defaultdict

def calculate_expected_hash(index, previous_hash, voter_id_hash, candidate, region):
    raw = f"{index}{previous_hash}{voter_id_hash}{candidate}{region}"
    return hashlib.sha256(raw.encode()).hexdigest()

def get_verified_vote_results():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT Region, BlockIndex, PreviousHash, Timestamp, VoterID_Hashed, Candidate, Hash
        FROM Blocks
        WHERE BlockIndex != 0 AND Candidate != 'MerkleRoot'
        ORDER BY Region, BlockIndex ASC
    ''')
    rows = cursor.fetchall()
    conn.close()

    results = defaultdict(int)
    invalid_blocks = []

    for row in rows:
        expected_hash = calculate_expected_hash(
            row["BlockIndex"],
            row["PreviousHash"],
            row["VoterID_Hashed"],
            row["Candidate"],
            row["Region"]
        )

        if expected_hash == row["Hash"]:
            results[row["Candidate"]] += 1
        else:
            invalid_blocks.append({
                "region": row["Region"],
                "index": row["BlockIndex"],
                "candidate": row["Candidate"],
                "hash_in_db": row["Hash"],
                "expected_hash": expected_hash
            })

    return {
        "verified_results": dict(results),
        "invalid_blocks": invalid_blocks
    }

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

def get_admin(username: str):
    """Admin kullanıcısını veritabanından çeker"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Admin tablosunu kontrol et, yoksa oluştur
    try:
        cur.execute("SELECT * FROM Admins LIMIT 1")
    except Exception:
        cur.execute("""
            CREATE TABLE Admins (
                Username TEXT PRIMARY KEY,
                Password TEXT NOT NULL
            )
        """)
        # Varsayılan admin kullanıcısı oluştur
        from auth.jwt_handler import hash_password
        default_admin_pw = hash_password("admin123")
        cur.execute("""
            INSERT INTO Admins (Username, Password)
            VALUES (?, ?)
        """, ("admin", default_admin_pw))
        conn.commit()
    
    cur.execute("SELECT * FROM Admins WHERE Username = ?", (username,))
    admin = cur.fetchone()
    conn.close()
    
    return admin

def create_admin(username: str, hashed_password: str):
    """Yeni admin kullanıcısı oluşturur"""
    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute("""
        INSERT INTO Admins (Username, Password)
        VALUES (?, ?)
    """, (username, hashed_password))
    
    conn.commit()
    conn.close()
    
    return True
