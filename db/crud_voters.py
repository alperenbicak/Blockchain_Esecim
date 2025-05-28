from db.connection import get_db_connection
import hashlib
from collections import defaultdict
from auth.jwt_handler import encrypt_tc, decrypt_tc, hash_tc_for_storage

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
    
    # TC'yi hashleyerek saklama
    hashed_tc = hash_tc_for_storage(tc)
    # Şifrelenmiş TC
    encrypted_tc = encrypt_tc(tc)
    
    cursor.execute(
        "INSERT INTO Voters (TC, TC_Hash, FullName, Region, Password, HasVoted) VALUES (?, ?, ?, ?, ?, 0)",
        (encrypted_tc, hashed_tc, full_name, region, hashed_password)
    )
    conn.commit()
    conn.close()

# TC'ye göre kullanıcı var mı kontrol et
def voter_exists(tc: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # TC hash'ini hesapla
    hashed_tc = hash_tc_for_storage(tc)
    
    # Önce TC_Hash ile kontrol et
    cursor.execute("SELECT 1 FROM Voters WHERE TC_Hash = ?", (hashed_tc,))
    exists = cursor.fetchone()
    
    if exists:
        conn.close()
        return True
    
    # Bulunamazsa, doğrudan TC ile kontrol et (eski kayıtlar için)
    cursor.execute("SELECT 1 FROM Voters WHERE TC = ?", (tc,))
    exists = cursor.fetchone()
    
    if exists:
        # TC_Hash alanını güncelle
        cursor.execute("UPDATE Voters SET TC_Hash = ? WHERE TC = ?", (hashed_tc, tc))
        conn.commit()
    
    conn.close()
    return bool(exists)

# TC ve bölgeye göre kullanıcıyı getir (şifre doğrulama için)
def get_voter(tc: str, region: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # TC hash'ini hesapla
    hashed_tc = hash_tc_for_storage(tc)
    
    # Önce TC_Hash ile sorgula
    cursor.execute("SELECT * FROM Voters WHERE TC_Hash = ? AND Region = ?", (hashed_tc, region))
    voter = cursor.fetchone()
    
    if voter:
        conn.close()
        return voter
    
    # Bulunamazsa, doğrudan TC ile sorgula (eski kayıtlar için)
    cursor.execute("SELECT * FROM Voters WHERE TC = ? AND Region = ?", (tc, region))
    voter = cursor.fetchone()
    
    if voter:
        # TC_Hash alanını güncelle
        cursor.execute("UPDATE Voters SET TC_Hash = ? WHERE TC = ?", (hashed_tc, tc))
        conn.commit()
    
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

def update_existing_voters_to_hashed():
    """Mevcut tüm kullanıcıların TC kimlik numaralarını hashli ve şifreli formata günceller"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # TC_Hash sütununu kontrol et, yoksa ekle
    try:
        cursor.execute("SELECT TC_Hash FROM Voters LIMIT 1")
    except Exception:
        cursor.execute("ALTER TABLE Voters ADD COLUMN TC_Hash TEXT")
        conn.commit()
    
    # Tüm kullanıcıları getir
    cursor.execute("SELECT id, TC FROM Voters")
    voters = cursor.fetchall()
    
    updated_count = 0
    decrypted_count = 0
    plain_count = 0
    
    for voter in voters:
        voter_id = voter[0]
        tc = voter[1]
        
        # Şifrelenmiş veya hash mi kontrol et
        is_hash = len(tc) == 64 and all(c in '0123456789abcdef' for c in tc.lower())
        
        if is_hash:
            continue
            
        # TC'nin şifrelenmiş olup olmadığını kontrol et
        try:
            # Eğer zaten şifrelenmişse, decrypt_tc başarılı olur
            plaintext_tc = decrypt_tc(tc)
            decrypted_count += 1
            
            # Hash'i güncelle
            hashed_tc = hash_tc_for_storage(plaintext_tc)
            
            cursor.execute("UPDATE Voters SET TC_Hash = ? WHERE id = ?", (hashed_tc, voter_id))
            updated_count += 1
        except Exception as e:
            # Şifrelenmemiş TC - şifrele ve hashle
            hashed_tc = hash_tc_for_storage(tc)
            encrypted_tc = encrypt_tc(tc)
            
            cursor.execute("""
                UPDATE Voters 
                SET TC = ?, TC_Hash = ? 
                WHERE id = ?
            """, (encrypted_tc, hashed_tc, voter_id))
            plain_count += 1
    
    conn.commit()
    
    # Eski hash değerlerini düzeltmek için kayıtları gözden geçir
    cursor.execute("SELECT id, TC, TC_Hash FROM Voters")
    voters = cursor.fetchall()
    
    fixed_hash_count = 0
    for voter in voters:
        voter_id = voter[0]
        encrypted_tc = voter[1]
        current_hash = voter[2]
        
        # Hash'i olmayan kayıtları atla
        if not current_hash:
            continue
            
        try:
            # Şifreli TC'yi çöz
            plaintext_tc = decrypt_tc(encrypted_tc)
            # Doğru hash değerini hesapla
            correct_hash = hash_tc_for_storage(plaintext_tc)
            
            # Eğer hash değeri farklıysa güncelle
            if current_hash != correct_hash:
                cursor.execute("UPDATE Voters SET TC_Hash = ? WHERE id = ?", (correct_hash, voter_id))
                fixed_hash_count += 1
        except Exception as e:
            pass
    
    if fixed_hash_count > 0:
        conn.commit()
    
    conn.close()
    
    # Güncelleme özetini hazırla
    summary = {
        "message": "Tüm kullanıcıların TC kimlik numaraları güncellendi",
        "total_processed": len(voters),
        "already_encrypted_updated": decrypted_count,
        "plain_text_encrypted": plain_count,
        "fixed_hash_values": fixed_hash_count,
        "total_updated": updated_count + plain_count + fixed_hash_count
    }
    
    return summary
