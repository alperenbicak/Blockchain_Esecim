# db/crud_candidates.py
from db.connection import get_db_connection

def get_all_candidates():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT Name FROM Candidates")
    rows = cursor.fetchall()
    conn.close()
    return [row["Name"] for row in rows]

def candidate_exists(name: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM Candidates WHERE Name = ?", (name,))
    exists = cursor.fetchone()
    conn.close()
    return bool(exists)
