# recalc_roots.py
import sqlite3
import time
from blockchain.utils import calculate_merkle_root
from db.connection import get_db_connection

REGIONS = [
    "Marmara", "Ege", "Akdeniz", "Iç Anadolu",
    "Karadeniz", "Doğu Anadolu", "Güneydoğu Anadolu"
]

def recalc_region_roots():
    conn = get_db_connection()
    cur = conn.cursor()

    print(">>> Bölgesel kökler yeniden hesaplanıyor…")
    for region in REGIONS:
        # 1) O bölgenin blok hash'lerini al
        cur.execute("""
            SELECT Hash FROM Blocks
            WHERE Region = ?
            ORDER BY BlockIndex ASC
        """, (region,))
        hashes = [r["Hash"] for r in cur.fetchall()]

        # 2) Full Merkle root'u hesapla
        region_root = calculate_merkle_root(hashes)
        now = int(time.time())

        # 3) RegionRoots tablosuna yaz
        cur.execute("""
            INSERT INTO RegionRoots (Region, MerkleRoot, UpdatedAt)
            VALUES (?, ?, ?)
            ON CONFLICT(Region) DO UPDATE SET
              MerkleRoot = excluded.MerkleRoot,
              UpdatedAt  = excluded.UpdatedAt
        """, (region, region_root, now))

        print(f"  • {region}: {region_root[:8]}…")

    conn.commit()
    conn.close()

def recalc_national_root():
    conn = get_db_connection()
    cur = conn.cursor()

    # 1) Bölgesel kökleri belirtilen sırada al (alfabetik değil)
    region_roots = []
    for region in REGIONS:
        cur.execute("SELECT MerkleRoot FROM RegionRoots WHERE Region = ?", (region,))
        result = cur.fetchone()
        if result:
            region_roots.append(result["MerkleRoot"])

    # 2) Full Merkle root'u hesapla
    national_root = calculate_merkle_root(region_roots)
    now = int(time.time())

    # 3) NationalRoots tablosuna yaz (kayıt varsa güncelle, yoksa ekle)
    cur.execute("""
        INSERT INTO NationalRoots (Id, MerkleRoot, UpdatedAt)
        VALUES (0, ?, ?)
        ON CONFLICT(Id) DO UPDATE SET
          MerkleRoot = excluded.MerkleRoot,
          UpdatedAt = excluded.UpdatedAt
    """, (national_root, now))

    conn.commit()
    conn.close()
    print(f">>> Ulusal kök güncellendi: {national_root[:8]}…")

if __name__ == "__main__":
    recalc_region_roots()
    recalc_national_root()
    print("✅ Tüm kökler resetlendi ve veritabanına yazıldı.")
