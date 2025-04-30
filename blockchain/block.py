import hashlib
import time
from typing import List, Dict
from db.connection import get_db_connection
from blockchain.utils import validate_chain, calculate_merkle_root

REGIONS = [
    "Marmara", "Ege", "Akdeniz", "Iç Anadolu",
    "Karadeniz", "Doğu Anadolu", "Güneydoğu Anadolu"
]

class Block:
    def __init__(self, index: int, previous_hash: str, timestamp: int,
                 voter_id_hash: str, candidate: str, hash: str):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.voter_id_hash = voter_id_hash
        self.candidate = candidate
        self.hash = hash

    def to_dict(self) -> Dict:
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "voter_id_hash": self.voter_id_hash,
            "candidate": self.candidate,
            "hash": self.hash
        }

class RegionalBlockchain:
    def __init__(self, region_name: str):
        self.region_name = region_name
        self.chain: List[Block] = []
        self.load_chain_from_db()
        if not self.chain:
            self.create_genesis_block()

    def create_genesis_block(self):
        genesis_hash = self.calculate_hash(0, "0", "Genesis", "Genesis")
        genesis = Block(0, "0", int(time.time()), "Genesis", "Genesis", genesis_hash)
        self.chain.append(genesis)
        self.save_block_to_db(genesis)

    def calculate_hash(self, index, previous_hash, voter_id_hash, candidate):
        raw = f"{index}{previous_hash}{voter_id_hash}{candidate}{self.region_name}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def add_vote(self, voter_id: str, candidate: str):
        conn = get_db_connection()
        cur = conn.cursor()

        # 1️⃣ Seçmen kontrolü (TC ve bölge eşleşmesi)
        cur.execute(
            "SELECT HasVoted FROM Voters WHERE TC = ? AND Region = ?",
            (voter_id, self.region_name)
        )
        row = cur.fetchone()
        if not row:
            conn.close()
            raise ValueError("Seçmen bulunamadı veya bölge eşleşmiyor.")
        if row["HasVoted"] == 1:
            conn.close()
            raise ValueError("Bu seçmen zaten oy kullandı.")

        # 2️⃣ Blok oluşturma
        voter_hash = hashlib.sha256(voter_id.encode()).hexdigest()
        idx = len(self.chain)
        prev = self.chain[-1].hash
        ts = int(time.time())
        h = self.calculate_hash(idx, prev, voter_hash, candidate)

        block = Block(idx, prev, ts, voter_hash, candidate, h)
        self.chain.append(block)
        self.save_block_to_db(block)

        # 3️⃣ Seçmeni işaretle (HasVoted = 1)
        cur.execute(
            "UPDATE Voters SET HasVoted = 1 WHERE TC = ? AND Region = ?",
            (voter_id, self.region_name)
        )
        conn.commit()
        conn.close()
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
                    SELECT Hash
                    FROM Blocks
                    WHERE Region = ?
                    ORDER BY BlockIndex ASC
                    """, (self.region_name,))
        hashes = [row["Hash"] for row in cur.fetchall()]

        region_root = calculate_merkle_root(hashes)
        timestamp = int(time.time())

        # 3) RegionRoots tablosuna upsert (INSERT OR REPLACE)
        cur.execute("""
                    INSERT INTO RegionRoots (Region, MerkleRoot, UpdatedAt)
                    VALUES (?, ?, ?) ON CONFLICT(Region) DO
                    UPDATE SET
                        MerkleRoot = excluded.MerkleRoot,
                        UpdatedAt = excluded.UpdatedAt
                    """, (self.region_name, region_root, timestamp))

        conn.commit()
        conn.close()
    def load_chain_from_db(self):
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT BlockIndex, PreviousHash, Timestamp,
                   VoterID_Hashed, Candidate, Hash
            FROM Blocks
            WHERE Region = ?
            ORDER BY BlockIndex
        """, (self.region_name,))
        rows = cur.fetchall()
        conn.close()

        self.chain = [
            Block(r["BlockIndex"], r["PreviousHash"], r["Timestamp"],
                  r["VoterID_Hashed"], r["Candidate"], r["Hash"])
            for r in rows
        ]

    def save_block_to_db(self, block: Block):
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO Blocks
              (Region, BlockIndex, PreviousHash, Timestamp,
               VoterID_Hashed, Candidate, Hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            self.region_name,
            block.index,
            block.previous_hash,
            block.timestamp,
            block.voter_id_hash,
            block.candidate,
            block.hash
        ))
        conn.commit()
        conn.close()

    def get_chain(self) -> List[Dict]:
        # DB’den satır bazlı okur, dict listesi döner
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT BlockIndex, PreviousHash, Timestamp,
                   VoterID_Hashed, Candidate, Hash
            FROM Blocks
            WHERE Region = ?
            ORDER BY BlockIndex
        """, (self.region_name,))
        rows = cur.fetchall()
        conn.close()

        return [
            {
              "index": r["BlockIndex"],
              "previous_hash": r["PreviousHash"],
              "timestamp": r["Timestamp"],
              "voter_id_hash": r["VoterID_Hashed"],
              "candidate": r["Candidate"],
              "hash": r["Hash"]
            }
            for r in rows
        ]

class MainBlockchain:
    def __init__(self):
        self.regions = {r: RegionalBlockchain(r) for r in REGIONS}

    def vote(self, region: str, voter_id: str, candidate: str):
        self.regions[region].add_vote(voter_id, candidate)

    def get_all_chains(self) -> Dict:
        return {r: rb.get_chain() for r, rb in self.regions.items()}

    def get_merkle_structure(self) -> dict:
        structure = {"root": "Ulusal Seçim Zinciri", "children": [], "merkle_root": ""}

        conn = get_db_connection()
        cur = conn.cursor()

        # 1) Bölge blokları ve kökleri
        region_roots = []
        for region in REGIONS:
            # A) Bölge zincir bütünlüğünü kontrol et (isteğe bağlı)
            cur.execute("SELECT BlockIndex, PreviousHash, Timestamp, VoterID_Hashed, Candidate, Hash FROM Blocks WHERE Region = ? ORDER BY BlockIndex", (region,))
            rows = cur.fetchall()
            blocks = []
            for r in rows:
                blocks.append({
                    "index": r["BlockIndex"],
                    "previous_hash": r["PreviousHash"],
                    "timestamp": r["Timestamp"],
                    "voter_id_hash": r["VoterID_Hashed"],
                    "candidate": r["Candidate"],
                    "hash": r["Hash"],  # lowercase key
                })
            ok = validate_chain(blocks, region)

            # B) Bölge Merkle root’unu RegionRoots’tan al
            cur.execute("SELECT MerkleRoot, UpdatedAt FROM RegionRoots WHERE Region = ?", (region,))
            root_row = cur.fetchone()
            region_root = root_row["MerkleRoot"] if root_row else ""

            entry = {
                "region": region,
                "status": "OK" if ok else "BROKEN",
                "blocks": blocks,
                "merkle_root": region_root,
                "updated_at": root_row["UpdatedAt"] if root_row else None
            }
            structure["children"].append(entry)
            if ok and region_root:
                region_roots.append(region_root)

        # 2) Ulusal Merkle root — bölge köklerini kullan
        structure["merkle_root"] = calculate_merkle_root(region_roots)

        conn.close()
        return structure
