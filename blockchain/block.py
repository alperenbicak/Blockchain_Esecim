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
        conn2 = get_db_connection()
        cur2 = conn2.cursor()

        # A) Bölge root’larını oku
        cur2.execute("SELECT MerkleRoot FROM RegionRoots ORDER BY Region")
        roots = [r["MerkleRoot"] for r in cur2.fetchall()]

        # B) Ulusal Merkle root’u hesapla
        national_root = calculate_merkle_root(roots)
        now = int(time.time())

        # C) Upsert NationalRoots tablosuna
        cur2.execute("""
          UPDATE NationalRoots
             SET MerkleRoot = ?, UpdatedAt = ?
           WHERE Id = 0
        """, (national_root, now))

        conn2.commit()
        conn2.close()
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
        conn = get_db_connection()
        cur = conn.cursor()

        structure = {
            "root": "Ulusal Seçim Zinciri",
            "children": [],
            "stored_merkle_root": "",
            "live_merkle_root": "",
            "regions": []
        }

        # 1) RegionRoots tablosundan kayıtlı kökler
        cur.execute("SELECT Region, MerkleRoot, UpdatedAt FROM RegionRoots")
        reg_rows = cur.fetchall()
        stored_region_roots = {r["Region"]: r["MerkleRoot"] for r in reg_rows}

        # 2) Blocks’dan canlı hash listesiyle yeniden hesapla
        live_region_roots = {}
        for region in REGIONS:
            cur.execute(
                "SELECT Hash FROM Blocks WHERE Region = ? ORDER BY BlockIndex",
                (region,)
            )
            hashes = [r["Hash"] for r in cur.fetchall()]
            live_region_roots[region] = calculate_merkle_root(hashes)

            structure["regions"].append({
                "region": region,
                "stored_root": stored_region_roots.get(region, ""),
                "live_root": live_region_roots[region],
                "match": stored_region_roots.get(region, "") == live_region_roots[region]
            })

        # 3) Ulusal kayıtlı root
        cur.execute("SELECT MerkleRoot, UpdatedAt FROM NationalRoots WHERE Id = 0")
        nat_row = cur.fetchone()
        structure["stored_merkle_root"] = nat_row["MerkleRoot"]

        # 4) Ulusal canlı root
        structure["live_merkle_root"] = calculate_merkle_root(
            list(live_region_roots.values())
        )
        structure["match"] = (
                structure["stored_merkle_root"] == structure["live_merkle_root"]
        )

        conn.close()
        return structure
