# blockchain/block.py
import hashlib
import time
from typing import List
from db.connection import get_db_connection

REGIONS = [
    "Marmara",
    "Ege",
    "Akdeniz",
    "Iç Anadolu",
    "Karadeniz",
    "Doğu Anadolu",
    "Güneydoğu Anadolu"
]

class Block:
    def __init__(self, index: int, previous_hash: str, timestamp: int, voter_id_hash: str, candidate: str, hash: str):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.voter_id_hash = voter_id_hash
        self.candidate = candidate
        self.hash = hash

    def to_dict(self):
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
        self.vote_counts = {}
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis = Block(0, "0", int(time.time()), "Genesis", "Genesis", self.calculate_hash(0, "0", "Genesis", "Genesis"))
        self.chain.append(genesis)

    def calculate_hash(self, index, previous_hash, voter_id_hash, candidate):
        value = f"{index}{previous_hash}{voter_id_hash}{candidate}"
        return hashlib.sha256(value.encode()).hexdigest()

    def add_vote(self, voter_id: str, candidate: str):
        conn = get_db_connection()
        cursor = conn.cursor()

        # 1. Seçmen kontrolü (TC ve bölge eşleşmesi)
        cursor.execute(
            "SELECT HasVoted FROM Voters WHERE TC = ? AND Region = ?",
            (voter_id, self.region_name)
        )
        result = cursor.fetchone()

        if not result:
            cursor.close()
            conn.close()
            raise ValueError("Seçmen bulunamadı veya bölge eşleşmiyor.")

        if result["HasVoted"]:
            cursor.close()
            conn.close()
            raise ValueError("Bu TC ile zaten oy kullanılmış.")

        # 2. Blok oluşturma ve zincire ekleme
        voter_id_hash = hashlib.sha256(voter_id.encode()).hexdigest()
        index = len(self.chain)
        previous_hash = self.chain[-1].hash
        timestamp = int(time.time())
        hash_value = self.calculate_hash(index, previous_hash, voter_id_hash, candidate)

        block = Block(index, previous_hash, timestamp, voter_id_hash, candidate, hash_value)
        self.chain.append(block)
        self.save_block_to_db(block)

        self.vote_counts[candidate] = self.vote_counts.get(candidate, 0) + 1

        # 3. Seçmeni işaretle (HasVoted = 1)
        cursor.execute(
            "UPDATE Voters SET HasVoted = 1 WHERE TC = ?",
            (voter_id,)
        )
        conn.commit()
        cursor.close()
        conn.close()

    def get_results(self):
        return self.vote_counts

    def get_chain(self):
        return [block.to_dict() for block in self.chain]

    def save_block_to_db(self, block: Block):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO Blocks (Region, BlockIndex, PreviousHash, Timestamp, VoterID_Hashed, Candidate, Hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (self.region_name, block.index, block.previous_hash, block.timestamp, block.voter_id_hash, block.candidate,
              block.hash))
        conn.commit()
        cursor.close()
        conn.close()

class MainBlockchain:
    def __init__(self):
        self.regions = {region: RegionalBlockchain(region) for region in REGIONS}

    def vote(self, region: str, voter_id: str, candidate: str):
        if region not in self.regions:
            raise ValueError("Geçersiz bölge")
        self.regions[region].add_vote(voter_id, candidate)

    def get_all_results(self):
        results = {}
        for region, chain in self.regions.items():
            results[region] = chain.get_results()
        return results

    def get_all_chains(self):
        return {
            region: chain.get_chain() for region, chain in self.regions.items()
        }
