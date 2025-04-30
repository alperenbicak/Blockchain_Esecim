# blockchain/utils.py

import hashlib
from typing import List, Dict

def calculate_block_hash(
    index: int,
    previous_hash: str,
    voter_id_hash: str,
    candidate: str,
    region: str
) -> str:
    """
    Tek bir bloğun hash’ini, içindeki tüm alanlardan (ve bölgeden) SHA-256 ile yeniden hesaplar.
    """
    raw = f"{index}{previous_hash}{voter_id_hash}{candidate}{region}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def validate_chain(blocks: List[Dict], region: str) -> bool:
    """
    1) Önceki bloğun hash’inin current.previous_hash ile eşleştiğini,
    2) current.hash değerinin doğru hesaplanmış hash olduğunu kontrol eder.
    Eğer herhangi bir aşamada tutarsızlık varsa False döner.
    """
    for i, block in enumerate(blocks):
        # Genesis bloğunu doğrula
        if i == 0:
            expected_genesis = calculate_block_hash(
                index=0,
                previous_hash="0",
                voter_id_hash="Genesis",
                candidate="Genesis",
                region=region
            )
            if block["hash"] != expected_genesis:
                return False
            continue

        prev = blocks[i - 1]

        # 1️⃣ Zincir bağlantısını kontrol et
        if block["previous_hash"] != prev["hash"]:
            return False

        # 2️⃣ Blok içeriğini tekrar hash’le ve karşılaştır
        recalculated = calculate_block_hash(
            index=block["index"],
            previous_hash=block["previous_hash"],
            voter_id_hash=block["voter_id_hash"],
            candidate=block["candidate"],
            region=region
        )
        if recalculated != block["hash"]:
            return False

    return True

def calculate_merkle_root(hashes: List[str]) -> str:
    """
    Verilen hash listesi üzerinden Merkle Root’u hesaplar.
    Eğer tek sayıda eleman varsa son elemanı çiftler.
    """
    if not hashes:
        return ""
    if len(hashes) == 1:
        return hashes[0]

    level = hashes[:]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        next_level = []
        for i in range(0, len(level), 2):
            combined = (level[i] + level[i + 1]).encode("utf-8")
            next_level.append(hashlib.sha256(combined).hexdigest())
        level = next_level

    return level[0]
