import hashlib
import time
import os
import base64
from typing import List, Dict, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from db.connection import get_db_connection
from blockchain.utils import validate_chain, calculate_merkle_root

REGIONS = [
    "Marmara", "Ege", "Akdeniz", "Iç Anadolu",
    "Karadeniz", "Doğu Anadolu", "Güneydoğu Anadolu"
]

# Bölge adı normalizasyonu için eşleştirme tablosu
REGION_MAPPING = {
    "İç Anadolu": "Iç Anadolu",
    "İc Anadolu": "Iç Anadolu",
    "Ic Anadolu": "Iç Anadolu",
    "İç anadolu": "Iç Anadolu",
    "Iç anadolu": "Iç Anadolu",
    "İc anadolu": "Iç Anadolu",
    "Ic anadolu": "Iç Anadolu",
    "iç anadolu": "Iç Anadolu",
    "iç Anadolu": "Iç Anadolu",
    "ic anadolu": "Iç Anadolu",
    "Doğu Anadolu": "Doğu Anadolu",
    "Dogu Anadolu": "Doğu Anadolu",
    "doğu anadolu": "Doğu Anadolu",
    "dogu anadolu": "Doğu Anadolu",
    "Güneydoğu Anadolu": "Güneydoğu Anadolu",
    "Guneydoğu Anadolu": "Güneydoğu Anadolu",
    "Güneydogu Anadolu": "Güneydoğu Anadolu",
    "Guneydogu Anadolu": "Güneydoğu Anadolu",
    "güneydoğu anadolu": "Güneydoğu Anadolu",
    "güneydogu anadolu": "Güneydoğu Anadolu",
    "guneydoğu anadolu": "Güneydoğu Anadolu",
    "guneydogu anadolu": "Güneydoğu Anadolu"
}

# Anahtar dosyaları için sabit yollar
PRIVATE_KEY_PATH = os.path.join(os.path.dirname(__file__), "..", "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(os.path.dirname(__file__), "..", "public_key.pem")

def normalize_region_name(region_name: str) -> str:
    """
    Bölge adındaki Türkçe karakter sorunlarını çözer ve standart hale getirir.
    """
    if region_name in REGION_MAPPING:
        return REGION_MAPPING[region_name]
    # Eşleştirme tablosunda yoksa direk karşılaştırma yapmak için kendisini döndür
    return region_name

def generate_keypair():
    """RSA anahtar çifti oluşturur ve dosyalara kaydeder"""
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        print("Anahtarlar zaten mevcut, yeniden oluşturulmadı.")
        return

    # 2048-bit RSA anahtar çifti oluştur
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Özel anahtarı PEM formatında kaydet
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Açık anahtarı PEM formatında kaydet
    public_key = private_key.public_key()
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    print("RSA anahtar çifti oluşturuldu ve kaydedildi.")

def load_private_key():
    """Özel anahtarı yükler"""
    if not os.path.exists(PRIVATE_KEY_PATH):
        generate_keypair()
        
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )

def load_public_key():
    """Açık anahtarı yükler"""
    if not os.path.exists(PUBLIC_KEY_PATH):
        generate_keypair()
        
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(
            f.read()
        )

def sign_data(data):
    """Veriyi özel anahtarla imzalar"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    private_key = load_private_key()
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(data, signature, public_key=None):
    """İmzayı açık anahtarla doğrular"""
    # İmza None ise False döndür
    if signature is None:
        return False
        
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    signature = base64.b64decode(signature)
    
    if public_key is None:
        public_key = load_public_key()
    
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

class Block:
    def __init__(self, index: int, previous_hash: str, timestamp: int,
                 voter_id_hash: str, candidate: str, hash: str, signature: Optional[str] = None):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.voter_id_hash = voter_id_hash
        self.candidate = candidate
        self.hash = hash
        self.signature = signature
        
        # Eğer imza yoksa, hash üzerinden imza oluştur
        if not self.signature:
            self.signature = sign_data(self.hash)

    def to_dict(self) -> Dict:
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "voter_id_hash": self.voter_id_hash,
            "candidate": self.candidate,
            "hash": self.hash,
            "signature": self.signature
        }
    
    def verify(self) -> bool:
        """Bloğun imzasını doğrular"""
        return verify_signature(self.hash, self.signature)

class RegionalBlockchain:
    def __init__(self, region_name: str):
        self.region_name = region_name
        self.chain: List[Block] = []
        
        # Anahtarların varlığını kontrol et
        if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
            generate_keypair()
            
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

        # --- Debug bilgisi: Girilen değerleri kontrol et ---
        print(f"DEBUG: Oy verme işlemi başlatıldı - TC: {voter_id[:3]}***, Bölge: {self.region_name}, Aday: {candidate}")
        
        # Önce seçmen kaydının genel olarak var olup olmadığını kontrol et
        cur.execute("SELECT TC, Region, HasVoted FROM Voters WHERE TC = ?", (voter_id,))
        voter_record = cur.fetchone()
        
        if not voter_record:
            conn.close()
            raise ValueError(f"Seçmen kaydı bulunamadı! TC: {voter_id[:3]}***")
        
        print(f"DEBUG: Seçmen kaydı bulundu. Kayıtlı bölge: {voter_record['Region']}, Mevcut bölge: {self.region_name}")
        
        # --- Oy kaydı ve HasVoted kontrolü ---
        # Şimdi bölge eşleşmesini kontrol et
        cur.execute(
            "SELECT HasVoted FROM Voters WHERE TC = ? AND Region = ?",
            (voter_id, self.region_name)
        )
        row = cur.fetchone()
        
        # Seçmenin gerçek bölgesini saklayalım (veritabanında işaretlemek için kullanacağız)
        actual_voter_region = voter_record['Region']
        
        if not row:
            # Bölge adı normalizasyonunu dene
            print(f"DEBUG: Doğrudan bölge eşleşmesi yok. Normalizasyon deneniyor.")
            normalized_region = normalize_region_name(self.region_name)
            print(f"DEBUG: Normalize edilmiş bölge: {normalized_region}")
            
            # Ayrıca kullanıcının bölgesini de normalize et
            voter_region = voter_record['Region']
            voter_normalized_region = normalize_region_name(voter_region)
            print(f"DEBUG: Kullanıcı bölgesi normalize: {voter_normalized_region}")
            
            # ÖNEMLİ: Burada çift yönlü kontrol yapıyoruz!
            # 1. Durumumuz kullanıcının bölge adı "İç Anadolu", normalize formu "Iç Anadolu"
            # 2. Şu anki bölge adı ise zaten "Iç Anadolu"
            
            # Kontrol 1: Mevcut bölge adının normalize hali ile seçmenin kayıtlı olduğu bölge adını karşılaştır
            if normalized_region == voter_region:
                print(f"DEBUG: Normalize edilmiş bölge adı, seçmenin bölgesiyle eşleşti: {normalized_region} == {voter_region}")
                self.region_name = voter_region
                row = {"HasVoted": voter_record["HasVoted"]}
            
            # Kontrol 2: Seçmenin bölge adının normalize hali ile mevcut bölge adını karşılaştır
            elif voter_normalized_region == self.region_name:
                print(f"DEBUG: Normalize edilmiş seçmen bölgesi, mevcut bölgeyle eşleşti: {voter_normalized_region} == {self.region_name}")
                row = {"HasVoted": voter_record["HasVoted"]}
            
            # Kontrol 3: Her iki bölge adının normalize halleri karşılaştır
            elif normalized_region == voter_normalized_region:
                print(f"DEBUG: Her iki bölgenin normalize halleri eşleşti: {normalized_region} == {voter_normalized_region}")
                self.region_name = normalized_region  # En tutarlı hali kullan
                row = {"HasVoted": voter_record["HasVoted"]}
                
                # Veritabanındaki bölge adını da düzeltmeyi dene
                try:
                    print(f"DEBUG: Veritabanındaki bölge adını düzeltme deneniyor: {voter_region} -> {normalized_region}")
                    cur.execute(
                        "UPDATE Voters SET Region = ? WHERE TC = ? AND Region = ?",
                        (normalized_region, voter_id, voter_region)
                    )
                    conn.commit()
                    print("DEBUG: Veritabanındaki bölge adı güncellendi.")
                    actual_voter_region = normalized_region  # Güncellenmiş bölge adını kullan
                except Exception as e:
                    print(f"DEBUG: Veritabanı güncelleme hatası: {str(e)}")
                    # Hata durumunda işleme devam edebiliriz, veritabanı güncellemek kritik değil
                    pass
                    
            # Eğer normalizasyonla hala eşleşme sağlanamazsa, mevcut bölge adını kullanıcının bölgesiyle değiştirmeyi dene
            elif not row:
                print(f"DEBUG: Son çare olarak kullanıcının bölgesi kullanılıyor: {voter_region}")
                self.region_name = voter_region
                cur.execute(
                    "SELECT HasVoted FROM Voters WHERE TC = ? AND Region = ?",
                    (voter_id, voter_region)
                )
                row = cur.fetchone()
            
            # Eğer yine bulunamazsa, hata veren bölge bilgisini göster
            if not row:
                conn.close()
                raise ValueError(f"Seçmen bölge eşleşmiyor! Seçmen bölgesi: {voter_record['Region']}, İstenen bölge: {self.region_name}")
        
        # Seçmenin daha önce oy kullanıp kullanmadığını kontrol et
        if row["HasVoted"] == 1:
            conn.close()
            raise ValueError(f"Bu seçmen zaten oy kullandı! TC: {voter_id[:3]}***")

        # Blok oluşturma & DB'ye kaydetme
        voter_hash = hashlib.sha256(voter_id.encode()).hexdigest()
        idx = len(self.chain)
        prev = self.chain[-1].hash
        ts = int(time.time())
        h = self.calculate_hash(idx, prev, voter_hash, candidate)
        block = Block(idx, prev, ts, voter_hash, candidate, h)
        
        # Blok imzasını doğrula
        if not block.verify():
            conn.close()
            raise ValueError("Blok imzası doğrulanamadı! Güvenlik ihlali olabilir.")
            
        self.chain.append(block)
        self.save_block_to_db(block)

        # Seçmeni işaretle - ÖNEMLİ: Burada actual_voter_region kullanarak doğru bölgeyi güncelliyoruz
        print(f"DEBUG: Seçmen oy kullandı olarak işaretleniyor. TC: {voter_id[:3]}***, Bölge: {actual_voter_region}")
        
        cur.execute(
            "UPDATE Voters SET HasVoted = 1 WHERE TC = ? AND Region = ?",
            (voter_id, actual_voter_region)
        )
        
        # İşlem başarılı mı kontrol et
        if cur.rowcount <= 0:
            print(f"UYARI: HasVoted güncellemesi başarısız olmuş olabilir! Etkilenen satır sayısı: {cur.rowcount}")
            
            # REGIONS içindeki tam eşleşen bölgeyi aramayı da dene
            for region in REGIONS:
                if normalize_region_name(region) == normalize_region_name(actual_voter_region):
                    print(f"DEBUG: İkinci deneme: Standart bölge adı '{region}' ile güncelleme deneniyor")
                    cur.execute(
                        "UPDATE Voters SET HasVoted = 1 WHERE TC = ? AND Region = ?",
                        (voter_id, region)
                    )
                    if cur.rowcount > 0:
                        print(f"DEBUG: İkinci deneme başarılı! Bölge '{region}' ile güncellendi.")
                        break
        else:
            print(f"DEBUG: HasVoted başarıyla güncellendi! Etkilenen satır sayısı: {cur.rowcount}")
            
        conn.commit()

        # --- Bölge Merkle Root güncelle ---
        cur.execute(
            "SELECT Hash FROM Blocks WHERE Region = ? ORDER BY BlockIndex ASC",
            (self.region_name,)
        )
        hashes = [r["Hash"] for r in cur.fetchall()]
        region_root = calculate_merkle_root(hashes)
        now = int(time.time())
        
        # Bölge kökünü imzala
        region_signature = sign_data(region_root)
        
        # Signature sütununu kontrol et ve gerekirse ekle
        try:
            cur.execute("SELECT Signature FROM RegionRoots LIMIT 1")
        except Exception:
            # Sütun yoksa ekle
            cur.execute("ALTER TABLE RegionRoots ADD COLUMN Signature TEXT")
        
        cur.execute("""
                    INSERT INTO RegionRoots (Region, MerkleRoot, UpdatedAt, Signature)
                    VALUES (?, ?, ?, ?) ON CONFLICT(Region) DO
                    UPDATE SET
                        MerkleRoot = excluded.MerkleRoot,
                        UpdatedAt = excluded.UpdatedAt,
                        Signature = excluded.Signature
                    """, (self.region_name, region_root, now, region_signature))
        conn.commit()

        # --- Ulusal Merkle Root güncelle ---
        # Burada tüm bölge köklerini tekrar çekip ulusal kökü hesaplıyoruz
        # Alfabetik değil, REGIONS sırasına göre alıyoruz
        region_roots = []
        for region in REGIONS:
            cur.execute("SELECT MerkleRoot FROM RegionRoots WHERE Region = ?", (region,))
            result = cur.fetchone()
            if result:
                region_roots.append(result["MerkleRoot"])
                
        national_root = calculate_merkle_root(region_roots)
        national_signature = sign_data(national_root)
        
        # Signature sütununu kontrol et ve gerekirse ekle
        try:
            cur.execute("SELECT Signature FROM NationalRoots LIMIT 1")
        except Exception:
            # Sütun yoksa ekle
            cur.execute("ALTER TABLE NationalRoots ADD COLUMN Signature TEXT")
            
        cur.execute("""
                    UPDATE NationalRoots
                    SET MerkleRoot = ?,
                        UpdatedAt  = ?,
                        Signature  = ?
                    WHERE Id = 0
                    """, (national_root, now, national_signature))
        conn.commit()

        conn.close()
        
    def load_chain_from_db(self):
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Signature sütunu var mı kontrol et
        has_signature_column = True
        try:
            cur.execute("SELECT Signature FROM Blocks LIMIT 1")
        except Exception:
            has_signature_column = False
            # Sütunu ekle
            cur.execute("ALTER TABLE Blocks ADD COLUMN Signature TEXT")
            conn.commit()
        
        if has_signature_column:
            cur.execute("""
                SELECT BlockIndex, PreviousHash, Timestamp,
                       VoterID_Hashed, Candidate, Hash, Signature
                FROM Blocks
                WHERE Region = ?
                ORDER BY BlockIndex
            """, (self.region_name,))
            rows = cur.fetchall()
            
            self.chain = [
                Block(r["BlockIndex"], r["PreviousHash"], r["Timestamp"],
                      r["VoterID_Hashed"], r["Candidate"], r["Hash"], r["Signature"])
                for r in rows
            ]
        else:
            cur.execute("""
                SELECT BlockIndex, PreviousHash, Timestamp,
                       VoterID_Hashed, Candidate, Hash
                FROM Blocks
                WHERE Region = ?
                ORDER BY BlockIndex
            """, (self.region_name,))
            rows = cur.fetchall()
            
            self.chain = []
            for r in rows:
                # İmzasız bloklar için imza oluştur
                block = Block(r["BlockIndex"], r["PreviousHash"], r["Timestamp"],
                          r["VoterID_Hashed"], r["Candidate"], r["Hash"])
                self.chain.append(block)
                
                # İmzayı veritabanına kaydet
                cur.execute("""
                    UPDATE Blocks SET Signature = ?
                    WHERE Region = ? AND BlockIndex = ?
                """, (block.signature, self.region_name, block.index))
            
            conn.commit()
        
        conn.close()

    def save_block_to_db(self, block: Block):
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Signature sütununu kontrol et ve gerekirse ekle
        try:
            cur.execute("SELECT Signature FROM Blocks LIMIT 1")
        except Exception:
            # Sütun yoksa ekle
            cur.execute("ALTER TABLE Blocks ADD COLUMN Signature TEXT")
            conn.commit()
        
        cur.execute("""
            INSERT INTO Blocks
              (Region, BlockIndex, PreviousHash, Timestamp,
               VoterID_Hashed, Candidate, Hash, Signature)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            self.region_name,
            block.index,
            block.previous_hash,
            block.timestamp,
            block.voter_id_hash,
            block.candidate,
            block.hash,
            block.signature
        ))
        conn.commit()
        conn.close()

    def get_chain(self) -> List[Dict]:
        # DB'den satır bazlı okur, dict listesi döner
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Signature sütunu var mı kontrol et
        has_signature_column = True
        try:
            cur.execute("SELECT Signature FROM Blocks LIMIT 1")
        except Exception:
            has_signature_column = False
            
        if has_signature_column:
            cur.execute("""
                SELECT BlockIndex, PreviousHash, Timestamp,
                       VoterID_Hashed, Candidate, Hash, Signature
                FROM Blocks
                WHERE Region = ?
                ORDER BY BlockIndex
            """, (self.region_name,))
        else:
            cur.execute("""
                SELECT BlockIndex, PreviousHash, Timestamp,
                       VoterID_Hashed, Candidate, Hash
                FROM Blocks
                WHERE Region = ?
                ORDER BY BlockIndex
            """, (self.region_name,))
            
        rows = cur.fetchall()
        conn.close()

        chain_data = []
        for r in rows:
            block_data = {
                "index": r["BlockIndex"],
                "previous_hash": r["PreviousHash"],
                "timestamp": r["Timestamp"],
                "voter_id_hash": r["VoterID_Hashed"],
                "candidate": r["Candidate"],
                "hash": r["Hash"],
            }
            
            if has_signature_column:
                block_data["signature"] = r["Signature"]
                
            chain_data.append(block_data)
            
        return chain_data

    def verify_chain_integrity(self) -> bool:
        """Zincirdeki tüm blokların imzalarını ve hash bağlantılarını doğrular"""
        if not self.chain:
            return True  # Boş zincir geçerli kabul edilir
            
        for i, block in enumerate(self.chain):
            # İmzayı doğrula
            if not block.verify():
                print(f"Blok {block.index} için imza doğrulaması başarısız oldu!")
                return False
                
            # Genesis bloğu için özel kontrol
            if i == 0:
                if block.previous_hash != "0" or block.index != 0:
                    print("Genesis bloğu hatalı!")
                    return False
                continue
                
            # Diğer bloklar için zincir bağlantısını kontrol et
            prev_block = self.chain[i-1]
            if block.previous_hash != prev_block.hash:
                print(f"Blok {block.index} için zincir bağlantısı hatalı!")
                return False
                
            # Hash değerini yeniden hesapla ve karşılaştır
            expected_hash = self.calculate_hash(
                block.index, 
                block.previous_hash, 
                block.voter_id_hash, 
                block.candidate
            )
            if expected_hash != block.hash:
                print(f"Blok {block.index} için hash değeri hatalı!")
                return False
                
        return True

class MainBlockchain:
    def __init__(self):
        # Anahtarların varlığını kontrol et
        if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
            generate_keypair()
            
        self.regions = {r: RegionalBlockchain(r) for r in REGIONS}
        
        # Tüm bölgelerin zincirlerini kontrol et ve eksik imzaları tamamla
        self._update_missing_signatures()
    
    def _update_missing_signatures(self):
        """Tüm bölgelerdeki eksik imzaları kontrol eder ve tamamlar"""
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Signature sütunu var mı kontrol et
        try:
            cur.execute("SELECT Signature FROM Blocks LIMIT 1")
        except Exception:
            # Sütun yoksa ekle
            cur.execute("ALTER TABLE Blocks ADD COLUMN Signature TEXT")
            conn.commit()
        
        # Her bölge için eksik imzaları tamamla
        for region in REGIONS:
            cur.execute("""
                SELECT BlockIndex, Hash, Signature
                FROM Blocks
                WHERE Region = ?
                ORDER BY BlockIndex
            """, (region,))
            
            rows = cur.fetchall()
            for row in rows:
                # İmza yoksa oluştur ve güncelle
                if row["Signature"] is None:
                    signature = sign_data(row["Hash"])
                    cur.execute("""
                        UPDATE Blocks
                        SET Signature = ?
                        WHERE Region = ? AND BlockIndex = ?
                    """, (signature, region, row["BlockIndex"]))
        
        # RegionRoots tablosunda Signature sütunu kontrolü
        try:
            cur.execute("SELECT Signature FROM RegionRoots LIMIT 1")
        except Exception:
            cur.execute("ALTER TABLE RegionRoots ADD COLUMN Signature TEXT")
        
        # Bölge köklerinin imzalarını kontrol et
        cur.execute("SELECT Region, MerkleRoot, Signature FROM RegionRoots")
        for row in cur.fetchall():
            if row["Signature"] is None and row["MerkleRoot"]:
                signature = sign_data(row["MerkleRoot"])
                cur.execute("""
                    UPDATE RegionRoots
                    SET Signature = ?
                    WHERE Region = ?
                """, (signature, row["Region"]))
        
        # NationalRoots tablosunda Signature sütunu kontrolü
        try:
            cur.execute("SELECT Signature FROM NationalRoots LIMIT 1")
        except Exception:
            cur.execute("ALTER TABLE NationalRoots ADD COLUMN Signature TEXT")
        
        # Ulusal kökün imzasını kontrol et
        cur.execute("SELECT MerkleRoot, Signature FROM NationalRoots WHERE Id = 0")
        row = cur.fetchone()
        if row and row["MerkleRoot"] and (row["Signature"] is None or not verify_signature(row["MerkleRoot"], row["Signature"])):
            signature = sign_data(row["MerkleRoot"])
            cur.execute("""
                UPDATE NationalRoots
                SET Signature = ?
                WHERE Id = 0
            """, (signature,))
        
        conn.commit()
        conn.close()

    def vote(self, region: str, voter_id: str, candidate: str):
        # Debug bilgisi
        print(f"DEBUG: MainBlockchain.vote çağrıldı - Region: {region}, TC: {voter_id[:3]}***")
        
        # Bölge adını normalize et
        normalized_region = normalize_region_name(region)
        print(f"DEBUG: Normalize edilmiş bölge: {normalized_region}")
        
        # Normalize edilmiş bölge adını REGIONS listesinde kontrol et
        if normalized_region not in REGIONS:
            # Tüm geçerli bölge adlarını göster
            valid_regions = ", ".join(REGIONS)
            print(f"DEBUG: Normalize edilmiş bölge ({normalized_region}) REGIONS listesinde bulunamadı!")
            print(f"DEBUG: Geçerli bölgeler: {valid_regions}")
            
            # Hala eşleşme yoksa, doğrudan girilen bölge adını kullan
            try:
                self.regions[region].add_vote(voter_id, candidate)
            except KeyError:
                raise ValueError(f"Geçersiz bölge adı: '{region}'. Geçerli bölgeler: {valid_regions}")
        else:
            # Normalize edilmiş bölge adını kullan
            print(f"DEBUG: '{region}' normalize edildi: '{normalized_region}'. Bu bölge kullanılıyor.")
            self.regions[normalized_region].add_vote(voter_id, candidate)

    def get_all_chains(self) -> Dict:
        return {r: rb.get_chain() for r, rb in self.regions.items()}
        
    def verify_all_chains(self) -> Dict:
        """Tüm bölgesel zincirlerin bütünlüğünü doğrular"""
        results = {}
        for region, blockchain in self.regions.items():
            results[region] = blockchain.verify_chain_integrity()
        return results

    def get_merkle_structure(self) -> dict:
        conn = get_db_connection()
        cur  = conn.cursor()

        structure = {
            "root": "Ulusal Seçim Zinciri",
            "regions": [],
            "stored_merkle_root": "",
            "live_merkle_root": "",
            "stored_signature": "",
            "signature_valid": False,
            "match": True
        }

        live_region_roots = []

        # 1️⃣ Her bölge için zinciri oku, kontrol et, live_root hesapla
        for region in REGIONS:
            # Signature sütununu kontrol et
            has_signature_column = True
            try:
                cur.execute("SELECT Signature FROM Blocks LIMIT 1")
            except Exception:
                has_signature_column = False
                
            if has_signature_column:
                cur.execute("""
                    SELECT BlockIndex, PreviousHash, Timestamp,
                           VoterID_Hashed, Candidate, Hash, Signature
                    FROM Blocks
                    WHERE Region = ?
                    ORDER BY BlockIndex ASC
                """, (region,))
            else:
                cur.execute("""
                    SELECT BlockIndex, PreviousHash, Timestamp,
                           VoterID_Hashed, Candidate, Hash
                    FROM Blocks
                    WHERE Region = ?
                    ORDER BY BlockIndex ASC
                """, (region,))
                
            rows = cur.fetchall()
            
            blocks = []
            for r in rows:
                block = {
                    "index":        r["BlockIndex"],
                    "previous_hash":r["PreviousHash"],
                    "timestamp":    r["Timestamp"],
                    "voter_id_hash":r["VoterID_Hashed"],
                    "candidate":    r["Candidate"],
                    "hash":         r["Hash"]
                }
                
                if has_signature_column:
                    block["signature"] = r["Signature"]
                    
                blocks.append(block)
                
            # Blok zincirinin tutarlılığını kontrol et
            ok = validate_chain(blocks, region)
            
            # İmzaları doğrula
            signatures_valid = True
            if has_signature_column:
                for block in blocks:
                    # İmza varsa kontrol et, yoksa geç
                    if "signature" in block and block["signature"] is not None:
                        if not verify_signature(block["hash"], block["signature"]):
                            signatures_valid = False
                            ok = False
                            break
                    else:
                        # İmza yoksa, bu blok için imza oluştur ve kaydet
                        signature = sign_data(block["hash"])
                        cur.execute("""
                            UPDATE Blocks SET Signature = ?
                            WHERE Region = ? AND BlockIndex = ?
                        """, (signature, region, block["index"]))
                        conn.commit()

            leaf_hashes = [b["hash"] for b in blocks]
            live_root = calculate_merkle_root(leaf_hashes)

            region_data = {
                "region":    region,
                "status":    "OK" if ok else "BROKEN",
                "blocks":    blocks,
                "live_root": live_root
            }
            
            if has_signature_column:
                region_data["signatures_valid"] = signatures_valid
                
            structure["regions"].append(region_data)
            
            if ok:
                live_region_roots.append(live_root)

        # 2️⃣ Canlı ulusal kök
        structure["live_merkle_root"] = calculate_merkle_root(live_region_roots)

        # 3️⃣ Stored (DB'deki) ulusal kökü ve imzasını çek
        has_signature_column = True
        try:
            cur.execute("SELECT MerkleRoot, Signature FROM NationalRoots WHERE Id = 0")
            row = cur.fetchone()
        except Exception:
            has_signature_column = False
            cur.execute("SELECT MerkleRoot FROM NationalRoots WHERE Id = 0")
            row = cur.fetchone()
            
        if row and row["MerkleRoot"]:
            structure["stored_merkle_root"] = row["MerkleRoot"]
            
            if has_signature_column and row["Signature"]:
                structure["stored_signature"] = row["Signature"]
                structure["signature_valid"] = verify_signature(
                    row["MerkleRoot"], 
                    row["Signature"]
                )
            
            # 4️⃣ Match durumu
            structure["match"] = (
                structure["stored_merkle_root"] == structure["live_merkle_root"]
            )

        conn.close()
        return structure