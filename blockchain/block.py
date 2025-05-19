import hashlib
import time
import os
import base64
from typing import List, Dict, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from db.connection import get_db_connection, get_db_session
from db.models import Block as BlockModel, Voter, RegionRoot, NationalRoot
from blockchain.utils import validate_chain, calculate_merkle_root
from sqlalchemy import select, update

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
        # SQLAlchemy ile sorguları dönüştürüyoruz
        with get_db_session() as session:
            # Debug bilgisi: Girilen değerleri kontrol et
            print(f"DEBUG: Oy verme işlemi başlatıldı - TC: {voter_id[:3]}***, Bölge: {self.region_name}, Aday: {candidate}")
            
            # Önce seçmen kaydının genel olarak var olup olmadığını kontrol et
            voter_query = select(Voter).where(Voter.TC == voter_id)
            voter_record = session.execute(voter_query).scalar_one_or_none()
            
            if not voter_record:
                raise ValueError(f"Seçmen kaydı bulunamadı! TC: {voter_id[:3]}***")
            
            print(f"DEBUG: Seçmen kaydı bulundu. Kayıtlı bölge: {voter_record.Region}, Mevcut bölge: {self.region_name}")
            
            # Şimdi bölge eşleşmesini kontrol et
            region_match_query = select(Voter).where(
                (Voter.TC == voter_id) & (Voter.Region == self.region_name)
            )
            row = session.execute(region_match_query).scalar_one_or_none()
            
            # Seçmenin gerçek bölgesini saklayalım
            actual_voter_region = voter_record.Region
            
            if not row:
                # Bölge adı normalizasyonunu dene
                print(f"DEBUG: Doğrudan bölge eşleşmesi yok. Normalizasyon deneniyor.")
                normalized_region = normalize_region_name(self.region_name)
                print(f"DEBUG: Normalize edilmiş bölge: {normalized_region}")
                
                # Ayrıca kullanıcının bölgesini de normalize et
                voter_region = voter_record.Region
                voter_normalized_region = normalize_region_name(voter_region)
                print(f"DEBUG: Kullanıcı bölgesi normalize: {voter_normalized_region}")
                
                # Kontrol 1: Mevcut bölge adının normalize hali ile seçmenin kayıtlı olduğu bölge adını karşılaştır
                if normalized_region == voter_region:
                    print(f"DEBUG: Normalize edilmiş bölge adı, seçmenin bölgesiyle eşleşti: {normalized_region} == {voter_region}")
                    self.region_name = voter_region
                    row = voter_record
                
                # Kontrol 2: Seçmenin bölge adının normalize hali ile mevcut bölge adını karşılaştır
                elif voter_normalized_region == self.region_name:
                    print(f"DEBUG: Normalize edilmiş seçmen bölgesi, mevcut bölgeyle eşleşti: {voter_normalized_region} == {self.region_name}")
                    row = voter_record
                
                # Kontrol 3: Her iki bölge adının normalize halleri karşılaştır
                elif normalized_region == voter_normalized_region:
                    print(f"DEBUG: Her iki bölgenin normalize halleri eşleşti: {normalized_region} == {voter_normalized_region}")
                    self.region_name = normalized_region  # En tutarlı hali kullan
                    row = voter_record
                    
                    # Veritabanındaki bölge adını da düzeltmeyi dene
                    try:
                        print(f"DEBUG: Veritabanındaki bölge adını düzeltme deneniyor: {voter_region} -> {normalized_region}")
                        update_stmt = update(Voter).where(
                            (Voter.TC == voter_id) & (Voter.Region == voter_region)
                        ).values(Region=normalized_region)
                        
                        session.execute(update_stmt)
                        session.commit()
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
                    voter_in_region_query = select(Voter).where(
                        (Voter.TC == voter_id) & (Voter.Region == voter_region)
                    )
                    row = session.execute(voter_in_region_query).scalar_one_or_none()
                
                # Eğer yine bulunamazsa, hata veren bölge bilgisini göster
                if not row:
                    raise ValueError(f"Seçmen bölge eşleşmiyor! Seçmen bölgesi: {voter_record.Region}, İstenen bölge: {self.region_name}")
            
            # Seçmenin daha önce oy kullanıp kullanmadığını kontrol et
            if row.HasVoted:
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
                raise ValueError("Blok imzası doğrulanamadı! Güvenlik ihlali olabilir.")
                
            self.chain.append(block)
            self.save_block_to_db(block)

            # Seçmeni işaretle - ÖNEMLİ: Burada actual_voter_region kullanarak doğru bölgeyi güncelliyoruz
            print(f"DEBUG: Seçmen oy kullandı olarak işaretleniyor. TC: {voter_id[:3]}***, Bölge: {actual_voter_region}")
            
            update_stmt = update(Voter).where(
                (Voter.TC == voter_id) & (Voter.Region == actual_voter_region)
            ).values(HasVoted=True)
            
            result = session.execute(update_stmt)
            session.commit()
            
            # İşlem başarılı mı kontrol et
            if result.rowcount <= 0:
                print(f"UYARI: HasVoted güncellemesi başarısız olmuş olabilir! Etkilenen satır sayısı: {result.rowcount}")
                
                # REGIONS içindeki tam eşleşen bölgeyi aramayı da dene
                for region in REGIONS:
                    if normalize_region_name(region) == normalize_region_name(actual_voter_region):
                        print(f"DEBUG: İkinci deneme: Standart bölge adı '{region}' ile güncelleme deneniyor")
                        update_stmt = update(Voter).where(
                            (Voter.TC == voter_id) & (Voter.Region == region)
                        ).values(HasVoted=True)
                        
                        result = session.execute(update_stmt)
                        session.commit()
                        
                        if result.rowcount > 0:
                            print(f"DEBUG: İkinci deneme başarılı! Bölge '{region}' ile güncellendi.")
                            break
            else:
                print(f"DEBUG: HasVoted başarıyla güncellendi! Etkilenen satır sayısı: {result.rowcount}")

            # --- Bölge Merkle Root güncelle ---
            blocks_query = select(BlockModel.Hash).where(
                BlockModel.Region == self.region_name
            ).order_by(BlockModel.BlockIndex.asc())
            
            hashes = [row[0] for row in session.execute(blocks_query).fetchall()]
            region_root = calculate_merkle_root(hashes)
            now = int(time.time())
            
            # Bölge kökünü imzala
            region_signature = sign_data(region_root)

            # RegionRoot tablosuna ekle veya güncelle
            region_root_obj = session.execute(
                select(RegionRoot).where(RegionRoot.Region == self.region_name)
            ).scalar_one_or_none()
            
            if region_root_obj:
                # Mevcut kaydı güncelle
                region_root_obj.MerkleRoot = region_root
                region_root_obj.UpdatedAt = now
                region_root_obj.Signature = region_signature
            else:
                # Yeni kayıt ekle
                new_region_root = RegionRoot(
                    Region=self.region_name,
                    MerkleRoot=region_root,
                    UpdatedAt=now,
                    Signature=region_signature
                )
                session.add(new_region_root)
                
            session.commit()

            # --- Ulusal Merkle Root güncelle ---
            # Burada tüm bölge köklerini tekrar çekip ulusal kökü hesaplıyoruz
            # Alfabetik değil, REGIONS sırasına göre alıyoruz
            region_roots = []
            for region in REGIONS:
                region_root_query = select(RegionRoot.MerkleRoot).where(RegionRoot.Region == region)
                result = session.execute(region_root_query).scalar_one_or_none()
                if result:
                    region_roots.append(result)
                    
            national_root = calculate_merkle_root(region_roots)
            national_signature = sign_data(national_root)

            # NationalRoot tablosunu güncelle (tek bir kayıt var, Id=0)
            national_root_obj = session.execute(
                select(NationalRoot).where(NationalRoot.Id == 0)
            ).scalar_one_or_none()
            
            if national_root_obj:
                # Mevcut kaydı güncelle
                national_root_obj.MerkleRoot = national_root
                national_root_obj.UpdatedAt = now
                national_root_obj.Signature = national_signature
            else:
                # Yeni kayıt ekle
                new_national_root = NationalRoot(
                    Id=0,
                    MerkleRoot=national_root,
                    UpdatedAt=now,
                    Signature=national_signature
                )
                session.add(new_national_root)
                
            session.commit()
        
    def load_chain_from_db(self):
        # SQLAlchemy ile veritabanından zinciri yükle
        with get_db_session() as session:
            # Bölgeye ait blokları çek
            blocks_query = select(BlockModel).where(
                BlockModel.Region == self.region_name
            ).order_by(BlockModel.BlockIndex.asc())
            
            db_blocks = session.execute(blocks_query).scalars().all()
            
            # Çekilen blokları Block nesnesine dönüştür
            self.chain = []
            for block in db_blocks:
                block_obj = Block(
                    block.BlockIndex,
                    block.PreviousHash,
                    block.Timestamp,
                    block.VoterID_Hashed,
                    block.Candidate,
                    block.Hash,
                    block.Signature
                )
                self.chain.append(block_obj)
                
                # İmza yoksa oluştur ve güncelle
                if not block.Signature:
                    # İmzayı güncelle
                    block_update = update(BlockModel).where(
                        (BlockModel.Region == self.region_name) &
                        (BlockModel.BlockIndex == block.BlockIndex)
                    ).values(Signature=block_obj.signature)
                    
                    session.execute(block_update)
            
            # Tüm değişiklikleri kaydet
            session.commit()

    def save_block_to_db(self, block: Block):
        # SQLAlchemy ile bloğu veritabanına kaydet
        with get_db_session() as session:
            new_block = BlockModel(
                Region=self.region_name,
                BlockIndex=block.index,
                PreviousHash=block.previous_hash,
                Timestamp=block.timestamp,
                VoterID_Hashed=block.voter_id_hash,
                Candidate=block.candidate,
                Hash=block.hash,
                Signature=block.signature
            )
            
            session.add(new_block)
            session.commit()

    def get_chain(self) -> List[Dict]:
        # SQLAlchemy ile veritabanından zinciri getir
        with get_db_session() as session:
            # Bölgeye ait blokları çek
            blocks_query = select(BlockModel).where(
                BlockModel.Region == self.region_name
            ).order_by(BlockModel.BlockIndex.asc())
            
            blocks = session.execute(blocks_query).scalars().all()
            
            # Blokları dictionary formatına dönüştür
            chain_data = []
            for block in blocks:
                block_data = {
                    "index": block.BlockIndex,
                    "previous_hash": block.PreviousHash,
                    "timestamp": block.Timestamp,
                    "voter_id_hash": block.VoterID_Hashed,
                    "candidate": block.Candidate,
                    "hash": block.Hash,
                    "signature": block.Signature
                }
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
        with get_db_session() as session:
            # Her bölge için eksik imzaları tamamla
            for region in REGIONS:
                blocks_query = select(BlockModel).where(
                    (BlockModel.Region == region) &
                    (BlockModel.Signature == None)
                ).order_by(BlockModel.BlockIndex)
                
                blocks_without_signature = session.execute(blocks_query).scalars().all()
                for block in blocks_without_signature:
                    # İmza oluştur ve güncelle
                    signature = sign_data(block.Hash)
                    block_update = update(BlockModel).where(
                        (BlockModel.Region == region) & 
                        (BlockModel.BlockIndex == block.BlockIndex)
                    ).values(Signature=signature)
                    
                    session.execute(block_update)
            
            # Bölge köklerinin imzalarını kontrol et
            region_roots_query = select(RegionRoot).where(RegionRoot.Signature == None)
            region_roots_without_signature = session.execute(region_roots_query).scalars().all()
            
            for region_root in region_roots_without_signature:
                if region_root.MerkleRoot:
                    signature = sign_data(region_root.MerkleRoot)
                    region_root.Signature = signature
            
            # Ulusal kökün imzasını kontrol et
            national_root_query = select(NationalRoot).where(
                (NationalRoot.Id == 0) & 
                ((NationalRoot.Signature == None) | (NationalRoot.MerkleRoot != None))
            )
            national_root = session.execute(national_root_query).scalar_one_or_none()
            
            if national_root and national_root.MerkleRoot:
                if national_root.Signature is None or not verify_signature(national_root.MerkleRoot, national_root.Signature):
                    signature = sign_data(national_root.MerkleRoot)
                    national_root.Signature = signature
            
            # Değişiklikleri kaydet
            session.commit()

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
        with get_db_session() as session:
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
                # Bölgeye ait blokları getir
                blocks_query = select(BlockModel).where(
                    BlockModel.Region == region
                ).order_by(BlockModel.BlockIndex.asc())
                
                blocks_db = session.execute(blocks_query).scalars().all()
                
                blocks = []
                for block in blocks_db:
                    block_dict = {
                        "index": block.BlockIndex,
                        "previous_hash": block.PreviousHash,
                        "timestamp": block.Timestamp,
                        "voter_id_hash": block.VoterID_Hashed,
                        "candidate": block.Candidate,
                        "hash": block.Hash,
                        "signature": block.Signature
                    }
                    blocks.append(block_dict)
                
                # Blok zincirinin tutarlılığını kontrol et
                ok = validate_chain(blocks, region)
                
                # İmzaları doğrula
                signatures_valid = True
                for block in blocks:
                    if block["signature"] is not None:
                        if not verify_signature(block["hash"], block["signature"]):
                            signatures_valid = False
                            ok = False
                            break
                    else:
                        # İmza yoksa, bu blok için imza oluştur ve kaydet
                        signature = sign_data(block["hash"])
                        block_update = update(BlockModel).where(
                            (BlockModel.Region == region) & 
                            (BlockModel.BlockIndex == block["index"])
                        ).values(Signature=signature)
                        
                        session.execute(block_update)
                        session.commit()

                leaf_hashes = [b["hash"] for b in blocks]
                live_root = calculate_merkle_root(leaf_hashes)

                region_data = {
                    "region": region,
                    "status": "OK" if ok else "BROKEN",
                    "blocks": blocks,
                    "live_root": live_root,
                    "signatures_valid": signatures_valid
                }
                
                structure["regions"].append(region_data)
                
                if ok:
                    live_region_roots.append(live_root)

            # 2️⃣ Canlı ulusal kök
            structure["live_merkle_root"] = calculate_merkle_root(live_region_roots)

            # 3️⃣ Stored (DB'deki) ulusal kökü ve imzasını çek
            national_root_query = select(NationalRoot).where(NationalRoot.Id == 0)
            national_root = session.execute(national_root_query).scalar_one_or_none()
            
            if national_root and national_root.MerkleRoot:
                structure["stored_merkle_root"] = national_root.MerkleRoot
                
                if national_root.Signature:
                    structure["stored_signature"] = national_root.Signature
                    structure["signature_valid"] = verify_signature(
                        national_root.MerkleRoot, 
                        national_root.Signature
                    )
                
                # 4️⃣ Match durumu
                structure["match"] = (
                    structure["stored_merkle_root"] == structure["live_merkle_root"]
                )

            return structure