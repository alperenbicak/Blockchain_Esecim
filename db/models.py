from sqlalchemy import Column, Integer, String, Float, Boolean, ForeignKey, Text, create_engine, UniqueConstraint, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import os

Base = declarative_base()

class Block(Base):
    __tablename__ = 'Blocks'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    Region = Column(String(50), nullable=False)
    BlockIndex = Column(Integer, nullable=False)
    PreviousHash = Column(String(64), nullable=False)
    Timestamp = Column(Integer, nullable=False)
    VoterID_Hashed = Column(String(64), nullable=False)
    Candidate = Column(String(50), nullable=False)
    Hash = Column(String(64), nullable=False)
    Signature = Column(Text, nullable=True)
    
    __table_args__ = (
        UniqueConstraint('Region', 'BlockIndex', name='uix_region_block_idx'),
        Index('idx_region', 'Region'),
    )

class Voter(Base):
    __tablename__ = 'Voters'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    TC = Column(String(11), nullable=False, unique=True)
    FullName = Column(String(50), nullable=False)
    Region = Column(String(50), nullable=False)
    HasVoted = Column(Boolean, default=False)
    
    __table_args__ = (
        Index('idx_tc', 'TC'),
        Index('idx_region', 'Region'),
    )

class RegionRoot(Base):
    __tablename__ = 'RegionRoots'
    
    Region = Column(String(50), primary_key=True)
    MerkleRoot = Column(String(64), nullable=False)
    UpdatedAt = Column(Integer, nullable=False)
    Signature = Column(Text, nullable=True)

class NationalRoot(Base):
    __tablename__ = 'NationalRoots'
    
    Id = Column(Integer, primary_key=True)
    MerkleRoot = Column(String(64), nullable=False)
    UpdatedAt = Column(Integer, nullable=False)  
    Signature = Column(Text, nullable=True) 