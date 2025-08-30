from datetime import datetime
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    auth_salt_b64 = Column(String(64), nullable=False)   # salt for SHA-256 login hash
    auth_hash_b64 = Column(String(64), nullable=False)   # base64 of SHA-256 digest
    kdf_salt_b64  = Column(String(64), nullable=False)   # salt for PBKDF2
    kdf_iters     = Column(Integer, default=310000)      # PBKDF2 iterations
    created_at    = Column(DateTime, default=datetime.utcnow)

    records = relationship("PIIRecord", back_populates="owner", cascade="all, delete-orphan")

class PIIRecord(Base):
    __tablename__ = "pii_records"
    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    field_name = Column(String(64), nullable=False)
    nonce_b64 = Column(String(64), nullable=False)
    ciphertext_b64 = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="records")
