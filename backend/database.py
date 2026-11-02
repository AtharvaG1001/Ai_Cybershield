"""
Database models and session management for AI CyberShield.
"""
import os
import uuid
from datetime import datetime
from sqlalchemy import create_engine, Column, String, Float, Integer, DateTime, Text, ForeignKey, Boolean
from sqlalchemy.orm import DeclarativeBase, sessionmaker, relationship

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "data", "cybershield.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_type = Column(String, nullable=False)          # "url" or "email"
    input_value = Column(Text, nullable=False)           # URL or email subject
    risk_category = Column(String, nullable=False)       # LOW/MEDIUM/HIGH/CRITICAL/INCONCLUSIVE
    risk_score = Column(Float, nullable=False)
    verdict = Column(String, nullable=False)
    ml_prediction = Column(String, nullable=True)
    ml_confidence = Column(Float, nullable=True)
    model_version = Column(String, nullable=True)
    scan_status = Column(String, nullable=False, default="SUCCESS")
    created_at = Column(DateTime, default=datetime.utcnow)

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    finding_type = Column(String, nullable=False)   # "ml", "rule", "dns", "ssl", "whois", "email"
    severity = Column(String, nullable=False)        # LOW/MEDIUM/HIGH/CRITICAL
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    evidence = Column(Text, nullable=True)
    evidence_source = Column(String, nullable=True)

    scan = relationship("Scan", back_populates="findings")


class ModelEvaluation(Base):
    __tablename__ = "model_evaluations"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    model_version = Column(String, nullable=False)
    dataset_id = Column(String, nullable=False)
    evaluated_at = Column(DateTime, default=datetime.utcnow)
    precision = Column(Float, nullable=True)
    recall = Column(Float, nullable=True)
    f1_score = Column(Float, nullable=True)
    roc_auc = Column(Float, nullable=True)
    accuracy = Column(Float, nullable=True)
    false_positive_rate = Column(Float, nullable=True)
    false_negative_rate = Column(Float, nullable=True)
    dataset_size = Column(Integer, nullable=True)
    phishing_count = Column(Integer, nullable=True)
    legitimate_count = Column(Integer, nullable=True)
    confusion_matrix = Column(Text, nullable=True)  # JSON string


def get_db():
    """Dependency for FastAPI routes."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables():
    """Create all tables if they don't exist."""
    Base.metadata.create_all(bind=engine)
