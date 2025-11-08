# db/models.py
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Text,
    DateTime,
    ForeignKey,
    JSON,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
from scanner.utils import DB_PATH

Base = declarative_base()


# A "run" is one execution of run_scan.py
class Run(Base):
    __tablename__ = "runs"
    id = Column(Integer, primary_key=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    status = Column(String, default="running")
    findings = relationship("Finding", back_populates="run")


# Each finding = one misconfiguration detected
class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True)
    run_id = Column(Integer, ForeignKey("runs.id"))
    rule_id = Column(String)
    service = Column(String)
    resource_id = Column(String)
    title = Column(String)
    severity = Column(String)
    evidence = Column(Text)  # store as JSON string
    remediation = Column(Text)  # store as JSON string
    run = relationship("Run", back_populates="findings")


# Setup engine & session
engine = create_engine(
    f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(bind=engine)


def init_db():
    Base.metadata.create_all(engine)
