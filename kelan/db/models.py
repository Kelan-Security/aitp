"""SQLAlchemy async ORM models."""
import time, uuid
from sqlalchemy import Column, String, Float, Integer, Boolean, Text, Index
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return str(uuid.uuid4())

def _now() -> float:
    return time.time()


class Session(Base):
    __tablename__ = "sessions"
    id          = Column(String, primary_key=True, default=_uuid)
    entity_id   = Column(String, nullable=False, index=True)
    phase       = Column(Integer, default=0)
    verdict     = Column(String)
    confidence  = Column(Float, default=0.0)
    reason      = Column(Text)
    intent      = Column(String)
    anomalies   = Column(Text, default="{}")
    created_at  = Column(Float, default=_now)
    updated_at  = Column(Float, default=_now)


class Entity(Base):
    __tablename__ = "entities"
    id               = Column(String, primary_key=True, default=_uuid)
    name             = Column(String)
    public_key       = Column(Text)
    enrollment_count = Column(Integer, default=0)
    is_banned        = Column(Boolean, default=False)
    last_seen        = Column(Float)
    created_at       = Column(Float, default=_now)


class VerdictLog(Base):
    __tablename__ = "verdict_log"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    entity_id    = Column(String, nullable=False, index=True)
    session_id   = Column(String)
    verdict      = Column(String, nullable=False)
    confidence   = Column(Float, default=0.0)
    reason       = Column(Text)
    latency_ms   = Column(Float, default=0.0)
    anomaly_json = Column(Text, default="{}")
    created_at   = Column(Float, default=_now, index=True)

    __table_args__ = (
        Index("ix_verdict_log_time", "created_at"),
        Index("ix_verdict_log_entity", "entity_id"),
    )


class AnomalyLog(Base):
    __tablename__ = "anomaly_log"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    source       = Column(String, index=True)
    kind         = Column(String, nullable=False)
    severity     = Column(Float, nullable=False)
    details_json = Column(Text, default="{}")
    created_at   = Column(Float, default=_now, index=True)
