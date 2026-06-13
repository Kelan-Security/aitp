"""Async database engine and session factory."""
import json
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from .models import Base, VerdictLog, AnomalyLog
from ..config import get_settings

_engine = None
_session_factory = None


async def init_db():
    global _engine, _session_factory
    cfg = get_settings()
    _engine = create_async_engine(
        cfg.database_url,
        echo=cfg.debug,
        pool_pre_ping=True,
    )
    _session_factory = async_sessionmaker(
        _engine, expire_on_commit=False, class_=AsyncSession
    )
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        from sqlalchemy import text
        await conn.execute(text("CREATE VIEW IF NOT EXISTS verdicts AS SELECT * FROM verdict_log;"))
        await conn.execute(text("CREATE VIEW IF NOT EXISTS anomalies AS SELECT * FROM anomaly_log;"))
        await conn.execute(text("CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT, timestamp REAL);"))


def get_session() -> AsyncSession:
    assert _session_factory is not None, (
        "Database not initialised. "
        "Call await init_db() first."
    )
    return _session_factory()


async def save_verdict(session_id: str, entity_id: str,
                       verdict: str, confidence: float,
                       reason: str, latency_ms: float,
                       anomalies: dict):
    async with get_session() as s:
        s.add(VerdictLog(
            session_id   = session_id,
            entity_id    = entity_id,
            verdict      = verdict,
            confidence   = confidence,
            reason       = reason,
            latency_ms   = latency_ms,
            anomaly_json = json.dumps(anomalies),
        ))
        await s.commit()


async def save_anomaly(source: str, kind: str,
                       severity: float, details: dict):
    async with get_session() as s:
        s.add(AnomalyLog(
            source       = source,
            kind         = kind,
            severity     = severity,
            details_json = json.dumps(details),
        ))
        await s.commit()


async def fetch_verdicts(limit: int = 100) -> list[dict]:
    from sqlalchemy import select, desc
    async with get_session() as s:
        rows = await s.execute(
            select(VerdictLog)
            .order_by(desc(VerdictLog.created_at))
            .limit(limit)
        )
        return [
            {
                "id":          r.id,
                "entity_id":   r.entity_id,
                "session_id":  r.session_id,
                "verdict":     r.verdict,
                "confidence":  r.confidence,
                "reason":      r.reason,
                "latency_ms":  r.latency_ms,
                "created_at":  r.created_at,
            }
            for r in rows.scalars().all()
        ]


async def fetch_anomalies(limit: int = 50) -> list[dict]:
    from sqlalchemy import select, desc
    async with get_session() as s:
        rows = await s.execute(
            select(AnomalyLog)
            .order_by(desc(AnomalyLog.created_at))
            .limit(limit)
        )
        return [
            {
                "id":        r.id,
                "source":    r.source,
                "kind":      r.kind,
                "severity":  r.severity,
                "details":   json.loads(str(r.details_json or "{}")),
                "created_at":r.created_at,
            }
            for r in rows.scalars().all()
        ]
