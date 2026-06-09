"""
Kelan Security — FastAPI Server
Full replacement for Rust aitp-server.
Endpoints: health, stats, verdicts, anomalies,
           enroll, handshake, xdp/drop, /ws/agent
"""
import time
import uuid
from contextlib import asynccontextmanager
from typing import Optional, Any, cast

import structlog
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST, REGISTRY
from starlette.responses import Response
# pyrefly: ignore [missing-import]
from pydantic import BaseModel

from ..config import get_settings
from ..ai.ollama_client import OllamaClient, Verdict
from ..ai.engine import HybridTrustEngine
from ..sentinel.detector import SentinelDetector
from ..enforcement.ebpf_bridge import EbpfBridge
from ..protocol.handshake import HandshakeManager, HandshakeError
from ..db.database import init_db, save_verdict, fetch_verdicts, fetch_anomalies

log = structlog.get_logger()
cfg = get_settings()

# ── Prometheus metrics 
if "kelan_requests_total" in REGISTRY._names_to_collectors:
    REQ_COUNT = cast(Counter, REGISTRY._names_to_collectors["kelan_requests_total"])
else:
    REQ_COUNT = Counter("kelan_requests_total", "Total requests", ["endpoint"])

if "kelan_api_verdicts_total" in REGISTRY._names_to_collectors:
    VERDICT_COUNT = cast(Counter, REGISTRY._names_to_collectors["kelan_api_verdicts_total"])
else:
    VERDICT_COUNT = Counter("kelan_api_verdicts_total", "Verdicts", ["verdict"])

if "kelan_ollama_latency_ms" in REGISTRY._names_to_collectors:
    OLLAMA_LAT = cast(Histogram, REGISTRY._names_to_collectors["kelan_ollama_latency_ms"])
else:
    OLLAMA_LAT = Histogram("kelan_ollama_latency_ms", "Ollama latency ms",
                           buckets=[50, 100, 200, 500, 1000, 2000, 5000])

# ── Global singletons 
ollama:    Optional[OllamaClient]     = None
engine:    Optional[HybridTrustEngine] = None
sentinel:  Optional[SentinelDetector] = None
ebpf:      Optional[EbpfBridge]       = None
handshake_mgr: Optional[HandshakeManager] = None

_ws_clients: set[WebSocket] = set()
_start_time = time.time()
_xdp_drops = 0

# In-memory ring buffers
_verdict_buf: list[dict] = []
_MAX_BUF = 1000


# ── Application lifespan 
@asynccontextmanager
async def lifespan(app: FastAPI):
    global ollama, engine, sentinel, ebpf, handshake_mgr

    log.info("kelan_starting", port=cfg.http_port, model=cfg.ollama_model)

    await init_db()

    ollama   = OllamaClient(cfg.ollama_endpoint, cfg.ollama_model,
                            cfg.ollama_timeout, cfg.ollama_temperature)
    sentinel = SentinelDetector()
    ebpf     = EbpfBridge()
    handshake_mgr = HandshakeManager(require_pq=cfg.require_pq)

    engine = HybridTrustEngine(ollama, cfg.cb_threshold, cfg.cb_recovery)
    engine.on_verdict(_on_verdict)

    await ebpf.start()

    ok = await ollama.ping()
    log.info("ollama_status", connected=ok, model=cfg.ollama_model,
             endpoint=cfg.ollama_endpoint)
    if ok:
        models = await ollama.list_models()
        log.info("models_available", models=models)
    else:
        log.warning("ollama_unreachable",
                    fix="run: ollama serve  (on macOS/Linux)")
    yield

    await ebpf.stop()
    await ollama.close()
    log.info("kelan_stopped")


# ── App 
app = FastAPI(
    title="Kelan Security Intelligence",
    version="4.0.0-python",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                  allow_methods=["*"], allow_headers=["*"])

from prometheus_fastapi_instrumentator import Instrumentator
Instrumentator().instrument(app).expose(app)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


# ── Helpers 
async def _on_verdict(payload: dict):
    """Called on every verdict — store + broadcast."""
    _verdict_buf.append(payload)
    if len(_verdict_buf) > _MAX_BUF:
        _verdict_buf.pop(0)
    # Persist to DB
    await save_verdict(
        payload.get("session_id", ""),
        payload.get("entity_id", ""),
        payload.get("verdict", ""),
        payload.get("confidence", 0.0),
        payload.get("reason", ""),
        payload.get("latency_ms", 0.0),
        payload.get("anomalies", {}),
    )
    # eBPF enforcement
    if ebpf:
        if payload.get("action") == "REVOKE":
            await ebpf.revoke(payload.get("entity_id", ""))
        elif payload.get("action") == "PERMIT":
            await ebpf.permit(
                payload.get("session_id", ""),
                payload.get("entity_id", ""),
            )
    # WebSocket broadcast
    dead = set()
    for ws in _ws_clients:
        try:
            await ws.send_json(payload)
        except Exception:
            dead.add(ws)
    _ws_clients.difference_update(dead)


# ── Request Models 
class EnrollReq(BaseModel):
    entity_id:          str
    intent:             str   = "INIT_ENROL"
    name:               str   = ""
    version:            Any   = 1
    x25519_public_key:  Optional[str] = None
    kem_public_key:     Optional[str] = None
    signature:          Optional[str] = None
    nonce:              Optional[str] = None
    metadata:           Optional[dict] = None


class HandshakeReq(BaseModel):
    session_id:        Optional[str] = None
    entity_id:         str
    phase:             int   = 1
    intent:            str   = "INIT_SESSION"
    nonce_c:           Optional[str] = None
    x25519_public_key: Optional[str] = None
    kem_ciphertext:    Optional[str] = None
    kem_public_key:    Optional[str] = None
    signature:         Optional[str] = None
    ed25519_public_key: Optional[str] = None


class TrustEvalReq(BaseModel):
    entity_id:  str
    intent:     str
    session_id: str
    anomalies:  Optional[Any] = None


class XdpDropReport(BaseModel):
    count:     int
    interface: str = "eth0"
    reason:    Optional[str] = None


# ── Routes

@app.get("/")
@app.get("/dashboard")
async def get_dashboard():
    return FileResponse("static/index.html")


@app.get("/api/health")
async def health():
    REQ_COUNT.labels("health").inc()
    ok = await ollama.ping() if ollama else False
    return {
        "status":           "healthy",
        "version":          "4.0.0-python",
        "engine":           "fastapi+ollama",
        "ollama_connected": ok,
        "ollama_model":     cfg.ollama_model,
        "ebpf_mode":        ebpf.mode if ebpf else "unknown",
        "uptime_s":         int(time.time() - _start_time),
    }


@app.get("/api/stats")
async def stats():
    REQ_COUNT.labels("stats").inc()
    eng = engine.stats if engine else {}
    return {
        "requests":         eng.get("total", 0),
        "verdicts_total":   eng.get("total", 0),
        "allow":            eng.get("allow", 0),
        "deny":             eng.get("deny", 0),
        "monitor":          eng.get("monitor", 0),
        "fallbacks":        eng.get("fallbacks", 0),
        "circuit_state":    eng.get("circuit", "unknown"),
        "cache":            eng.get("cache", {}),
        "ebpf_mode":        ebpf.mode if ebpf else "unknown",
        "packets_dropped":  _xdp_drops,
        "ollama_model":     cfg.ollama_model,
        "uptime_s":         int(time.time() - _start_time),
    }


@app.get("/api/verdicts")
async def verdicts(limit: int = 100):
    REQ_COUNT.labels("verdicts").inc()
    return {"verdicts": await fetch_verdicts(limit=limit)}


@app.get("/api/anomalies")
async def anomalies(limit: int = 50):
    REQ_COUNT.labels("anomalies").inc()
    return {"anomalies": await fetch_anomalies(limit=limit)}


@app.get("/api/sentinel/events")
async def sentinel_events(limit: int = 20):
    REQ_COUNT.labels("sentinel_events").inc()
    events = sentinel.recent(n=limit) if sentinel else []
    return {"events": events}


@app.post("/api/enroll")
async def enroll(req: EnrollReq, request: Request):
    REQ_COUNT.labels("enroll").inc()
    
    # signature validation
    if req.signature is not None:
        from ..protocol.crypto import is_valid_ed25519_sig
        if not is_valid_ed25519_sig(req.signature):
            raise HTTPException(
                status_code=403,
                detail={"error": "invalid_signature", "reason": "Ed25519 signature rejected"},
            )
            
    # post-quantum enforcement
    if cfg.require_pq and req.kem_public_key is None:
        raise HTTPException(
            status_code=403,
            detail={"error": "pq_required", "reason": "ML-KEM-768 public key required"},
        )
        
    source_ip = request.client.host if request.client else ""
    
    # Sentinel analysis
    anomalies = sentinel.analyze(req.entity_id, req.intent, source_ip) if sentinel else {}
    
    session_id = str(uuid.uuid4())
    session_ctx = {
        "session_id": session_id,
        "entity_id": req.entity_id,
        "intent": req.intent,
        "source_ip": source_ip,
        "anomalies": anomalies,
        "name": req.name,
        "version": req.version,
        "has_kem_key": req.kem_public_key is not None,
        "has_signature": req.signature is not None,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    
    if not engine:
        raise HTTPException(status_code=503, detail="Engine not initialized")
    verdict = await engine.evaluate(session_ctx)
    VERDICT_COUNT.labels(verdict.verdict.value).inc()
    
    if verdict.verdict == Verdict.DENY:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "enrollment_denied",
                "reason": verdict.reason,
                "confidence": verdict.confidence,
            },
        )
        
    permit_token = str(uuid.uuid4())
    
    return {
        "session_id": session_id,
        "entity_id": req.entity_id,
        "verdict": verdict.verdict.value,
        "confidence": verdict.confidence,
        "reason": verdict.reason,
        "permit_token": permit_token,
        "action": "PERMIT" if verdict.verdict == Verdict.ALLOW else "MONITOR",
    }


@app.post("/api/handshake")
async def handshake(req: HandshakeReq, request: Request):
    REQ_COUNT.labels("handshake").inc()
    
    if not handshake_mgr:
        raise HTTPException(status_code=503, detail="Handshake manager not initialized")
        
    # Enforce PQ checks
    if cfg.require_pq:
        if req.phase == 1 and not req.kem_public_key:
            raise HTTPException(status_code=403, detail={"error": "pq_required", "reason": "ML-KEM public key required (require_pq=true)"})
        if req.phase > 1 and not req.kem_ciphertext:
            raise HTTPException(status_code=403, detail={"error": "pq_downgrade_denied", "reason": "ML-KEM-768 ciphertext required — classical-only sessions rejected"})
        
    try:
        if req.phase == 1:
            nonce_c = req.nonce_c or uuid.uuid4().hex
            source_ip = request.client.host if request.client else ""
            anomalies = sentinel.analyze(req.entity_id, req.intent, source_ip) if sentinel else {}
            if anomalies:
                from ..db.database import save_anomaly
                await save_anomaly(req.entity_id, "handshake_anomaly", 0.7, anomalies)
            
            ps = handshake_mgr.receive_syn(
                entity_id=req.entity_id,
                intent=req.intent,
                nonce_c=nonce_c,
                x25519_pk_c_hex=req.x25519_public_key,
                kem_pk_c_hex=req.kem_public_key,
            )
            
            return {
                "session_id": ps.session_id,
                "phase": 2,
                "kem_ciphertext": ps.kem_ct_s.hex() if ps.kem_ct_s else None,
                "x25519_public_key": ps.x25519_pk_s.hex(),
            }
            
        elif req.phase == 3:
            if not req.session_id:
                raise HTTPException(status_code=400, detail="session_id required for Phase 3")
            if not req.kem_ciphertext or not req.signature or not req.ed25519_public_key:
                raise HTTPException(status_code=400, detail="kem_ciphertext, signature, and ed25519_public_key required for Phase 3")
                
            ps = handshake_mgr.receive_kem_complete(
                session_id=req.session_id,
                kem_ct_c_hex=req.kem_ciphertext,
                signature_hex=req.signature,
                ed25519_pk_hex=req.ed25519_public_key,
            )
            
            source_ip = request.client.host if request.client else ""
            anomalies = sentinel.analyze(ps.entity_id, ps.intent, source_ip) if sentinel else {}
            
            session_ctx = {
                "session_id": ps.session_id,
                "entity_id": ps.entity_id,
                "intent": ps.intent,
                "source_ip": source_ip,
                "anomalies": anomalies,
                "created_at": ps.created_at,
                "pq_enabled": True,
            }
            
            if not engine:
                raise HTTPException(status_code=503, detail="Engine not initialized")
            verdict = await engine.evaluate(session_ctx)
            VERDICT_COUNT.labels(verdict.verdict.value).inc()
            
            if verdict.verdict == Verdict.DENY:
                if source_ip and ebpf:
                    await ebpf.revoke(ps.entity_id)
                raise HTTPException(status_code=403, detail={
                    "error": "handshake_denied",
                    "reason": verdict.reason,
                    "confidence": verdict.confidence,
                })
                
            permit_token = handshake_mgr.complete_session(ps.session_id)
            
            return {
                "session_id": ps.session_id,
                "phase": 5,
                "verdict": verdict.verdict.value,
                "confidence": verdict.confidence,
                "reason": verdict.reason,
                "permit_token": permit_token,
                "action": "PERMIT" if verdict.verdict == Verdict.ALLOW else "MONITOR",
            }
            
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported phase: {req.phase}")
            
    except HandshakeError as e:
        raise HTTPException(status_code=403, detail={"error": "handshake_failed", "reason": str(e)})
 
 
@app.post("/api/trust/evaluate")
async def trust_evaluate(req: TrustEvalReq, request: Request):
    REQ_COUNT.labels("trust_evaluate").inc()
    
    anomalies_data = req.anomalies
    if isinstance(anomalies_data, list):
        anomalies_data = {}
        
    source_ip = request.client.host if request.client else ""
    session_ctx = {
        "session_id": req.session_id,
        "entity_id": req.entity_id,
        "intent": req.intent,
        "source_ip": source_ip,
        "anomalies": anomalies_data,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    
    if not engine:
        raise HTTPException(status_code=503, detail="Engine not initialized")
    verdict = await engine.evaluate(session_ctx)
    return verdict.to_dict()


@app.post("/api/xdp/drop")
async def record_xdp_drop(report: XdpDropReport):
    global _xdp_drops
    _xdp_drops += report.count
    log.info("xdp_drops_reported", count=report.count, iface=report.interface,
             total=_xdp_drops)
    return {"ok": True, "total_xdp_drops": _xdp_drops}


@app.get("/metrics")
async def get_metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


# ── WebSocket: Agentic Sync

@app.websocket("/ws/agent")
async def ws_agent(websocket: WebSocket):
    await websocket.accept()
    _ws_clients.add(websocket)
    client_info = f"{websocket.client.host}:{websocket.client.port}" if websocket.client else "unknown"
    log.info("agent_connected", client=client_info, total=len(_ws_clients))

    await websocket.send_json({
        "type": "connected",
        "server_version": "4.0.0-python",
        "model": cfg.ollama_model,
        "require_pq": cfg.require_pq,
    })

    try:
        while True:
            data = await websocket.receive_json()
            msg_type = data.get("type", "unknown")
            log.debug("agent_message", type=msg_type, client=client_info)
            await websocket.send_json({"type": "ack", "received": msg_type})
    except WebSocketDisconnect:
        _ws_clients.discard(websocket)
        log.info("agent_disconnected", client=client_info, remaining=len(_ws_clients))
    except Exception as exc:
        _ws_clients.discard(websocket)
        log.error("agent_ws_error", error=str(exc), client=client_info)
