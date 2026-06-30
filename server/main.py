"""
KHAOS FRAMEWORK Team Server — FastAPI
"""
import asyncio
import logging
import os
import shutil
import sys
from contextlib import asynccontextmanager

from fastapi import WebSocket, WebSocketDisconnect

import yaml
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models.agent import Base
from services.agent_manager import manager as agent_manager
from services.channel_reader import ChannelReader
from services.dns_server import start_dns_server
from routers import auth, beacon, agents, tasks, build, stage, creds
from routers.auth import verify_token_str
from services.ws_manager import ws_manager

# ---- Logging ----
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("main")

# ---- PyInstaller-aware paths ----
def _data_dir() -> str:
    """Répertoire persistant pour config.yaml et khaos.db."""
    if getattr(sys, 'frozen', False):
        if os.name == 'nt':  # Windows
            base = os.environ.get('APPDATA', os.path.expanduser('~'))
        else:                 # Linux / macOS
            base = os.environ.get('XDG_DATA_HOME', os.path.join(os.path.expanduser('~'), '.local', 'share'))
        d = os.path.join(base, 'KHAOS')
        os.makedirs(d, exist_ok=True)
        return d
    return os.path.dirname(os.path.abspath(__file__))

_DATA_DIR = _data_dir()

# ---- Config ----
CONFIG_PATH = os.path.join(_DATA_DIR, "config.yaml")
# Premier démarrage (bundle) : copie le config.yaml bundlé
if getattr(sys, 'frozen', False) and not os.path.exists(CONFIG_PATH):
    _src = os.path.join(sys._MEIPASS, "config.yaml")
    if os.path.exists(_src):
        shutil.copy2(_src, CONFIG_PATH)

def load_config() -> dict:
    try:
        with open(CONFIG_PATH) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}

config = load_config()

# Inject secrets from env if config values are placeholders
_channels = config.setdefault("channels", {})
_github   = _channels.setdefault("github", {})
if len(_github.get("token", "")) < 20:
    _github["token"]    = os.environ.get("KHAOS_GITHUB_TOKEN", "")
    _github["gist_cmd"] = os.environ.get("KHAOS_GIST_CMD",    "")
    _github["gist_out"] = os.environ.get("KHAOS_GIST_OUT",    "")

# Propagate JWT secret
_server = config.get("server", {})
jwt_secret = _server.get("jwt_secret", "/H7GCJcEI3tlCI98tnOrtHUFYOL2VnNVcM2O/amWy7s=")
if jwt_secret == "/H7GCJcEI3tlCI98tnOrtHUFYOL2VnNVcM2O/amWy7s=":
    jwt_secret = os.environ.get("KHAOS_JWT_SECRET", jwt_secret)
os.environ.setdefault("KHAOS_JWT_SECRET", jwt_secret)

# ---- Database ----
DB_PATH    = os.path.join(_DATA_DIR, "khaos.db")
# Premier démarrage (bundle) : copie le khaos.db bundlé (avec l'user operator pré-créé)
if getattr(sys, 'frozen', False) and not os.path.exists(DB_PATH):
    _src_db = os.path.join(sys._MEIPASS, "khaos.db")
    if os.path.exists(_src_db):
        shutil.copy2(_src_db, DB_PATH)
engine     = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

Base.metadata.create_all(bind=engine)

# Import Base from all models so tables are created
import models.task  # noqa: F401
import models.log   # noqa: F401
import models.user  # noqa: F401
import models.cred  # noqa: F401
Base.metadata.create_all(bind=engine)

with engine.connect() as _conn:
    _cols = [r[1] for r in _conn.execute(__import__('sqlalchemy').text("PRAGMA table_info(agents)")).fetchall()]
    if "parent_id" not in _cols:
        _conn.execute(__import__('sqlalchemy').text("ALTER TABLE agents ADD COLUMN parent_id TEXT DEFAULT ''"))
        _conn.commit()
    if "ip" not in _cols:
        _conn.execute(__import__('sqlalchemy').text("ALTER TABLE agents ADD COLUMN ip TEXT DEFAULT ''"))
        _conn.commit()
    if "auto_enum_done" not in _cols:
        _conn.execute(__import__('sqlalchemy').text("ALTER TABLE agents ADD COLUMN auto_enum_done INTEGER DEFAULT 0"))
        _conn.commit()


def _seed_default_admin() -> None:
    from models.user import User
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            uname = os.environ.get("KHAOS_OPERATOR_USER", "operator")
            upass = os.environ.get("KHAOS_OPERATOR_PASS", "changeme")
            db.add(User(
                username=uname,
                password_hash=User.hash_password(upass),
                role="admin",
                is_active=True,
            ))
            db.commit()
            logger.info("Seeded default admin: %s", uname)
    finally:
        db.close()


_seed_default_admin()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Expose SessionLocal so database.get_db can use it
import database as _db_module
_db_module.SessionLocal = SessionLocal

# ---- Channel reader ----
reader = ChannelReader(config, SessionLocal)

# ---- App lifecycle ----
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load existing sessions from DB
    db = SessionLocal()
    try:
        agent_manager.load_from_db(db)
    finally:
        db.close()

    poll_task = asyncio.create_task(reader.run())

    beacon_interval = config.get("agent", {}).get("interval", 30)

    async def _heartbeat():
        from models.agent import Agent as _Agent
        from models.log import Log as _Log
        from datetime import datetime, timedelta
        timeout = max(beacon_interval * 4, 120)
        while True:
            await asyncio.sleep(60)
            try:
                db = SessionLocal()
                cutoff = datetime.utcnow() - timedelta(seconds=timeout)
                stale = db.query(_Agent).filter(
                    _Agent.is_active == True,  # noqa: E712
                    _Agent.last_seen < cutoff,
                ).all()
                for a in stale:
                    a.is_active = False
                    db.add(_Log(agent_id=a.agent_id, event="agent_lost",
                                detail=f"no beacon for >{timeout}s"))
                if stale:
                    db.commit()
                    for a in stale:
                        await ws_manager.broadcast({
                            "type": "agent_lost",
                            "agent_id": a.agent_id,
                        })
                    logger.info("heartbeat: marked %d agent(s) lost", len(stale))
                db.close()
            except Exception as _e:
                logger.warning("heartbeat error: %s", _e)

    heartbeat_task = asyncio.create_task(_heartbeat())

    # Start authoritative DNS server if domain is configured
    dns_transport = None
    doh_cfg = config.get("channels", {}).get("doh", {})
    doh_domain = doh_cfg.get("domain", "")
    if doh_domain:
        try:
            dns_transport = await start_dns_server(doh_domain, SessionLocal)
            logger.info("DNS server started for %s", doh_domain)
        except PermissionError:
            logger.warning(
                "DNS server: port 53 requires root or cap_net_bind_service — "
                "run: sudo setcap cap_net_bind_service+ep $(which python3)"
            )
        except Exception as e:
            logger.warning("DNS server failed to start: %s", e)

    logger.info("KHAOS FRAMEWORK Team Server started")
    yield

    reader.stop()
    for t in (poll_task, heartbeat_task):
        t.cancel()
        try:
            await t
        except asyncio.CancelledError:
            pass
    if dns_transport:
        dns_transport.close()

# ---- FastAPI app ----
app = FastAPI(
    title="KHAOS FRAMEWORK Team Server",
    version="1.0.0",
    docs_url=None,  
    redoc_url=None,
    lifespan=lifespan,
)

_cors_origins = config.get("server", {}).get("cors_origins", ["*"])
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(auth.router)
app.include_router(beacon.router)
app.include_router(tasks.router)   # must come before agents.router: /agents/{id}/task etc. must not be shadowed by agents /{agent_id}
app.include_router(agents.router)
app.include_router(build.router)
app.include_router(stage.router)
app.include_router(creds.router)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = ""):
    try:
        verify_token_str(token)
    except ValueError:
        await websocket.close(code=1008)
        return

    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    # En mode frozen sans console, sys.stdout/stderr sont None
    # → redirige vers un fichier log dans %APPDATA%\KHAOS\
    if getattr(sys, 'frozen', False):
        _log_path = os.path.join(_DATA_DIR, "server.log")
        _log_file = open(_log_path, "a", buffering=1)
        sys.stdout = _log_file
        sys.stderr = _log_file
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning", log_config=None)
