import { useState, useRef, useEffect, useCallback, useMemo } from "react";
import useAgentStore from "./store/useAgentStore";
import Dashboard from "./components/Dashboard";
import Terminal from "./components/Terminal";
import Tasks from "./components/Tasks";
import Logs from "./components/Logs";
import FileManager from "./components/FileManager";
import CommandPalette from "./components/CommandPalette";
import DetailPanel from "./components/DetailPanel";
import ToastContainer from "./components/Toast";
import Users from "./components/Users";
import Build from "./components/Build";
import Creds from "./components/Creds";
import Screenshots from "./components/Screenshots";
import Loot from "./components/Loot";
import NetworkMap from "./components/NetworkMap";

function decodeJwtPayload(token) {
  try {
    return JSON.parse(atob(token.split(".")[1]));
  } catch {
    return {};
  }
}

/* ─────────────────────────── Global CSS ─────────────────────────── */
const GLOBAL_CSS = `
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html, body, #root { height: 100%; overflow: hidden; }
body {
  background: #0a0a0a;
  color: #dde1e8;
  font-family: 'Share Tech Mono', 'Consolas', monospace;
  font-size: 13px;
  -webkit-font-smoothing: antialiased;
}
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: #0a0a0a; }
::-webkit-scrollbar-thumb { background: #1e1e1e; border-radius: 2px; }
::-webkit-scrollbar-thumb:hover { background: #2a2a2a; }

@keyframes pulse     { 0%,100%{opacity:1}        50%{opacity:.3} }
@keyframes blink     { 0%,100%{opacity:1}        50%{opacity:0} }
@keyframes dot-pulse { 0%,100%{box-shadow:0 0 4px currentColor} 50%{box-shadow:0 0 12px currentColor} }

/* ── Layout helpers ── */
.resize-handle {
  width: 4px; flex-shrink: 0; cursor: col-resize;
  background: transparent; transition: background .15s; z-index: 10;
}
.resize-handle:hover, .resize-handle.dragging { background: #ff3131; }

/* ── Agent rows ── */
.agent-row { cursor: pointer; transition: background .1s; }
.agent-row:hover { background: #130a0a !important; }
.agent-row.selected { background: #1c0808 !important; }

/* ── Tab buttons ── */
.tab-btn {
  transition: color .1s, border-color .1s;
  border-bottom: 2px solid transparent !important;
}
.tab-btn:hover { color: #dde1e8 !important; }
.tab-btn.active { color: #ff3131 !important; border-bottom-color: #ff3131 !important; }

/* ── Console tabs ── */
.c-tab {
  display: flex; align-items: center; gap: 6px;
  padding: 0 14px; height: 100%; cursor: pointer;
  border-right: 1px solid #1e1e1e;
  font-size: 11px; color: #888888; letter-spacing: 0.5px;
  transition: color .1s, background .1s;
  white-space: nowrap; max-width: 180px;
  position: relative; flex-shrink: 0;
}
.c-tab:hover { background: #130a0a; color: #dde1e8; }
.c-tab.active { color: #ff3131; background: #0a0a0a; border-bottom: 2px solid #ff3131; }
.c-tab .c-close {
  opacity: 0; transition: opacity .1s;
  background: transparent; border: none; color: #888888;
  cursor: pointer; font-size: 12px; padding: 0 0 0 2px; line-height: 1;
}
.c-tab:hover .c-close { opacity: 1; }
.c-tab .c-close:hover { color: #f85149; }

/* ── Hover rows (tasks / logs) ── */
.hover-row { transition: background .08s; cursor: default; }
.hover-row:hover { background: #111111 !important; }
.hover-row.clickable { cursor: pointer; }

/* ── Buttons ── */
.k-btn { transition: all .12s; cursor: pointer; }
.k-btn:hover:not(:disabled) { filter: brightness(1.15); }
.k-btn-outline:hover:not(:disabled) { background: #ff3131 !important; color: #0a0a0a !important; }
.k-btn-ghost:hover { background: #1e1e1e !important; color: #dde1e8 !important; }

/* ── Context menu ── */
.ctx-menu { user-select: none; }
.ctx-item {
  cursor: pointer; padding: 8px 16px; font-size: 11px;
  color: #888888; letter-spacing: 1px; transition: background .08s, color .08s;
}
.ctx-item:hover { background: #1e1e1e; color: #dde1e8; }
.ctx-item.sep { border-top: 1px solid #1e1e1e; margin-top: 4px; padding-top: 11px; }
.ctx-item.danger { color: #f85149; }
.ctx-item.danger:hover { background: #2d1818; }

/* ── Status badges ── */
.badge {
  display: inline-flex; align-items: center; gap: 3px;
  padding: 2px 7px; font-size: 10px; letter-spacing: 1.5px; font-weight: 700;
}
.badge-green  { background: #0d1f14; color: #3fb950; border: 1px solid #1a3d24; }
.badge-red    { background: #2a1414; color: #f85149; border: 1px solid #5c2020; }
.badge-yellow { background: #231a0a; color: #d29922; border: 1px solid #4a3412; }
.badge-gray   { background: #111111; color: #888888; border: 1px solid #1e1e1e; }

/* ── Inputs ── */
.k-input {
  background: #0a0a0a; border: 1px solid #1e1e1e; color: #dde1e8;
  font-family: inherit; font-size: 12px; padding: 7px 10px; outline: none;
  transition: border-color .1s; width: 100%;
}
.k-input:focus { border-color: #ff313166; }
.k-input::placeholder { color: #888888; }

/* ── Separator ── */
.k-sep { border: none; border-top: 1px solid #1e1e1e; margin: 8px 0; }

/* ── Scrollable area ── */
.scroll { overflow-y: auto; overflow-x: hidden; }
`;

/* ─────────────────────────── Logo ─────────────────────────── */
function Logo({ size = 16 }) {
  return (
    <span
      style={{
        fontSize: size,
        fontWeight: 700,
        display: "inline-block",
        letterSpacing: 1,
        userSelect: "none",
      }}
    >
      <span style={{ color: "#ff3131" }}>KHA</span>
      <span style={{ color: "#ff3131", opacity: 0.7 }}>Ø</span>
      <span style={{ color: "#ff3131" }}>S</span>
      <span style={{ color: "#888888", margin: "0 5px", fontSize: size * 0.7 }}>
      
      </span>
      <span style={{ color: "#dde1e8" }}>C2</span>
    </span>
  );
}

/* ─────────────────────────── Login ─────────────────────────── */
function Login() {
  const { login, authError } = useAgentStore();
  const [u, setU] = useState("");
  const [p, setP] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setLoading(true);
    await login(u, p);
    setLoading(false);
  };

  return (
    <div style={l.wrap}>
      <div style={l.box}>
        <div style={{ textAlign: "center", marginBottom: 28 }}>
          <Logo size={28} />
        </div>
        <div style={l.divider} />
        <form
          onSubmit={submit}
          style={{ display: "flex", flexDirection: "column", gap: 10 }}
        >
          <div style={l.field}>
            <span style={l.pfx}>OPERATOR</span>
            <input
              className="k-input"
              type="text"
              placeholder="username"
              value={u}
              onChange={(e) => setU(e.target.value)}
              autoFocus
              autoComplete="off"
              style={{
                borderLeft: "none",
                borderTop: "none",
                borderRight: "none",
              }}
            />
          </div>
          <div style={l.field}>
            <span style={l.pfx}>PASSWORD</span>
            <input
              className="k-input"
              type="password"
              placeholder="••••••••"
              value={p}
              onChange={(e) => setP(e.target.value)}
              style={{
                borderLeft: "none",
                borderTop: "none",
                borderRight: "none",
              }}
            />
          </div>
          {authError && (
            <p
              style={{
                color: "#f85149",
                fontSize: 10,
                textAlign: "center",
                letterSpacing: 2,
              }}
            >
              // {authError.toUpperCase()} //
            </p>
          )}
          <button
            className="k-btn k-btn-outline"
            type="submit"
            disabled={loading}
            style={{
              marginTop: 8,
              padding: "11px 0",
              background: "transparent",
              border: "1px solid #ff3131",
              color: "#ff3131",
              fontSize: 11,
              fontFamily: "inherit",
              letterSpacing: 3,
            }}
          >
            {loading ? "AUTHENTICATING..." : "CONNECT"}
          </button>
        </form>
      </div>
    </div>
  );
}

const l = {
  wrap: {
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    minHeight: "100vh",
    background: "#0a0a0a",
    backgroundImage:
      "radial-gradient(ellipse at center, #180606 0%, #0a0a0a 60%)",
  },
  box: {
    width: 360,
    background: "#111111",
    border: "1px solid #888888",
    boxShadow: "0 0 60px rgba(255,49,49,.10)",
    padding: "40px 32px",
  },
  divider: {
    height: 1,
    background: "linear-gradient(90deg,transparent,#ff3131,transparent)",
    marginBottom: 24,
  },
  field: {
    display: "flex",
    alignItems: "center",
    borderBottom: "1px solid #1e1e1e",
  },
  pfx: {
    fontSize: 11,
    color: "#888888",
    letterSpacing: 2,
    minWidth: 80,
    flexShrink: 0,
    padding: "0 8px",
  },
};

/* ─────────────────────────── Console tab button ─────────────────────────── */
function ConsoleTab({ agent, active, onSelect, onClose }) {
  const { sendingTask, lastAckedTask } = useAgentStore();
  // A task is running for this agent if sendingTask is true and lastAckedTask doesn't belong to this agent yet
  const isRunning =
    sendingTask &&
    (!lastAckedTask || lastAckedTask.agent_id === agent.agent_id);
  return (
    <div className={`c-tab${active ? " active" : ""}`} onClick={onSelect}>
      <span
        style={{ color: agent.is_active ? "#3fb950" : "#888888", fontSize: 9 }}
      >
        ●
      </span>
      <span
        style={{ overflow: "hidden", textOverflow: "ellipsis", maxWidth: 100 }}
      >
        {agent.agent_id}
      </span>
      {isRunning && (
        <span
          style={{
            fontSize: 9,
            color: "#f59e0b",
            letterSpacing: 1,
            animation: "pulse 1s infinite",
          }}
        >
          RUN
        </span>
      )}
      <button
        className="c-close"
        onClick={(e) => {
          e.stopPropagation();
          onClose();
        }}
        title="close"
      >
        ✕
      </button>
    </div>
  );
}

/* ─────────────────────────── Main Shell ─────────────────────────── */
const BASE_TABS = [
  { id: "TERMINAL", icon: "⌨", label: "TERMINAL" },
  { id: "TASKS",    icon: "◈", label: "TASKS"    },
  { id: "FILES",    icon: "⇅", label: "FILES"    },
  { id: "LOGS",     icon: "≡", label: "LOGS"     },
  { id: "CREDS",    icon: "⊛", label: "CREDS"    },
  { id: "SHOTS",    icon: "⊡", label: "SHOTS"    },
  { id: "LOOT",     icon: "◉", label: "LOOT"     },
  { id: "MAP",      icon: "◎", label: "MAP"      },
];

export default function App() {
  const {
    token,
    logout,
    selectedAgent,
    agents,
    connectWS,
    wsConnected,
    consoleTabs,
    closeConsoleTab,
    sendTask,
    killAll,
    addToast,
    agentAliases,
    setAgentAlias,
    clearAgentAlias,
    clearMultiSelect,
  } = useAgentStore();

  const jwtPayload = useMemo(
    () => (token ? decodeJwtPayload(token) : {}),
    [token],
  );
  const isAdmin = jwtPayload.role === "admin";
  const TABS = useMemo(
    () =>
      isAdmin
        ? [
            ...BASE_TABS,
            { id: "BUILD", icon: "⬡", label: "BUILD" },
            { id: "USERS", icon: "☰", label: "USERS" },
          ]
        : BASE_TABS,
    [isAdmin],
  );
  const [tab, setTab] = useState("TERMINAL");
  const [showPalette, setShowPalette] = useState(false);
  const [showDetail, setShowDetail] = useState(true);
  const [clock, setClock] = useState("");
  const [killConfirm, setKillConfirm] = useState(false);

  /* ── Terminal slots (solo · hsplit · quad) ── */
  const [termSlots, setTermSlots] = useState({}) // slot → agentId
  const [dragTab, setDragTab] = useState(null)   // agentId en cours de drag
  const prevTabIdsRef = useRef(new Set())
  const [renameTarget, setRenameTarget] = useState(null)
  const [renameValue, setRenameValue] = useState('')
  const termSlotsRef = useRef({}) // toujours à jour sans dépendance d'effet
  useEffect(() => { termSlotsRef.current = termSlots }, [termSlots])

  // Auto-solo nouvel agent; purge les agents fermés des slots
  useEffect(() => {
    const currentIds = new Set(consoleTabs.map(a => a.agent_id))
    let newId = null
    consoleTabs.forEach(a => { if (!prevTabIdsRef.current.has(a.agent_id)) newId = a.agent_id })
    prevTabIdsRef.current = currentIds
    setTermSlots(prev => {
      if (newId) return { full: newId }
      const cleaned = {}
      for (const [k, v] of Object.entries(prev)) { if (v && currentIds.has(v)) cleaned[k] = v }
      const same = Object.keys(cleaned).length === Object.keys(prev).length &&
        Object.entries(cleaned).every(([k, v]) => prev[k] === v)
      return same ? prev : cleaned
    })
  }, [consoleTabs])

  // Clic sur chip = toujours solo (toggle si déjà solo) + sélectionne l'agent
  const clickTabChip = useCallback((agentId) => {
    setTermSlots(prev => {
      const isSolo = getTermLayout(prev) === 'solo' && prev.full === agentId
      return isSolo ? {} : { full: agentId }
    })
    // Mettre à jour selectedAgent pour que DetailPanel etc. soient synchros
    const agent = useAgentStore.getState().agents.find(a => a.agent_id === agentId)
    if (agent) useAgentStore.getState().selectAgent(agent)
  }, [])

  // Dépôt sur une zone snap (drag ou raccourci clavier)
  const snapToZone = useCallback((agentId, zone) => {
    setTermSlots(prev => {
      if (zone === 'full') return { full: agentId }
      if (zone === 'left' || zone === 'right') {
        const other = zone === 'left' ? 'right' : 'left'
        const otherAgent = prev[other] || prev.full || prev.tl || prev.tr || prev.bl || prev.br
        const result = { [zone]: agentId }
        if (otherAgent && otherAgent !== agentId) result[other] = otherAgent
        return result
      }
      const q = {}
      for (const s of ['tl','tr','bl','br']) { if (prev[s] && prev[s] !== agentId) q[s] = prev[s] }
      for (const src of [prev.left, prev.right, prev.full]) {
        if (src && src !== agentId && !Object.values(q).includes(src)) {
          const fs = ['tl','tr','bl','br'].find(s => !q[s]); if (fs) q[fs] = src
        }
      }
      q[zone] = agentId
      return q
    })
  }, [])

  // Dépôt sur une zone snap (drag)
  const dropToZone = useCallback((zone) => {
    snapToZone(dragTab, zone)
    setDragTab(null)
  }, [dragTab, snapToZone])

  // Cache un slot (garde consoletab)
  const hideSlot = useCallback((slot) => {
    setTermSlots(prev => {
      const next = { ...prev }; delete next[slot]
      const rem = Object.entries(next).filter(([, v]) => v)
      if (rem.length === 1) return { full: rem[0][1] }
      return next
    })
  }, [])

  // Ferme un slot + consoletab
  const closeSlot = useCallback((slot, agentId) => {
    hideSlot(slot); if (agentId) closeConsoleTab(agentId)
  }, [hideSlot, closeConsoleTab])

  useEffect(() => {
    const tick = () => {
      const now = new Date();
      setClock(now.toUTCString().slice(17, 25) + " UTC");
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  /* ── Init WS on load ── */
  useEffect(() => {
    if (token) connectWS();
  }, [token]);

  /* ── Periodic agent refresh — fallback if WS misses agent_lost/agent_seen ── */
  useEffect(() => {
    if (!token) return;
    const { fetchAgents } = useAgentStore.getState();
    fetchAgents();
    const id = setInterval(() => useAgentStore.getState().fetchAgents(), 30000);
    return () => clearInterval(id);
  }, [token]);

  /* ── Keyboard shortcuts ── */
  useEffect(() => {
    const onKey = (e) => {
      const t = e.target;
      const inInput = t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.closest?.(".xterm");

      /* Ctrl/Cmd+K — command palette */
      if (e.key === "k" && (e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey) {
        e.preventDefault();
        if (!inInput) setShowPalette((p) => !p);
        return;
      }

      /* ] — toggle detail panel */
      if (e.key === "]" && !e.ctrlKey && !e.altKey && !e.metaKey) {
        if (!inInput) setShowDetail((p) => !p);
        return;
      }

      /* Escape — close palette */
      if (e.key === "Escape" && !inInput) {
        setShowPalette(false);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [isAdmin]);

  /* ── Raccourcis split terminal (Ctrl+flèches) ──
     Conditions : un agent est shift-sélectionné dans la sidebar
                  ET au moins une fenêtre terminal est déjà ouverte
     Ctrl+← → Ctrl+←  = ½ gauche    Ctrl+← → Ctrl+↑ = ¼ haut-gauche
     Ctrl+→ → Ctrl+→  = ½ droite   Ctrl+→ → Ctrl+↓ = ¼ bas-droite
     Ctrl+↑ (seul)   = solo agent sélectionné   */
  const chordDir = useRef(null)
  const chordTimeout = useRef(null)
  const [chordHint, setChordHint] = useState(null)

  useEffect(() => {
    const onKey = (e) => {
      if (!e.ctrlKey || e.altKey || e.metaKey) return
      if (!['ArrowLeft','ArrowRight','ArrowUp','ArrowDown'].includes(e.key)) return
      const t = document.activeElement
      if (t?.closest?.('.xterm') || t?.tagName === 'INPUT' || t?.tagName === 'TEXTAREA') return

      // Ctrl+↑ sans chord : solo de l’agent sélectionné, toujours disponible
      if (e.key === 'ArrowUp' && !chordDir.current) {
        e.preventDefault()
        const agent = useAgentStore.getState().selectedAgent
        if (agent) { clearTimeout(chordTimeout.current); chordDir.current = null; setChordHint(null); snapToZone(agent.agent_id, 'full') }
        return
      }

      // Pour les splits : vérifier conditions
      const ms = useAgentStore.getState().multiSelect
      const slots = termSlotsRef.current
      if (ms.size === 0 || Object.keys(slots).length === 0) return

      e.preventDefault()

      // Agent à placer : le 1er shift-sélectionné pas encore dans un slot
      const placedIds = Object.values(slots)
      const agentId = [...ms].find(id => !placedIds.includes(id)) ?? [...ms][0]

      const commit = (zone) => {
        clearTimeout(chordTimeout.current)
        chordDir.current = null
        setChordHint(null)
        snapToZone(agentId, zone)
        useAgentStore.getState().clearMultiSelect()
        if (tab !== 'TERMINAL') setTab('TERMINAL')
      }

      if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
        const dir = e.key === 'ArrowRight' ? 'right' : 'left'
        if (chordDir.current === dir) {
          commit(dir)
        } else {
          clearTimeout(chordTimeout.current)
          chordDir.current = dir
          setChordHint(dir)
          chordTimeout.current = setTimeout(() => {
            const msNow = useAgentStore.getState().multiSelect
            const slotsNow = termSlotsRef.current
            if (msNow.size > 0 && Object.keys(slotsNow).length > 0) {
              const placed = Object.values(slotsNow)
              const aid = [...msNow].find(id => !placed.includes(id)) ?? [...msNow][0]
              snapToZone(aid, dir)
              useAgentStore.getState().clearMultiSelect()
              if (tab !== 'TERMINAL') setTab('TERMINAL')
            }
            chordDir.current = null
            setChordHint(null)
          }, 600)
        }
        return
      }

      if ((e.key === 'ArrowDown' || e.key === 'ArrowUp') && chordDir.current) {
        const v = e.key === 'ArrowDown' ? 'b' : 't'
        const h = chordDir.current[0]
        commit(v + h)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => { window.removeEventListener('keydown', onKey); clearTimeout(chordTimeout.current) }
  }, [tab, snapToZone])

  /* ── Quick command from palette ── */
  const handleRunCommand = useCallback(
    async (item) => {
      const agent = useAgentStore.getState().selectedAgent;
      if (!agent) return;
      sendTask(agent.agent_id, item.cmd, item.args);
    },
    [sendTask],
  );

  /* ── Resizable sidebars ── */
  const [sidebarW, setSidebarW] = useState(260);
  const dragging = useRef(false);
  const startX = useRef(0);
  const startW = useRef(0);
  const handleRef = useRef(null);

  const onMouseDown = useCallback(
    (e) => {
      e.preventDefault();
      dragging.current = true;
      startX.current = e.clientX;
      startW.current = sidebarW;
      handleRef.current?.classList.add("dragging");
    },
    [sidebarW],
  );

  const [detailW, setDetailW] = useState(280);
  const detailDragging = useRef(false);
  const detailStartX = useRef(0);
  const detailStartW = useRef(0);
  const detailHandleRef = useRef(null);

  const onDetailMouseDown = useCallback(
    (e) => {
      e.preventDefault();
      detailDragging.current = true;
      detailStartX.current = e.clientX;
      detailStartW.current = detailW;
      detailHandleRef.current?.classList.add("dragging");
    },
    [detailW],
  );

  const [windowW, setWindowW] = useState(window.innerWidth);

  useEffect(() => {
    const onMove = (e) => {
      if (dragging.current) {
        setSidebarW(Math.max(180, Math.min(480, startW.current + e.clientX - startX.current)));
      }
      if (detailDragging.current) {
        setDetailW(Math.max(180, Math.min(500, detailStartW.current - (e.clientX - detailStartX.current))));
      }
    };
    const onUp = () => {
      dragging.current = false;
      handleRef.current?.classList.remove("dragging");
      detailDragging.current = false;
      detailHandleRef.current?.classList.remove("dragging");
    };
    const onResize = () => setWindowW(window.innerWidth);
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    window.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      window.removeEventListener("resize", onResize);
    };
  }, []);

  const detailVisible = showDetail && windowW >= 900;

  if (!token)
    return (
      <>
        <style>{GLOBAL_CSS}</style>
        <Login />
      </>
    );

  const onlineCount = agents.filter((a) => a.is_active).length;

  return (
    <>
      <style>{GLOBAL_CSS}</style>
      <ToastContainer />

      {showPalette && (
        <CommandPalette
          onClose={() => setShowPalette(false)}
          onOpenTerminal={() => setTab("TERMINAL")}
          onRunCommand={handleRunCommand}
        />
      )}

      <div style={s.shell}>
        {/* ── Top bar ── */}
        <header style={s.topBar}>
          <Logo size={15} />
          <div style={{ flex: 1 }} />
          <button
            className="k-btn k-btn-ghost"
            onClick={() => setShowDetail((p) => !p)}
            title="Toggle detail panel  ]"
            style={{
              background: showDetail ? "#1e1e1e" : "transparent",
              border: "1px solid #1e1e1e",
              color: showDetail ? "#888888" : "#888888",
              padding: "4px 10px",
              fontSize: 11,
              fontFamily: "inherit",
              letterSpacing: 1,
            }}
          >
            ◫
          </button>
          {isAdmin &&
            (killConfirm ? (
              <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
                <span
                  style={{ fontSize: 10, color: "#f85149", letterSpacing: 1 }}
                >
                  KILL ALL?
                </span>
                <button
                  className="k-btn"
                  onClick={async () => {
                    setKillConfirm(false);
                    const r = await killAll();
                    addToast({
                      type: "success",
                      text: `☠ kill sent to ${r?.killed ?? 0} agents`,
                    });
                  }}
                  style={{
                    background: "#2d1818",
                    border: "1px solid #f85149",
                    color: "#f85149",
                    padding: "4px 10px",
                    fontSize: 10,
                    fontFamily: "inherit",
                    letterSpacing: 1,
                    cursor: "pointer",
                  }}
                >
                  CONFIRM
                </button>
                <button
                  className="k-btn k-btn-ghost"
                  onClick={() => setKillConfirm(false)}
                  style={{
                    background: "transparent",
                    border: "1px solid #1e1e1e",
                    color: "#888888",
                    padding: "4px 8px",
                    fontSize: 10,
                    fontFamily: "inherit",
                    cursor: "pointer",
                  }}
                >
                  CANCEL
                </button>
              </div>
            ) : (
              <button
                className="k-btn"
                onClick={() => setKillConfirm(true)}
                title="Kill all active agents"
                style={{
                  background: "transparent",
                  border: "1px solid #f8514966",
                  color: "#f85149",
                  padding: "4px 10px",
                  fontSize: 10,
                  fontFamily: "inherit",
                  letterSpacing: 1,
                }}
              >
                ☠ KILL ALL
              </button>
            ))}
          <button
            className="k-btn k-btn-ghost"
            onClick={logout}
            style={{
              background: "transparent",
              border: "1px solid #1e1e1e",
              color: "#888888",
              padding: "4px 12px",
              fontSize: 11,
              fontFamily: "inherit",
              letterSpacing: 2,
            }}
          >
            DISCONNECT
          </button>
        </header>

        {/* ── Body ── */}
        <div style={s.body}>
          {/* Sidebar */}
          <aside style={{ ...s.sidebar, width: sidebarW, minWidth: sidebarW }}>
            <Dashboard
              onOpenTerminal={(agentId) => { setTab('TERMINAL'); if (agentId) setTermSlots({ full: agentId }) }}
              openSlotIds={new Set(Object.values(termSlots))}
            />
          </aside>

          {/* Resize handle */}
          <div
            className="resize-handle"
            ref={handleRef}
            onMouseDown={onMouseDown}
          />

          {/* Main panel */}
          <main style={s.main} onDragOver={dragTab ? (e => e.preventDefault()) : undefined}>
            {/* Tab bar */}
            <div style={s.tabBar}>
              {TABS.map((t) => (
                <button
                  key={t.id}
                  className={`tab-btn ${tab === t.id ? "active" : ""}`}
                  onClick={() => setTab(t.id)}
                  style={s.tabBtn}
                >
                  <span style={{ marginRight: 5, opacity: 0.6 }}>{t.icon}</span>
                  {t.label}
                </button>
              ))}
              <div style={{ flex: 1 }} />
              {/* Indicateur chord Ctrl+flèche en attente */}
              {chordHint && (
                <div style={{ display:'flex', alignItems:'center', gap:6, padding:'0 14px', color:'#ff313199', fontSize:10, letterSpacing:2, animation:'pulse 0.5s infinite' }}>
                  <span>Ctrl+</span>
                  <span style={{ fontSize:14 }}>{chordHint === 'right' ? '→' : '←'}</span>
                  <span style={{ color:'#333' }}>→ ½ ou ↑↓ pour ¼</span>
                </div>
              )}
            </div>

            {/* ── Console tab chips ── */}
            {tab === "TERMINAL" && (
              <div style={s.consoleTabBar}>
                {consoleTabs.length === 0 && (
                  <div style={{ padding: '0 16px', color: '#333', fontSize: 10, letterSpacing: 2, display: 'flex', alignItems: 'center' }}>NO SESSIONS</div>
                )}
                {consoleTabs.map(agent => {
                  const inSlot = Object.values(termSlots).includes(agent.agent_id)
                  const alias = agentAliases?.[agent.agent_id]
                  const displayName = alias || agent.agent_id
                  const isRenaming = renameTarget === agent.agent_id
                  return (
                    <div
                      key={agent.agent_id}
                      className={`c-tab ${inSlot ? 'active' : ''}`}
                      draggable={!isRenaming}
                      onDragStart={isRenaming ? undefined : e => {
                        e.dataTransfer.setData('tab', agent.agent_id)
                        setDragTab(agent.agent_id)
                      }}
                      onDragEnd={isRenaming ? undefined : () => setDragTab(null)}
                      onClick={isRenaming ? undefined : () => clickTabChip(agent.agent_id)}
                      title="clic = solo · double-clic nom = renommer · glisser = split"
                    >
                      <span style={{ fontSize: 8, color: agent.is_active ? '#3fb950' : '#444', flexShrink: 0 }}>●</span>
                      {isRenaming ? (
                        <input
                          autoFocus
                          value={renameValue}
                          onChange={e => setRenameValue(e.target.value)}
                          onKeyDown={e => {
                            if (e.key === 'Enter') {
                              if (renameValue.trim()) setAgentAlias(agent.agent_id, renameValue.trim())
                              setRenameTarget(null)
                            }
                            if (e.key === 'Escape') setRenameTarget(null)
                          }}
                          onBlur={() => {
                            if (renameValue.trim()) setAgentAlias(agent.agent_id, renameValue.trim())
                            setRenameTarget(null)
                          }}
                          onClick={e => e.stopPropagation()}
                          style={{
                            background: 'transparent', border: 'none',
                            borderBottom: '1px solid #ff3131', color: '#ff3131',
                            fontFamily: 'inherit', fontSize: 11, width: 90,
                            outline: 'none', padding: 0,
                          }}
                        />
                      ) : (
                        <span
                          style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}
                          onDoubleClick={e => {
                            e.stopPropagation()
                            setRenameTarget(agent.agent_id)
                            setRenameValue(alias || agent.agent_id)
                          }}
                        >{displayName}</span>
                      )}
                      {alias && !isRenaming && (
                        <button
                          title="reset nom original"
                          onClick={e => { e.stopPropagation(); clearAgentAlias(agent.agent_id) }}
                          style={{ background:'transparent', border:'none', color:'#444', cursor:'pointer', fontSize:10, padding:'0 2px', lineHeight:1, flexShrink:0 }}
                        >⊘</button>
                      )}
                      <button
                        className="c-close"
                        style={{ opacity: 1, marginLeft: 2 }}
                        onClick={e => { e.stopPropagation(); closeConsoleTab(agent.agent_id) }}
                        title="close"
                      >✕</button>
                    </div>
                  )
                })}
              </div>
            )}

            {/* Content */}
            <div style={s.content}>
              {/* Terminal — toujours monté, caché par display:none hors onglet pour préserver xterm */}
              <div style={{ display: tab === 'TERMINAL' ? 'flex' : 'none', flex: 1, overflow: 'hidden', position: 'relative' }}>
                {(() => {
                  const layout = getTermLayout(termSlots)
                  if (layout === 'empty') return <NoSel />
                  const rp = (slot) => (
                    <TerminalPane key={slot} agentId={termSlots[slot]} consoleTabs={consoleTabs} />
                  )
                  const vd = <div key="vd" style={{ width:1, background:'#1a1a1a', flexShrink:0 }} />
                  const hd = <div key="hd" style={{ height:1, background:'#1a1a1a', flexShrink:0 }} />
                  return (
                    <div style={{ flex:1, overflow:'hidden', position:'relative', display:'flex' }}>
                      {/* Overlay drag */}
                      <div
                        style={{
                          position:'absolute', inset:0, zIndex:30,
                          background:'rgba(0,0,0,.82)',
                          display: dragTab ? 'block' : 'none',
                          pointerEvents: dragTab ? 'all' : 'none',
                        }}
                        onDragOver={e => e.preventDefault()}
                      >
                        <DropZone label="½" icon="←" onDrop={() => dropToZone('left')}
                          style={{ position:'absolute', left:16, top:'22%', bottom:'22%', width:90 }} />
                        <DropZone label="½" icon="→" onDrop={() => dropToZone('right')}
                          style={{ position:'absolute', right:16, top:'22%', bottom:'22%', width:90 }} />
                        <DropZone label="¼" icon="↖" onDrop={() => dropToZone('tl')}
                          style={{ position:'absolute', top:16, left:120, width:130, height:110 }} />
                        <DropZone label="¼" icon="↗" onDrop={() => dropToZone('tr')}
                          style={{ position:'absolute', top:16, right:120, width:130, height:110 }} />
                        <DropZone label="¼" icon="↙" onDrop={() => dropToZone('bl')}
                          style={{ position:'absolute', bottom:16, left:120, width:130, height:110 }} />
                        <DropZone label="¼" icon="↘" onDrop={() => dropToZone('br')}
                          style={{ position:'absolute', bottom:16, right:120, width:130, height:110 }} />
                        <div style={{ position:'absolute', inset:0, display:'flex', alignItems:'center', justifyContent:'center', pointerEvents:'none' }}>
                          <span style={{ color:'#2a2a2a', fontSize:10, letterSpacing:4 }}>GLISSER VERS UN COIN</span>
                        </div>
                      </div>
                      {layout === 'solo' && rp('full')}
                      {layout === 'hsplit' && <>{rp('left')}{vd}{rp('right')}</>}
                      {layout === 'quad' && (
                        <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden' }}>
                          <div style={{ flex:1, display:'flex', overflow:'hidden' }}>
                            {rp('tl')}<div style={{ width:1, background:'#1a1a1a', flexShrink:0 }} />{rp('tr')}
                          </div>
                          {hd}
                          <div style={{ flex:1, display:'flex', overflow:'hidden' }}>
                            {rp('bl')}<div style={{ width:1, background:'#1a1a1a', flexShrink:0 }} />{rp('br')}
                          </div>
                        </div>
                      )}
                    </div>
                  )
                })()}
              </div>

              {tab === "TASKS" &&
                (selectedAgent ? (
                  <Tasks agent={selectedAgent} key={selectedAgent.agent_id} />
                ) : (
                  <NoSel />
                ))}
              {tab === "FILES" &&
                (selectedAgent ? (
                  <FileManager
                    agent={selectedAgent}
                    key={selectedAgent.agent_id}
                  />
                ) : (
                  <NoSel />
                ))}
              {tab === "LOGS" && <Logs agentId={selectedAgent?.agent_id} />}
              {tab === "CREDS" && <Creds />}
              {tab === "SHOTS" && (selectedAgent
                ? <Screenshots key={selectedAgent.agent_id} agentId={selectedAgent.agent_id} />
                : <NoSel />)}
              {tab === "LOOT"  && (selectedAgent
                ? <Loot key={selectedAgent.agent_id} agentId={selectedAgent.agent_id} />
                : <NoSel />)}
              {tab === "MAP"   && <NetworkMap />}
              {tab === "BUILD" && <Build />}
              {tab === "USERS" && <Users />}
            </div>
          </main>

          {/* Detail panel resize handle */}
          {detailVisible && (
            <div
              className="resize-handle"
              ref={detailHandleRef}
              onMouseDown={onDetailMouseDown}
            />
          )}

          {/* Detail panel */}
          <DetailPanel
            visible={detailVisible}
            width={detailW}
            onOpenTerminal={() => setTab("TERMINAL")}
            onOpenFiles={() => setTab("FILES")}
            onOpenTasks={() => setTab("TASKS")}
          />
        </div>

        {/* ── Status bar ── */}
        <footer style={s.statusBar}>
          <span
            style={{ ...s.sbItem, color: wsConnected ? "#3fb950" : "#f85149" }}
          >
            {wsConnected ? "●" : "○"} WS
          </span>
          <span style={s.sbSep}>│</span>
          <span style={s.sbItem}>
            <span
              style={{
                color:
                  agents.filter((a) => a.is_active).length > 0
                    ? "#3fb950"
                    : "#888888",
              }}
            >
              {agents.filter((a) => a.is_active).length}
            </span>
            <span style={{ color: "#333" }}>/{agents.length}</span>
            <span style={{ color: "#555", marginLeft: 5 }}>AGENTS</span>
          </span>
          <span style={s.sbSep}>│</span>
          <span style={{ ...s.sbItem, color: "#888888" }}>
            {jwtPayload.sub || "operator"}
            {isAdmin && (
              <span style={{ color: "#f59e0b", marginLeft: 4 }}>★</span>
            )}
          </span>
          <span style={{ flex: 1 }} />
          <span style={{ ...s.sbItem, color: "#333", letterSpacing: 1 }}>
            {clock}
          </span>
          <span style={s.sbSep}>│</span>
          <span style={{ ...s.sbItem, color: "#444", letterSpacing: 1 }}>
            built by khaotic.fr
          </span>
        </footer>
      </div>
    </>
  );
}

function getTermLayout(slots) {
  if (Object.values(slots).filter(Boolean).length === 0) return 'empty'
  if (slots.tl || slots.tr || slots.bl || slots.br) return 'quad'
  if (slots.left || slots.right) return 'hsplit'
  return 'solo'
}

function TerminalPane({ agentId, consoleTabs }) {
  const agent = consoleTabs.find(a => a.agent_id === agentId)
  if (!agentId || !agent) return (
    <div style={{ flex:1, background:'#060606', display:'flex', alignItems:'center', justifyContent:'center', minWidth:0 }}>
      <span style={{ color:'#1a1a1a', fontSize:10, letterSpacing:3 }}>EMPTY</span>
    </div>
  )
  return (
    <div style={{ flex:1, minWidth:0, minHeight:0, overflow:'hidden' }}>
      <Terminal agent={agent} active={true} />
    </div>
  )
}

function DropZone({ label, icon, onDrop, style }) {
  const [over, setOver] = useState(false)
  return (
    <div
      style={{
        ...style,
        border: `1px solid ${over ? '#ff3131' : '#2a2a2a'}`,
        background: over ? 'rgba(255,49,49,.12)' : 'rgba(20,20,20,.92)',
        display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center',
        cursor:'copy', color: over ? '#ff3131' : '#444',
        transition:'border-color .1s, background .1s, color .1s', borderRadius:2, gap:6, userSelect:'none',
      }}
      onDragOver={e => { e.preventDefault(); setOver(true) }}
      onDragLeave={() => setOver(false)}
      onDrop={e => { e.preventDefault(); setOver(false); onDrop() }}
    >
      <span style={{ fontSize:22, lineHeight:1 }}>{icon}</span>
      <span style={{ fontSize:10, letterSpacing:2 }}>{label}</span>
    </div>
  )
}

function NoSel() {
  return (
    <div
      style={{
        flex: 1,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      <div style={{ textAlign: "center" }}>
        <div style={{ color: "#1e1e1e", fontSize: 32, marginBottom: 16 }}>
          ⊡
        </div>
        <p style={{ color: "#888888", fontSize: 11, letterSpacing: 4 }}>
          SELECT AN AGENT
        </p>
        <p
          style={{
            color: "#1e1e1e",
            fontSize: 11,
            letterSpacing: 2,
            marginTop: 8,
          }}
        >
          click a session in the sidebar
        </p>
      </div>
    </div>
  );
}

const s = {
  toolbar: {
    display: "flex",
    alignItems: "center",
    height: 32,
    padding: "0 12px",
    background: "#0d0d0d",
    borderBottom: "1px solid #1a1a1a",
    flexShrink: 0,
  },
  shell: {
    display: "flex",
    flexDirection: "column",
    height: "100vh",
    background: "#0a0a0a",
  },
  topBar: {
    display: "flex",
    alignItems: "center",
    gap: 10,
    height: 48,
    padding: "0 16px",
    background: "#111111",
    borderBottom: "1px solid #1e1e1e",
    flexShrink: 0,
  },
  topSep: { width: 1, height: 20, background: "#1e1e1e", flexShrink: 0 },
  topInfo: { display: "flex", alignItems: "center", gap: 7 },
  dot: { width: 7, height: 7, borderRadius: "50%", flexShrink: 0 },
  infoTxt: { fontSize: 11, color: "#888888", letterSpacing: 2 },
  activeChip: {
    fontSize: 10,
    color: "#888888",
    letterSpacing: 1,
    padding: "3px 10px",
    background: "#0a0a0a",
    border: "1px solid #1e1e1e",
  },
  body: { display: "flex", flex: 1, overflow: "hidden" },
  sidebar: {
    background: "#0a0a0a",
    borderRight: "1px solid #1e1e1e",
    display: "flex",
    flexDirection: "column",
    overflow: "hidden",
    flexShrink: 0,
  },
  main: {
    flex: 1,
    display: "flex",
    flexDirection: "column",
    overflow: "hidden",
    minWidth: 0,
  },
  tabBar: {
    display: "flex",
    alignItems: "center",
    height: 38,
    padding: "0 4px",
    background: "#111111",
    borderBottom: "1px solid #1e1e1e",
    flexShrink: 0,
  },
  tabBtn: {
    background: "transparent",
    border: "none",
    padding: "0 16px",
    height: "100%",
    fontSize: 10,
    fontFamily: "inherit",
    letterSpacing: 2,
    color: "#888888",
    display: "flex",
    alignItems: "center",
  },
  consoleTabBar: {
    display: "flex",
    alignItems: "stretch",
    height: 36,
    background: "#0a0a0a",
    borderBottom: "1px solid #1e1e1e",
    flexShrink: 0,
    overflowX: "auto",
    overflowY: "hidden",
  },
  content: {
    flex: 1,
    overflow: "hidden",
    display: "flex",
    flexDirection: "column",
    position: "relative",
  },
  statusBar: {
    display: "flex",
    alignItems: "center",
    height: 26,
    padding: "0 16px",
    background: "#111111",
    borderTop: "1px solid #1e1e1e",
    flexShrink: 0,
    gap: 12,
  },
  sbItem: { fontSize: 11, color: "#888888", letterSpacing: 1 },
  sbSep: { color: "#1e1e1e", fontSize: 9 },
};