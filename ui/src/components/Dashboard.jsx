import { useEffect, useRef, useState, useCallback } from 'react'
import useAgentStore from '../store/useAgentStore'

function relTime(iso) {
  if (!iso) return '—'
  const s = Math.floor((Date.now() - new Date(iso + 'Z')) / 1000)
  if (s < 60)   return `${s}s`
  if (s < 3600) return `${Math.floor(s/60)}m`
  return `${Math.floor(s/3600)}h`
}

/* ── Beacon freshness: seconds since last seen ── */
function beaconStatus(lastSeen) {
  if (!lastSeen) return null
  const s = Math.floor((Date.now() - new Date(lastSeen + 'Z')) / 1000)
  if (s <  30) return { label: `⏱ ${s}s`,  color: '#3fb950' }
  if (s <  90) return { label: `⏱ ${s}s`,  color: '#f59e0b' }
  if (s < 300) return { label: `⏱ ${Math.floor(s/60)}m`, color: '#ff6b35' }
  return { label: '⏱ late', color: '#f85149' }
}

/* ── Context menu ── */
function CtxMenu({ menu, onClose, onShell, onCopyId, onDelete, onRename, onResetName, hasAlias }) {
  const ref = useRef(null)
  useEffect(() => {
    const close = e => { if (ref.current && !ref.current.contains(e.target)) onClose() }
    document.addEventListener('mousedown', close)
    return () => document.removeEventListener('mousedown', close)
  }, [onClose])
  if (!menu) return null
  return (
    <div ref={ref} className="ctx-menu"
      style={{ position: 'fixed', top: menu.y, left: menu.x, zIndex: 999, minWidth: 160, background: '#111111', border: '1px solid #888888', boxShadow: '0 8px 32px rgba(0,0,0,.6)' }}>
      <div style={{ padding: '6px 0 2px', borderBottom: '1px solid #1e1e1e', marginBottom: 4 }}>
        <p style={{ fontSize: 11, color: '#888888', letterSpacing: 2, padding: '0 16px 4px' }}>{menu.agent.agent_id}</p>
      </div>
      <div className="ctx-item" onClick={() => { onShell(); onClose() }}>⌨  OPEN TERMINAL</div>
      <div className="ctx-item" onClick={() => { onCopyId(menu.agent.agent_id); onClose() }}>⎘  COPY AGENT ID</div>
      <div className="ctx-item" onClick={() => { onRename(menu.agent); onClose() }}>&#9998;  RENAME</div>
      {hasAlias && (
        <div className="ctx-item" onClick={() => { onResetName(menu.agent.agent_id); onClose() }}>⊘  RESET NAME</div>
      )}
      <div className="ctx-item" style={{ color: '#f85149', borderTop: '1px solid #1e1e1e', marginTop: 4 }}
        onClick={() => { onDelete(menu.agent.agent_id); onClose() }}>✕  KILL AGENT</div>
    </div>
  )
}

/* ── Agent detail panel ── */
function AgentDetail({ agent }) {
  if (!agent) return null
  const online = !!agent.last_seen && (Date.now() - new Date(agent.last_seen + 'Z').getTime()) < 15 * 60 * 1000
  return (
    <div style={d.panel}>
      <div style={d.panelHead}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
          <span style={{ width: 2, height: 9, background: '#ff3131', flexShrink: 0, display: 'inline-block', opacity: .7 }} />
          <span style={{ color: '#888888', fontSize: 9, letterSpacing: 4 }}>SESSION DETAIL</span>
        </div>
        <span style={{ color: online ? '#3fb950' : '#1e1e1e', fontSize: 10, letterSpacing: 1 }}>
          {online ? '◉' : '○'}
        </span>
      </div>
      <div style={d.grid}>
        <Row label="ID"   val={agent.agent_id} accent="#ff3131" />
        <Row label="HOST" val={agent.hostname} />
        <Row label="USER" val={agent.username} />
        <Row label="OS"   val={agent.os_info ? agent.os_info.slice(0,30) : '—'} />
        <Row label="PRIV" val={agent.privileges}
          accent={agent.privileges === 'elevated' ? '#f85149' : null} />
        <Row label="SEEN" val={relTime(agent.last_seen)} />
      </div>
    </div>
  )
}

function Row({ label, val, accent }) {
  return (
    <div style={d.row}>
      <span style={d.label}>{label}</span>
      <span style={{ ...d.val, color: accent || '#dde1e8' }}>{val || '—'}</span>
    </div>
  )
}

const d = {
  panel:    { borderTop: '1px solid #1e1e1e', padding: '10px 12px', flexShrink: 0, background: '#0a0a0a' },
  panelHead:{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 },
  grid:     { display: 'flex', flexDirection: 'column', gap: 3 },
  row:      { display: 'flex', gap: 8, alignItems: 'flex-start' },
  label:    { fontSize: 9, color: '#888888', letterSpacing: 2, minWidth: 36, flexShrink: 0, paddingTop: 2 },
  val:      { fontSize: 11, color: '#dde1e8', fontFamily: 'inherit', wordBreak: 'break-all', lineHeight: 1.4 },
}

/* ── Tree builder: roots first, children indented below their parent ── */
function buildTree(agents) {
  const byId = Object.fromEntries(agents.map(a => [a.agent_id, a]))
  const result = []
  const added = new Set()

  for (const a of agents) {
    if (!a.parent_id || !byId[a.parent_id]) {
      result.push({ agent: a, depth: 0 })
      added.add(a.agent_id)
      for (const child of agents) {
        if (child.parent_id === a.agent_id && !added.has(child.agent_id)) {
          result.push({ agent: child, depth: 1 })
          added.add(child.agent_id)
        }
      }
    }
  }
  for (const a of agents) {
    if (!added.has(a.agent_id)) {
      result.push({ agent: a, depth: 0 })
    }
  }
  return result
}

/* ── Main component ── */
export default function Dashboard({ onOpenTerminal, openSlotIds }) {
  const {
    agents, fetchAgents, loadingAgents,
    selectAgent, selectedAgent, openConsoleTab, deleteAgent,
    multiSelect, toggleMultiSelect, clearMultiSelect, broadcastTask,
    agentAliases, setAgentAlias, clearAgentAlias,
  } = useAgentStore()
  const [ctx, setCtx]           = useState(null)
  const [filter, setFilter]     = useState('all')
  const [bcCmd, setBcCmd]       = useState('')
  const [, tick]                = useState(0)
  const [renameAgent, setRenameAgent] = useState(null)  // agent being renamed
  const [renameVal, setRenameVal]     = useState('')
  const renameInputRef = useRef(null)

  useEffect(() => {
    fetchAgents()
    const fetchId = setInterval(fetchAgents, 12_000)
    const tickId  = setInterval(() => tick(n => n + 1), 1000)
    return () => { clearInterval(fetchId); clearInterval(tickId) }
  }, [])

  const isOnline = a => !!a.last_seen && (Date.now() - new Date(a.last_seen + 'Z').getTime()) < 15 * 60 * 1000

  const filtered = agents.filter(a => {
    if (filter === 'online')   return isOnline(a)
    if (filter === 'elevated') return a.privileges === 'elevated'
    return true
  })

  const onCtxMenu = (e, agent) => {
    e.preventDefault()
    setCtx({ x: e.clientX, y: e.clientY, agent })
  }

  const handleDelete = (agentId) => {
    if (deleteAgent) deleteAgent(agentId)
  }

  const handleRename = (agent) => {
    setRenameAgent(agent)
    setRenameVal(agentAliases?.[agent.agent_id] || agent.agent_id)
    setTimeout(() => renameInputRef.current?.focus(), 30)
  }

  const confirmRename = () => {
    if (renameAgent && renameVal.trim()) setAgentAlias(renameAgent.agent_id, renameVal.trim())
    setRenameAgent(null)
  }

  /* Delete key removes selected agent */
  useEffect(() => {
    const onKey = e => {
      if (e.key === 'Delete' && selectedAgent && document.activeElement?.tagName !== 'INPUT') {
        handleDelete(selectedAgent.agent_id)
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [selectedAgent])

  return (
    <div style={s.wrap}>
      {/* Rename modal */}
      {renameAgent && (
        <div style={{ position:'fixed', inset:0, zIndex:1000, background:'rgba(0,0,0,.7)', display:'flex', alignItems:'center', justifyContent:'center' }}
          onClick={() => setRenameAgent(null)}>
          <div style={{ background:'#111', border:'1px solid #ff313166', padding:'24px 28px', minWidth:300, display:'flex', flexDirection:'column', gap:12 }}
            onClick={e => e.stopPropagation()}>
            <span style={{ fontSize:9, letterSpacing:3, color:'#888' }}>RENOMMER L’AGENT</span>
            <span style={{ fontSize:10, color:'#555', letterSpacing:1 }}>{renameAgent.agent_id}</span>
            <input
              ref={renameInputRef}
              value={renameVal}
              onChange={e => setRenameVal(e.target.value)}
              onKeyDown={e => { if (e.key==='Enter') confirmRename(); if (e.key==='Escape') setRenameAgent(null) }}
              style={{ background:'#0a0a0a', border:'1px solid #ff313166', color:'#dde1e8', fontFamily:'inherit', fontSize:12, padding:'6px 10px', outline:'none' }}
            />
            <div style={{ display:'flex', gap:8, justifyContent:'flex-end' }}>
              <button onClick={() => setRenameAgent(null)}
                style={{ background:'transparent', border:'1px solid #1e1e1e', color:'#888', fontFamily:'inherit', fontSize:10, letterSpacing:2, padding:'4px 14px', cursor:'pointer' }}>ANNULER</button>
              <button onClick={confirmRename}
                style={{ background:'#1c0808', border:'1px solid #ff313166', color:'#ff3131', fontFamily:'inherit', fontSize:10, letterSpacing:2, padding:'4px 14px', cursor:'pointer' }}>OK</button>
            </div>
          </div>
        </div>
      )}
      {/* Header */}
      <div style={s.header}>
        <span style={s.title}>SESSIONS</span>
        <span style={s.count}>{agents.filter(isOnline).length}/{agents.length}</span>
        {loadingAgents && <span style={{ color: '#3fb950', fontSize: 10, animation: 'pulse 1s infinite' }}>●</span>}
        <div style={s.filters}>
          {[['online','ACTIVE']].map(([f, label]) => (
            <button key={f} onClick={() => setFilter(f === filter ? 'all' : f)}
              style={{ ...s.fBtn, color: filter===f ? '#ff3131' : '#888888', borderColor: filter===f ? '#ff313144' : 'transparent' }}>
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Column headers */}
      <div style={s.colHead}>
        <span style={{ ...s.col, minWidth: 14 }} />
        <span style={{ ...s.col, flex: 1 }}>ID</span>
        <span style={{ ...s.col, minWidth: 34 }}>OS</span>
        <span style={{ ...s.col, minWidth: 42, textAlign: 'right' }}>AGO</span>
      </div>

      {/* Agent list */}
      <div className="scroll" style={s.list}>
        {filtered.length === 0 && (
          <div style={s.empty}>
            <span style={{ fontSize: 22, display: 'block', marginBottom: 8, opacity: .15 }}>⊡</span>
            NO SESSIONS
          </div>
        )}
        {buildTree(filtered).map(({ agent: a, depth }) => {
          const online   = isOnline(a)
          const inSlot   = openSlotIds?.has(a.agent_id)
          const selected = selectedAgent?.agent_id === a.agent_id || inSlot
          const alias    = agentAliases?.[a.agent_id]
          const osTag    = a.os_info?.toLowerCase().includes('windows') ? 'WIN'
                         : a.os_info?.toLowerCase().includes('linux')   ? 'LNX'
                         : a.os_info?.toLowerCase().includes('mac')     ? 'MAC' : '?'
          return (
            <div key={a.agent_id}
              className={`agent-row${selected ? ' selected' : ''}`}
              style={{
                ...s.row,
                paddingLeft: depth * 16 + 12,
                background: multiSelect.has(a.agent_id) ? '#0d1929' : undefined,
                borderLeft: multiSelect.has(a.agent_id) ? '2px solid #60a5fa' : '2px solid transparent',
              }}
              onClick={(e) => {
                if (e.shiftKey) {
                  toggleMultiSelect(a.agent_id)
                  openConsoleTab(a) // arme l'agent pour placement par Ctrl+flèche
                } else {
                  clearMultiSelect()
                  selectAgent(a)
                  openConsoleTab(a)
                  onOpenTerminal?.(a.agent_id)
                }
              }}
              onContextMenu={e => onCtxMenu(e, a)}>

              <span style={{ ...s.statusDot, background: online ? '#3fb950' : '#f85149', boxShadow: online ? '0 0 5px #3fb95077' : '0 0 5px #f8514977' }} />

              <div style={{ flex: 1, minWidth: 0 }}>
                {depth > 0 && (
                  <span style={{ fontSize: 10, color: '#555', marginRight: 4, fontFamily: 'inherit' }}>↳</span>
                )}
                <span style={{ fontSize: 12, letterSpacing: .5, color: selected ? '#ff3131' : '#dde1e8', fontFamily: 'inherit' }}>
                  {alias || a.agent_id}
                </span>
                {alias && (
                  <span style={{ fontSize: 9, color: '#333', marginLeft: 4, letterSpacing: 0 }} title={a.agent_id}>→{a.agent_id.slice(0,8)}</span>
                )}
              </div>

              <span style={{ fontSize: 9, color: '#555', minWidth: 34, letterSpacing: 1 }}>{osTag}</span>
              {a.privileges === 'elevated' && (
                <span title="Elevated" style={{ fontSize: 9, color: depth > 0 ? '#ff6b35' : '#f85149', lineHeight: 1 }}>▲</span>
              )}
              {(() => {
                const bs = beaconStatus(a.last_seen)
                return (
                  <span style={{ ...s.ago, color: bs?.color || '#888888' }} title={bs?.label}>
                    {relTime(a.last_seen)}
                  </span>
                )
              })()}
            </div>
          )
        })}
      </div>

      {/* Context menu */}
      <CtxMenu
        menu={ctx}
        onClose={() => setCtx(null)}
        onShell={() => { openConsoleTab(ctx.agent); onOpenTerminal?.() }}
        onCopyId={id => navigator.clipboard.writeText(id).catch(()=>{})}
        onDelete={handleDelete}
        onRename={handleRename}
        onResetName={id => clearAgentAlias(id)}
        hasAlias={ctx ? !!agentAliases?.[ctx.agent.agent_id] : false}
      />

      {/* Broadcast bar — visible when ≥2 agents selected */}
      {multiSelect.size >= 2 && (
        <div style={s.bcastBar}>
          <span style={s.bcastLabel}>⊕ {multiSelect.size}</span>
          <input
            className="k-input"
            style={{ flex: 1, fontSize: 11, padding: '3px 6px' }}
            value={bcCmd}
            onChange={e => setBcCmd(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && bcCmd.trim()) {
                const [cmd, ...rest] = bcCmd.trim().split(/\s+/)
                broadcastTask(cmd, rest.join(' '))
                setBcCmd('')
                clearMultiSelect()
              }
              if (e.key === 'Escape') clearMultiSelect()
            }}
            placeholder="cmd args..."
            autoFocus
          />
          <button onClick={() => clearMultiSelect()} style={s.bcastClose} title="clear selection">✕</button>
        </div>
      )}
    </div>
  )
}

const s = {
  wrap: { display: 'flex', flexDirection: 'column', height: '100%', userSelect: 'none' },
  header: { display: 'flex', alignItems: 'center', gap: 6, padding: '9px 12px', borderBottom: '1px solid #1e1e1e', flexShrink: 0 },
  title: { fontSize: 10, color: '#888888', letterSpacing: 3, flex: 1 },
  count: { fontSize: 11, color: '#ff3131', fontFamily: 'inherit' },
  filters: { display: 'flex', gap: 2 },
  fBtn: { background: 'transparent', border: '1px solid', padding: '1px 6px', fontSize: 10, fontFamily: 'inherit', cursor: 'pointer', letterSpacing: 1 },
  colHead: { display: 'flex', alignItems: 'center', gap: 8, padding: '5px 10px 5px 12px', borderBottom: '1px solid #111111', flexShrink: 0 },
  col: { fontSize: 11, color: '#888888', letterSpacing: 2 },
  list: { flex: 1 },
  empty: { color: '#1e1e1e', fontSize: 11, textAlign: 'center', padding: '48px 12px', letterSpacing: 3 },
  row: { display: 'flex', alignItems: 'center', gap: 8, padding: '10px 10px 10px 12px', borderBottom: '1px solid #111111' },
  statusDot: { width: 7, height: 7, borderRadius: '50%', flexShrink: 0 },
  rowBody: { flex: 1, minWidth: 0 },
  rowTop: { display: 'flex', alignItems: 'center', marginBottom: 2 },
  agentId: { fontSize: 12, letterSpacing: .5, fontFamily: 'inherit' },
  rowSub: { fontSize: 10, color: '#888888', letterSpacing: .5, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' },
  ago: { fontSize: 10, color: '#888888', flexShrink: 0 },
  bcastBar: {
    display: 'flex', alignItems: 'center', gap: 4,
    padding: '6px 8px', borderTop: '1px solid #1a3a5c',
    background: '#0d1929', flexShrink: 0,
  },
  bcastLabel: { fontSize: 9, color: '#60a5fa', letterSpacing: 2, flexShrink: 0 },
  bcastClose: {
    background: 'transparent', border: 'none', color: '#555',
    cursor: 'pointer', fontSize: 13, padding: '0 3px', fontFamily: 'inherit',
  },
}
