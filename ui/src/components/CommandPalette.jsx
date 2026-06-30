import { useState, useEffect, useRef, useMemo } from 'react'
import useAgentStore from '../store/useAgentStore'

const QUICK_CMDS = [
  { label: 'whoami',         cmd: 'shell',     args: 'whoami' },
  { label: 'hostname',       cmd: 'shell',     args: 'hostname' },
  { label: 'ipconfig /all',  cmd: 'shell',     args: 'ipconfig /all' },
  { label: 'systeminfo',     cmd: 'shell',     args: 'systeminfo' },
  { label: 'net user',       cmd: 'shell',     args: 'net user' },
  { label: 'tasklist',       cmd: 'shell',     args: 'tasklist' },
  { label: 'sysinfo',        cmd: 'sysinfo',   args: '' },
  { label: 'ps',             cmd: 'ps',        args: '' },
  { label: 'getuid',         cmd: 'getuid',    args: '' },
  { label: 'hashdump',       cmd: 'hashdump',  args: '' },
  { label: 'lsassdump',      cmd: 'lsassdump', args: '' },
  { label: 'privs list',     cmd: 'privs',     args: 'list' },
  { label: 'privs enable SeDebugPrivilege', cmd: 'privs', args: 'enable SeDebugPrivilege' },
  { label: 'privesc',        cmd: 'privesc',   args: '' },
  { label: 'getsystem',      cmd: 'getsystem', args: '' },
]

export default function CommandPalette({ onClose, onOpenTerminal, onRunCommand }) {
  const { agents, openConsoleTab } = useAgentStore()
  const [q, setQ]     = useState('')
  const [sel, setSel] = useState(0)
  const inputRef      = useRef(null)

  useEffect(() => {
    inputRef.current?.focus()
    const esc = e => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', esc)
    return () => window.removeEventListener('keydown', esc)
  }, [onClose])

  const results = useMemo(() => {
    const items = []
    const lq = q.toLowerCase()

    // Matching agents
    const matchAgents = agents.filter(a =>
      !lq ||
      a.agent_id.includes(lq) ||
      a.hostname?.toLowerCase().includes(lq) ||
      a.username?.toLowerCase().includes(lq)
    ).slice(0, 5)

    matchAgents.forEach(a => items.push({
      type:    'agent',
      label:   a.agent_id,
      sub:     `${a.hostname} · ${a.username}`,
      online:  a.is_active,
      agent:   a,
    }))

    // Quick commands (if no query or query matches)
    QUICK_CMDS.filter(c => !lq || c.label.includes(lq)).slice(0, 6).forEach(c =>
      items.push({ type: 'cmd', label: c.label, cmd: c.cmd, args: c.args })
    )

    return items
  }, [q, agents])

  useEffect(() => setSel(0), [q])

  const exec = (item) => {
    if (item.type === 'agent') {
      openConsoleTab(item.agent)
      onOpenTerminal?.()
    } else {
      onRunCommand?.(item)
    }
    onClose()
  }

  const onKey = (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setSel(s => Math.min(s + 1, results.length - 1)) }
    if (e.key === 'ArrowUp')   { e.preventDefault(); setSel(s => Math.max(s - 1, 0)) }
    if (e.key === 'Enter' && results[sel]) exec(results[sel])
  }

  return (
    <div style={s.overlay} onMouseDown={onClose}>
      <div style={s.box} onMouseDown={e => e.stopPropagation()}>
        {/* Input */}
        <div style={s.inputRow}>
          <span style={s.searchIcon}>⌨</span>
          <input
            ref={inputRef}
            style={s.input}
            placeholder="Search agent, run command..."
            value={q}
            onChange={e => setQ(e.target.value)}
            onKeyDown={onKey}
          />
          {q && (
            <button style={s.clearBtn} onClick={() => setQ('')}>✕</button>
          )}
        </div>

        {/* Results */}
        <div style={s.results}>
          {results.length === 0 && (
            <p style={s.empty}>No results</p>
          )}

          {/* Group: agents */}
          {results.some(r => r.type === 'agent') && (
            <div style={s.groupLabel}>SESSIONS</div>
          )}
          {results.filter(r => r.type === 'agent').map((item, i) => (
            <ResultRow key={item.agent.agent_id} item={item}
              active={results.indexOf(item) === sel}
              onClick={() => exec(item)}
              onHover={() => setSel(results.indexOf(item))} />
          ))}

          {/* Group: commands */}
          {results.some(r => r.type === 'cmd') && (
            <div style={s.groupLabel}>QUICK COMMANDS</div>
          )}
          {results.filter(r => r.type === 'cmd').map((item, i) => (
            <ResultRow key={item.label} item={item}
              active={results.indexOf(item) === sel}
              onClick={() => exec(item)}
              onHover={() => setSel(results.indexOf(item))} />
          ))}
        </div>

        {/* Footer */}
        <div style={s.footer}>
          <span style={s.hint}><kbd style={s.kbd}>↑↓</kbd> navigate</span>
          <span style={s.hint}><kbd style={s.kbd}>↵</kbd> select</span>
          <span style={s.hint}><kbd style={s.kbd}>esc</kbd> close</span>
        </div>
      </div>
    </div>
  )
}

function ResultRow({ item, active, onClick, onHover }) {
  return (
    <div
      onMouseEnter={onHover}
      onClick={onClick}
      style={{
        display: 'flex', alignItems: 'center', gap: 10,
        padding: '8px 14px', cursor: 'pointer',
        background: active ? '#1a0808' : 'transparent',
        borderLeft: `2px solid ${active ? '#ff3131' : 'transparent'}`,
        transition: 'background .08s',
      }}
    >
      {item.type === 'agent' ? (
        <>
          <span style={{ color: item.online ? '#3fb950' : '#888888', fontSize: 10 }}>
            {item.online ? '●' : '○'}
          </span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <p style={{ fontSize: 11, color: active ? '#ff3131' : '#dde1e8', letterSpacing: .5 }}>
              {item.label}
            </p>
            <p style={{ fontSize: 11, color: '#888888', marginTop: 1 }}>{item.sub}</p>
          </div>
          <span style={{ fontSize: 11, color: '#888888' }}>OPEN TERMINAL →</span>
        </>
      ) : (
        <>
          <span style={{ color: '#888888', fontSize: 11, minWidth: 16 }}>$</span>
          <p style={{ fontSize: 11, color: active ? '#dde1e8' : '#888888', flex: 1 }}>
            {item.label}
          </p>
          <span style={{ fontSize: 11, color: '#888888' }}>RUN →</span>
        </>
      )}
    </div>
  )
}

const s = {
  overlay: {
    position: 'fixed', inset: 0, zIndex: 1000,
    background: 'rgba(0,0,0,.7)', display: 'flex',
    alignItems: 'flex-start', justifyContent: 'center',
    paddingTop: '15vh',
  },
  box: {
    width: 560, background: '#111111',
    border: '1px solid #888888',
    boxShadow: '0 24px 64px rgba(0,0,0,.8)',
    display: 'flex', flexDirection: 'column',
    maxHeight: '60vh',
  },
  inputRow: {
    display: 'flex', alignItems: 'center', gap: 10,
    padding: '12px 14px', borderBottom: '1px solid #1e1e1e',
  },
  searchIcon: { color: '#888888', fontSize: 14, flexShrink: 0 },
  input: {
    flex: 1, background: 'transparent', border: 'none', outline: 'none',
    color: '#dde1e8', fontSize: 14, fontFamily: 'inherit', letterSpacing: .5,
  },
  clearBtn: {
    background: 'transparent', border: 'none', color: '#888888',
    cursor: 'pointer', fontSize: 11, padding: '2px 4px',
  },
  results:    { overflowY: 'auto', flex: 1, padding: '6px 0' },
  groupLabel: { fontSize: 8, color: '#888888', letterSpacing: 3, padding: '8px 14px 4px' },
  empty:      { fontSize: 11, color: '#888888', textAlign: 'center', padding: '24px', letterSpacing: 2 },
  footer: {
    display: 'flex', gap: 16, padding: '8px 14px',
    borderTop: '1px solid #1e1e1e', background: '#0a0a0a',
  },
  hint: { display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, color: '#888888' },
  kbd: {
    background: '#1e1e1e', border: '1px solid #888888',
    padding: '1px 5px', fontSize: 11, fontFamily: 'inherit', color: '#888888',
  },
}
