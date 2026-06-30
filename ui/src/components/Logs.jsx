import { useEffect, useState, useCallback } from 'react'
import useAgentStore, { API_BASE } from '../store/useAgentStore'

const LEVEL = {
  info:  { cls: 'badge-gray',   dot: '#888888' },
  warn:  { cls: 'badge-yellow', dot: '#d29922' },
  error: { cls: 'badge-red',    dot: '#f85149' },
}

function fmt(iso) {
  if (!iso) return '—'
  const d = new Date(iso + 'Z')
  return d.toLocaleTimeString('fr-FR', { hour12: false })
}

function parseTaskId(detail) {
  return detail?.match(/task_id=([a-f0-9-]{36})/)?.[1] ?? null
}

export default function Logs({ agentId }) {
  const { logs, fetchLogs, loadingLogs, token } = useAgentStore()
  const [lvlFilter,   setLvlFilter]   = useState('all')
  const [search,      setSearch]      = useState('')
  const [expandedId,  setExpandedId]  = useState(null)   // log.id
  const [taskCache,   setTaskCache]   = useState({})      // taskId → {output, loading, error}

  useEffect(() => {
    fetchLogs(agentId || null)
    const id = setInterval(() => fetchLogs(agentId || null), 8000)
    return () => clearInterval(id)
  }, [agentId])

  const fetchTask = useCallback(async (taskId) => {
    if (taskCache[taskId]) return
    setTaskCache(p => ({ ...p, [taskId]: { loading: true } }))
    try {
      const r = await fetch(`${API_BASE}/tasks/${taskId}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!r.ok) throw new Error(r.statusText)
      const data = await r.json()
      setTaskCache(p => ({ ...p, [taskId]: { output: data.output || '(empty)', loading: false } }))
    } catch (e) {
      setTaskCache(p => ({ ...p, [taskId]: { error: e.message, loading: false } }))
    }
  }, [token, taskCache])

  const toggleExpand = useCallback((log) => {
    if (log.event !== 'task_output') return
    const taskId = parseTaskId(log.detail)
    if (!taskId) return
    if (expandedId === log.id) {
      setExpandedId(null)
      return
    }
    setExpandedId(log.id)
    fetchTask(taskId)
  }, [expandedId, fetchTask])

  const filtered = logs.filter(l => {
    if (lvlFilter !== 'all' && l.level !== lvlFilter) return false
    if (search && !l.event?.includes(search) && !l.detail?.includes(search)) return false
    return true
  })

  return (
    <div style={s.wrap}>
      {/* Header */}
      <div style={s.header}>
        <span style={s.title}>AUDIT LOG</span>
        {agentId && <span className="badge badge-gray">{agentId}</span>}
        <span style={s.count}>{filtered.length} / {logs.length}</span>
        {loadingLogs && <span style={{ color: '#3fb950', fontSize: 8, animation: 'pulse 1s infinite' }}>●</span>}
        <div style={s.filters}>
          {['all','info','warn','error'].map(f => (
            <button key={f} onClick={() => setLvlFilter(f)}
              style={{ ...s.fBtn, color: lvlFilter===f ? '#ff3131' : '#888888', borderColor: lvlFilter===f ? '#ff149444' : 'transparent' }}>
              {f.toUpperCase()}
            </button>
          ))}
        </div>
        <input className="k-input" placeholder="search..."
          value={search} onChange={e => setSearch(e.target.value)}
          style={{ width: 140, fontSize: 10, padding: '3px 8px' }} />
      </div>

      {/* Column labels */}
      <div style={s.colHead}>
        <span style={{ ...s.col, minWidth: 64 }}>TIME</span>
        <span style={{ ...s.col, minWidth: 56 }}>LEVEL</span>
        <span style={{ ...s.col, minWidth: 80 }}>AGENT</span>
        <span style={{ ...s.col, minWidth: 140 }}>EVENT</span>
        <span style={{ ...s.col, flex: 1 }}>DETAIL</span>
      </div>

      {/* Rows */}
      <div className="scroll" style={s.body}>
        {filtered.length === 0 && (
          <div style={s.empty}>
            <span style={{ fontSize: 22, display: 'block', marginBottom: 8, opacity: .15 }}>≡</span>
            NO EVENTS
          </div>
        )}
        {filtered.map(log => {
          const lv       = LEVEL[log.level] || { cls: 'badge-gray', dot: '#888888' }
          const isOutput = log.event === 'task_output'
          const taskId   = isOutput ? parseTaskId(log.detail) : null
          const expanded = expandedId === log.id
          const cached   = taskId ? taskCache[taskId] : null

          return (
            <div key={log.id}>
              <div
                className="hover-row"
                onClick={() => toggleExpand(log)}
                style={{
                  ...s.row,
                  borderLeft: `2px solid ${lv.dot}22`,
                  cursor: isOutput ? 'pointer' : 'default',
                  background: expanded ? '#0d0d0d' : 'transparent',
                }}
              >
                <span style={s.ts}>{fmt(log.created_at)}</span>
                <span className={`badge ${lv.cls}`} style={{ minWidth: 44, justifyContent: 'center' }}>
                  {(log.level || '?').toUpperCase()}
                </span>
                <span style={s.agent}>{log.agent_id || '—'}</span>
                <span style={{ ...s.event, color: isOutput ? '#dde1e8' : '#888888' }}>{log.event}</span>
                <span style={s.detail}>{log.detail}</span>
                {isOutput && (
                  <span style={{ fontSize: 9, color: expanded ? '#ff3131' : '#333', flexShrink: 0, paddingLeft: 6 }}>
                    {expanded ? '▲' : '▼'}
                  </span>
                )}
              </div>

              {expanded && (
                <div style={s.expand}>
                  {cached?.loading && (
                    <span style={{ color: '#444', fontSize: 10 }}>loading...</span>
                  )}
                  {cached?.error && (
                    <span style={{ color: '#f85149', fontSize: 10 }}>// {cached.error} //</span>
                  )}
                  {cached?.output && !cached.loading && (
                    <pre style={s.pre}>{cached.output}</pre>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

const s = {
  wrap:   { display: 'flex', flexDirection: 'column', height: '100%', background: '#0a0a0a' },
  header: { display: 'flex', alignItems: 'center', gap: 8, padding: '8px 14px', borderBottom: '1px solid #1e1e1e', background: '#111111', flexShrink: 0, flexWrap: 'wrap' },
  title:  { fontSize: 11, color: '#888888', letterSpacing: 3, flex: 1 },
  count:  { fontSize: 10, color: '#888888' },
  filters:{ display: 'flex', gap: 2 },
  fBtn:   { background: 'transparent', border: '1px solid', padding: '1px 5px', fontSize: 10, fontFamily: 'inherit', cursor: 'pointer', letterSpacing: 1 },
  colHead:{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 14px', borderBottom: '1px solid #111111', flexShrink: 0 },
  col:    { fontSize: 11, color: '#888888', letterSpacing: 2 },
  body:   { flex: 1 },
  empty:  { color: '#1e1e1e', fontSize: 11, textAlign: 'center', padding: '64px 12px', letterSpacing: 3 },
  row:    { display: 'flex', alignItems: 'center', gap: 10, padding: '5px 14px', borderBottom: '1px solid #111111' },
  ts:     { color: '#888888', fontSize: 10, minWidth: 64, flexShrink: 0, letterSpacing: 1 },
  agent:  { color: '#888888', fontSize: 10, minWidth: 80, flexShrink: 0, opacity: .7 },
  event:  { fontSize: 10, minWidth: 140, flexShrink: 0, letterSpacing: .5 },
  detail: { color: '#888888', fontSize: 10, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' },
  expand: { background: '#060606', borderLeft: '2px solid #ff313122', padding: '10px 14px 10px 20px', borderBottom: '1px solid #111' },
  pre:    { color: '#dde1e8', fontSize: 11, fontFamily: 'inherit', whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0, maxHeight: 320, overflow: 'auto' },
}
