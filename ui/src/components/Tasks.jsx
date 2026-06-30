import { useEffect, useState } from 'react'
import useAgentStore from '../store/useAgentStore'

const ST = {
  pending: { label: 'PENDING', cls: 'badge-yellow' },
  sent:    { label: 'SENT',    cls: 'badge-gray'   },
  acked:   { label: 'ACKED',   cls: 'badge-green'  },
  error:   { label: 'ERROR',   cls: 'badge-red'    },
}

function relTime(iso) {
  if (!iso) return '—'
  const ms = Date.now() - new Date(iso + 'Z').getTime()
  if (ms < 60000)   return `${Math.floor(ms/1000)}s ago`
  if (ms < 3600000) return `${Math.floor(ms/60000)}m ago`
  return `${Math.floor(ms/3600000)}h ago`
}

export default function Tasks({ agent }) {
  const { taskHistory, fetchTasks } = useAgentStore()
  const [expanded, setExpanded] = useState(new Set())
  const [filter, setFilter]     = useState('all')

  useEffect(() => {
    fetchTasks(agent.agent_id)
    const id = setInterval(() => fetchTasks(agent.agent_id), 30000)
    return () => clearInterval(id)
  }, [agent.agent_id])

  const toggle = id =>
    setExpanded(p => { const n = new Set(p); n.has(id) ? n.delete(id) : n.add(id); return n })

  const filtered = filter === 'all' ? taskHistory : taskHistory.filter(t => t.status === filter)

  return (
    <div style={s.wrap}>
      {/* Header */}
      <div style={s.header}>
        <span style={s.title}>TASK HISTORY</span>
        <span style={s.count}>{taskHistory.length}</span>
        <div style={s.filters}>
          {['all','pending','sent','acked','error'].map(f => (
            <button key={f} onClick={() => setFilter(f)}
              style={{ ...s.fBtn, color: filter===f ? '#ff3131' : '#888888', borderColor: filter===f ? '#ff149444' : 'transparent' }}>
              {f.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Column labels */}
      <div style={s.colHead}>
        <span style={{ ...s.col, minWidth: 72 }}>STATUS</span>
        <span style={{ ...s.col, minWidth: 60 }}>CMD</span>
        <span style={{ ...s.col, flex: 1 }}>ARGS</span>
        <span style={{ ...s.col, minWidth: 64, textAlign: 'right' }}>TIME</span>
        <span style={{ ...s.col, minWidth: 12 }} />
      </div>

      {/* Rows */}
      <div className="scroll" style={s.body}>
        {filtered.length === 0 && (
          <div style={s.empty}>
            <span style={{ fontSize: 22, display: 'block', marginBottom: 8, opacity: .15 }}>◈</span>
            NO TASKS
          </div>
        )}
        {filtered.map(t => {
          const st  = ST[t.status] || { label: t.status.toUpperCase(), cls: 'badge-gray' }
          const exp = expanded.has(t.task_id)
          return (
            <div key={t.task_id} style={s.taskWrap}>
              <div className={`hover-row${t.output ? ' clickable' : ''}`}
                style={s.row}
                onClick={() => t.output && toggle(t.task_id)}>
                <span className={`badge ${st.cls}`} style={{ minWidth: 64, justifyContent: 'center' }}>
                  {st.label}
                </span>
                <span style={s.cmd}>{t.cmd}</span>
                <span style={s.args}>{t.args || <span style={{ color: '#1e1e1e' }}>—</span>}</span>
                <span style={s.time}>{relTime(t.created_at)}</span>
                {t.output
                  ? <span style={s.chevron}>{exp ? '▾' : '▸'}</span>
                  : <span style={{ minWidth: 12 }} />}
              </div>

              {exp && t.output && (
                <div style={s.outputWrap}>
                  <div style={s.outputHeader}>
                    <span style={{ color: '#3fb950', fontSize: 11, letterSpacing: 2 }}>OUTPUT</span>
                    <span style={{ color: '#888888', fontSize: 9 }}>{t.task_id.slice(0,8)}</span>
                  </div>
                  <pre style={s.output}>{t.output}</pre>
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
  header: { display: 'flex', alignItems: 'center', gap: 8, padding: '8px 14px', borderBottom: '1px solid #1e1e1e', background: '#111111', flexShrink: 0 },
  title:  { fontSize: 11, color: '#888888', letterSpacing: 3, flex: 1 },
  count:  { fontSize: 11, color: '#ff3131' },
  filters:{ display: 'flex', gap: 2 },
  fBtn:   { background: 'transparent', border: '1px solid', padding: '1px 5px', fontSize: 10, fontFamily: 'inherit', cursor: 'pointer', letterSpacing: 1 },
  colHead:{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 14px', borderBottom: '1px solid #111111', flexShrink: 0 },
  col:    { fontSize: 11, color: '#888888', letterSpacing: 2 },
  body:   { flex: 1 },
  empty:  { color: '#1e1e1e', fontSize: 11, textAlign: 'center', padding: '64px 12px', letterSpacing: 3 },
  taskWrap: { borderBottom: '1px solid #111111' },
  row:    { display: 'flex', alignItems: 'center', gap: 10, padding: '8px 14px' },
  cmd:    { color: '#ff3131', fontSize: 10, minWidth: 64, flexShrink: 0, letterSpacing: .5 },
  args:   { color: '#dde1e8', fontSize: 11, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' },
  time:   { color: '#888888', fontSize: 11, minWidth: 64, textAlign: 'right', flexShrink: 0 },
  chevron:{ color: '#888888', fontSize: 10, minWidth: 12, textAlign: 'right', flexShrink: 0 },
  outputWrap: { margin: '0 14px 10px', background: '#0a0a0a', border: '1px solid #1e1e1e', borderLeft: '2px solid #3fb950' },
  outputHeader: { display: 'flex', justifyContent: 'space-between', padding: '4px 10px', borderBottom: '1px solid #111111' },
  output: { padding: '8px 10px', color: '#888888', fontSize: 11, lineHeight: 1.7, whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 320, overflowY: 'auto', fontFamily: 'inherit' },
}
