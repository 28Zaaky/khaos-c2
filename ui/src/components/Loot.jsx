import { useEffect, useState, useCallback } from 'react'
import useAgentStore, { API_BASE } from '../store/useAgentStore'

const CMD_META = {
  hashdump:    { cat: 'HASHES',   color: '#f59e0b', bg: '#231a0a' },
  lsassdump:   { cat: 'HASHES',   color: '#f59e0b', bg: '#231a0a' },
  steal_token: { cat: 'TOKENS',   color: '#8b5cf6', bg: '#1a1228' },
  make_token:  { cat: 'TOKENS',   color: '#8b5cf6', bg: '#1a1228' },
  getsystem:   { cat: 'PRIVESC',  color: '#ff3131', bg: '#2a1414' },
  uacbypass:   { cat: 'PRIVESC',  color: '#ff3131', bg: '#2a1414' },
  lpe_check:   { cat: 'PRIVESC',  color: '#ff3131', bg: '#2a1414' },
  privesc:     { cat: 'PRIVESC',  color: '#ff3131', bg: '#2a1414' },
  download:    { cat: 'FILES',    color: '#3fb950', bg: '#0d1f14' },
  kerberos:    { cat: 'KERBEROS', color: '#06b6d4', bg: '#0a1f26' },
  kerberoast:  { cat: 'KERBEROS', color: '#06b6d4', bg: '#0a1f26' },
  asreproast:  { cat: 'KERBEROS', color: '#06b6d4', bg: '#0a1f26' },
}

const CATS = ['ALL', 'HASHES', 'TOKENS', 'FILES', 'KERBEROS', 'PRIVESC']

function fmt(iso) {
  if (!iso) return '—'
  return new Date(iso + 'Z').toLocaleString('fr-FR', { hour12: false })
}

function parseNtlm(output) {
  const lines = output.split('\n').filter(l => l.includes(':'))
  return lines.filter(l => /^[^:]+:[0-9]+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}/.test(l))
}

export default function Loot({ agentId }) {
  const { token } = useAgentStore()
  const [items,       setItems]       = useState([])
  const [loading,     setLoading]     = useState(true)
  const [catFilter,   setCatFilter]   = useState('ALL')
  const [expandedId,  setExpandedId]  = useState(null)
  const [copied,      setCopied]      = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const r = await fetch(`${API_BASE}/loot?agent_id=${agentId}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (r.ok) setItems(await r.json())
    } finally {
      setLoading(false)
    }
  }, [token, agentId])

  useEffect(() => { load() }, [load])

  const filtered = catFilter === 'ALL'
    ? items
    : items.filter(it => (CMD_META[it.cmd]?.cat ?? 'OTHER') === catFilter)

  const copy = (text, id) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(id)
      setTimeout(() => setCopied(null), 1200)
    })
  }

  const cats = CATS.filter(c => {
    if (c === 'ALL') return true
    return items.some(it => (CMD_META[it.cmd]?.cat ?? 'OTHER') === c)
  })

  const exportMarkdown = () => {
    const ts = new Date().toISOString().replace('T', ' ').slice(0, 19)
    const lines = [`# KHAØS C2 — Loot Export`, `Generated: ${ts}  Agent: ${agentId || 'all'}`, '']
    const byCat = {}
    items.forEach(it => {
      const cat = CMD_META[it.cmd]?.cat ?? 'OTHER'
      if (!byCat[cat]) byCat[cat] = []
      byCat[cat].push(it)
    })
    Object.entries(byCat).forEach(([cat, its]) => {
      lines.push(`## ${cat}`, '')
      its.forEach(it => {
        lines.push(`### ${it.cmd} — ${fmt(it.acked_at)}`)
        if (it.args) lines.push(`**Args:** \`${it.args}\``, '')
        lines.push('```', it.output || '(empty)', '```', '')
      })
    })
    const blob = new Blob([lines.join('\n')], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `khaos-loot-${agentId || 'all'}-${Date.now()}.md`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div style={s.wrap}>
      {/* Header */}
      <div style={s.header}>
        <span style={s.title}>LOOT</span>
        {/* Category filter */}
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {cats.map(c => (
            <button
              key={c}
              onClick={() => setCatFilter(c)}
              style={{
                ...s.refreshBtn,
                color:       catFilter === c ? '#ff3131' : '#555',
                borderColor: catFilter === c ? '#ff313133' : '#1e1e1e',
              }}
            >
              {c}
            </button>
          ))}
        </div>
        <button onClick={exportMarkdown} style={{ ...s.refreshBtn, color: '#3fb950', borderColor: '#3fb95033', marginLeft: 'auto' }} title="Export Markdown report">
          EXPORT
        </button>
        <button onClick={load} style={s.refreshBtn}>REFRESH</button>
      </div>

      {/* List */}
      <div className="scroll" style={{ flex: 1 }}>
        {loading && <div style={s.msg}>loading...</div>}
        {!loading && filtered.length === 0 && (
          <div style={s.empty}>
            <span style={{ fontSize: 22, display: 'block', marginBottom: 8, opacity: .15 }}>⊡</span>
            NO LOOT
          </div>
        )}

        {filtered.map(item => {
          const meta = CMD_META[item.cmd] ?? { cat: 'OTHER', color: '#888', bg: '#111' }
          const expanded = expandedId === item.task_id
          const ntlm = (item.cmd === 'hashdump' || item.cmd === 'lsassdump') ? parseNtlm(item.output || '') : []

          return (
            <div key={item.task_id}>
              <div
                className="hover-row"
                onClick={() => setExpandedId(expanded ? null : item.task_id)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 10,
                  padding: '7px 14px', borderBottom: '1px solid #111',
                  borderLeft: `2px solid ${meta.color}22`,
                  background: expanded ? '#0d0d0d' : 'transparent',
                  cursor: 'pointer',
                }}
              >
                <span style={{ fontSize: 9, color: meta.color, background: meta.bg, padding: '2px 7px', letterSpacing: 1, minWidth: 70, textAlign: 'center' }}>
                  {meta.cat}
                </span>
                <span style={{ fontSize: 10, color: '#aaa', minWidth: 90, flexShrink: 0 }}>{item.cmd}</span>
                <span style={{ fontSize: 9, color: '#333', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {item.args || (item.output ? item.output.slice(0, 60) : '—')}
                </span>
                <span style={{ fontSize: 9, color: '#333', flexShrink: 0 }}>{fmt(item.acked_at)}</span>
                <span style={{ fontSize: 9, color: expanded ? '#ff3131' : '#333', flexShrink: 0 }}>{expanded ? '▲' : '▼'}</span>
              </div>

              {expanded && (
                <div style={{ background: '#060606', borderLeft: `2px solid ${meta.color}22`, padding: '10px 14px 10px 20px', borderBottom: '1px solid #111' }}>
                  {ntlm.length > 0 && (
                    <div style={{ marginBottom: 8 }}>
                      <div style={{ fontSize: 9, color: meta.color, letterSpacing: 2, marginBottom: 6 }}>
                        NTLM HASHES ({ntlm.length})
                        <button onClick={() => copy(ntlm.join('\n'), item.task_id + '_ntlm')} style={s.copyBtn}>
                          {copied === item.task_id + '_ntlm' ? 'COPIED' : 'COPY'}
                        </button>
                      </div>
                      <pre style={{ ...s.pre, color: meta.color + 'cc' }}>{ntlm.join('\n')}</pre>
                    </div>
                  )}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                    <span style={{ fontSize: 9, color: '#333', letterSpacing: 2 }}>RAW OUTPUT</span>
                    <button onClick={() => copy(item.output || '', item.task_id)} style={s.copyBtn}>
                      {copied === item.task_id ? 'COPIED' : 'COPY'}
                    </button>
                  </div>
                  <pre style={s.pre}>{item.output || '(empty)'}</pre>
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
  wrap:       { display: 'flex', flexDirection: 'column', height: '100%', background: '#0a0a0a' },
  header:     { display: 'flex', alignItems: 'center', gap: 8, padding: '8px 14px', borderBottom: '1px solid #1e1e1e', background: '#111111', flexShrink: 0, flexWrap: 'wrap' },
  title:      { fontSize: 11, color: '#888888', letterSpacing: 3, flex: 1 },
  count:      { fontSize: 10, color: '#888888' },
  refreshBtn: { background: 'transparent', border: '1px solid #1e1e1e', color: '#888', fontSize: 9, padding: '3px 8px', fontFamily: 'inherit', cursor: 'pointer', letterSpacing: 1 },
  msg:        { color: '#444', fontSize: 11, letterSpacing: 1, padding: 12 },
  empty:      { color: '#1e1e1e', fontSize: 11, textAlign: 'center', padding: '64px 12px', letterSpacing: 3 },
  pre:        { color: '#dde1e8', fontSize: 11, fontFamily: 'inherit', whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0, maxHeight: 280, overflow: 'auto' },
  copyBtn:    { background: 'transparent', border: '1px solid #1e1e1e', color: '#555', fontSize: 9, padding: '1px 6px', fontFamily: 'inherit', cursor: 'pointer', letterSpacing: 1, marginLeft: 8 },
}
