import { useEffect, useState } from 'react'
import useAgentStore from '../store/useAgentStore'

const TYPE_META = {
  cleartext: { label: 'CLEAR',  color: '#3fb950', bg: '#0d1f14', border: '#1a3d24' },
  hash:      { label: 'HASH',   color: '#f59e0b', bg: '#231a0a', border: '#4a3412' },
  token:     { label: 'TOKEN',  color: '#60a5fa', bg: '#0d1929', border: '#1a3a5c' },
  kerberos:  { label: 'KERB',   color: '#c084fc', bg: '#1a0d29', border: '#3d1a5c' },
}

function TypeBadge({ type }) {
  const m = TYPE_META[type] || { label: type?.toUpperCase(), color: '#888', bg: '#111', border: '#1e1e1e' }
  return (
    <span style={{ fontSize: 9, padding: '1px 5px', letterSpacing: 1.5, flexShrink: 0,
      color: m.color, background: m.bg, border: `1px solid ${m.border}` }}>
      {m.label}
    </span>
  )
}

function CopyBtn({ value, label = '⎘' }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    }).catch(() => {})
  }
  return (
    <button onClick={copy}
      style={{ background: 'transparent', border: '1px solid #1e1e1e', color: copied ? '#3fb950' : '#888888',
        fontSize: 10, padding: '2px 6px', fontFamily: 'inherit', cursor: 'pointer', transition: 'color .15s' }}>
      {copied ? '✓' : label}
    </button>
  )
}

export default function Creds() {
  const { creds, fetchCreds, deleteCred } = useAgentStore()
  const [filter, setFilter]   = useState('all')
  const [showSecret, setShowSecret] = useState({})
  const [deleting, setDeleting] = useState(null)

  useEffect(() => { fetchCreds() }, [])

  const filtered = filter === 'all' ? creds : creds.filter(c => c.cred_type === filter)

  const toggleSecret = (id) => setShowSecret(p => ({ ...p, [id]: !p[id] }))

  const handleDelete = async (credId) => {
    setDeleting(credId)
    await deleteCred(credId)
    setDeleting(null)
  }

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

      {/* Toolbar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 16px',
        borderBottom: '1px solid #1e1e1e', flexShrink: 0, background: '#0d0d0d' }}>
        <span style={{ fontSize: 10, color: '#888888', letterSpacing: 3, flex: 1 }}>
          CREDENTIALS
          <span style={{ color: '#ff3131', marginLeft: 10 }}>{filtered.length}</span>
        </span>
        {['all', 'cleartext', 'hash', 'token', 'kerberos'].map(f => {
          const m = f === 'all' ? null : TYPE_META[f]
          return (
            <button key={f} onClick={() => setFilter(f)}
              style={{
                background: filter === f ? (m?.bg || '#1e1e1e') : 'transparent',
                border: `1px solid ${filter === f ? (m?.border || '#888888') : '#1e1e1e'}`,
                color: filter === f ? (m?.color || '#dde1e8') : '#888888',
                fontSize: 9, padding: '3px 8px', fontFamily: 'inherit',
                cursor: 'pointer', letterSpacing: 1, transition: 'all .12s',
              }}>
              {f === 'all' ? 'ALL' : TYPE_META[f]?.label}
            </button>
          )
        })}
      </div>

      {/* Table header */}
      {filtered.length > 0 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '5px 16px',
          borderBottom: '1px solid #111', flexShrink: 0 }}>
          <span style={th}>TYPE</span>
          <span style={{ ...th, flex: 1 }}>USERNAME</span>
          <span style={{ ...th, flex: 1 }}>SECRET</span>
          <span style={{ ...th, flex: '0 0 100px' }}>HOST</span>
          <span style={{ ...th, flex: '0 0 80px' }}>AGENT</span>
          <span style={{ ...th, flex: '0 0 90px' }}>CAPTURED</span>
          <span style={{ width: 50, flexShrink: 0 }} />
        </div>
      )}

      {/* Rows */}
      <div className="scroll" style={{ flex: 1 }}>
        {filtered.length === 0 && (
          <div style={{ color: '#1e1e1e', fontSize: 11, textAlign: 'center', padding: '60px 0', letterSpacing: 3 }}>
            <span style={{ fontSize: 28, display: 'block', marginBottom: 12, opacity: .2 }}>🔑</span>
            NO CREDENTIALS SAVED
            <div style={{ fontSize: 10, color: '#1e1e1e', marginTop: 8, letterSpacing: 2 }}>
              use  savecred  in terminal
            </div>
          </div>
        )}

        {filtered.map(c => (
          <div key={c.cred_id} className="hover-row"
            style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '9px 16px',
              borderBottom: '1px solid #111', background: '#0a0a0a' }}>

            <div style={{ flexShrink: 0 }}>
              <TypeBadge type={c.cred_type} />
            </div>

            <div style={{ flex: 1, minWidth: 0, display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ fontSize: 12, color: '#dde1e8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {c.username || '—'}
              </span>
              <CopyBtn value={c.username} />
            </div>

            <div style={{ flex: 1, minWidth: 0, display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ fontSize: 11, color: '#888888', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                fontFamily: 'inherit', letterSpacing: showSecret[c.cred_id] ? 0 : 2 }}>
                {showSecret[c.cred_id] ? (c.secret || '—') : (c.secret ? '•'.repeat(Math.min(c.secret.length, 24)) : '—')}
              </span>
              {c.secret && (
                <>
                  <button onClick={() => toggleSecret(c.cred_id)}
                    style={{ background: 'transparent', border: '1px solid #1e1e1e', color: '#888888',
                      fontSize: 9, padding: '2px 5px', fontFamily: 'inherit', cursor: 'pointer' }}>
                    {showSecret[c.cred_id] ? 'HIDE' : 'SHOW'}
                  </button>
                  <CopyBtn value={c.secret} />
                </>
              )}
            </div>

            <span style={{ flex: '0 0 100px', fontSize: 11, color: '#888888', overflow: 'hidden',
              textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {c.host || '—'}
            </span>

            <span style={{ flex: '0 0 80px', fontSize: 11, color: '#ff3131', fontFamily: 'inherit',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {c.agent_id || '—'}
            </span>

            <span style={{ flex: '0 0 90px', fontSize: 10, color: '#555' }}>
              {c.captured_at ? new Date(c.captured_at + 'Z').toLocaleDateString('fr-FR') : '—'}
            </span>

            <button onClick={() => handleDelete(c.cred_id)} disabled={deleting === c.cred_id}
              style={{ width: 50, background: 'transparent', border: '1px solid #1e1e1e', color: '#f85149',
                fontSize: 10, padding: '3px 0', fontFamily: 'inherit', cursor: 'pointer', flexShrink: 0 }}>
              {deleting === c.cred_id ? '...' : '✕ DEL'}
            </button>

          </div>
        ))}
      </div>
    </div>
  )
}

const th = { fontSize: 9, color: '#555', letterSpacing: 2, flexShrink: 0 }
