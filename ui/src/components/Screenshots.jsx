import { useEffect, useState, useCallback } from 'react'
import useAgentStore, { API_BASE } from '../store/useAgentStore'

function fmt(iso) {
  if (!iso) return '—'
  return new Date(iso + 'Z').toLocaleString('fr-FR', { hour12: false })
}

export default function Screenshots({ agentId }) {
  const { token } = useAgentStore()
  const [shots,    setShots]   = useState([])
  const [loading,  setLoading] = useState(true)
  const [lightbox, setLightbox] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const r = await fetch(`${API_BASE}/screenshots?limit=200&agent_id=${agentId}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (r.ok) setShots(await r.json())
    } finally {
      setLoading(false)
    }
  }, [token, agentId])

  useEffect(() => { load() }, [load])

  return (
    <div style={s.wrap}>
      {/* Header */}
      <div style={s.header}>
        <span style={s.title}>SCREENSHOTS</span>
        {/* <span style={{ fontSize: 9, color: '#555', letterSpacing: 1, background: '#111', border: '1px solid #1e1e1e', padding: '2px 8px' }}>
          {agentId.slice(0, 12)}
        </span> */}
        <span style={s.count}>{shots.length}</span>
        <button onClick={load} style={s.refreshBtn}>REFRESH</button>
      </div>

      {/* Grid */}
      <div className="scroll" style={{ flex: 1, padding: 16 }}>
        {loading && <div style={s.msg}>loading...</div>}
        {!loading && shots.length === 0 && (
          <div style={s.empty}>
            <span style={{ fontSize: 22, display: 'block', marginBottom: 8, opacity: .15 }}>⊡</span>
            NO SCREENSHOTS
          </div>
        )}
        {!loading && shots.length > 0 && (
          <div style={s.grid}>
            {shots.map(shot => (
              <div key={shot.task_id} onClick={() => setLightbox(shot)} style={s.card}
                onMouseEnter={e => e.currentTarget.style.borderColor = '#ff313155'}
                onMouseLeave={e => e.currentTarget.style.borderColor = '#1e1e1e'}>
                <div style={s.thumb}>
                  <img
                    src={`data:${shot.mime || 'image/png'};base64,${shot.output}`}
                    alt="screenshot"
                    style={{ width: '100%', height: '100%', objectFit: 'contain', display: 'block' }}
                  />
                </div>
                <div style={s.cardFoot}>
                  <span style={{ fontSize: 9, color: '#555', letterSpacing: 1 }}>{shot.agent_id}</span>
                  <span style={{ fontSize: 9, color: '#333', letterSpacing: 1 }}>{fmt(shot.acked_at)}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Lightbox */}
      {lightbox && (
        <div onClick={() => setLightbox(null)} style={s.lightbox}>
          <div style={{ fontSize: 10, color: '#555', letterSpacing: 2, marginBottom: 12 }}>
            {lightbox.agent_id} — {fmt(lightbox.acked_at)}
            <span style={{ marginLeft: 16, color: '#333' }}>[ click to close ]</span>
          </div>
          <img
            src={`data:${lightbox.mime || 'image/png'};base64,${lightbox.output}`}
            alt="screenshot"
            style={{ maxWidth: '90vw', maxHeight: '85vh', objectFit: 'contain', border: '1px solid #1e1e1e', display: 'block' }}
            onClick={e => e.stopPropagation()}
          />
        </div>
      )}
    </div>
  )
}

const s = {
  wrap:       { display: 'flex', flexDirection: 'column', height: '100%', background: '#0a0a0a' },
  header:     { display: 'flex', alignItems: 'center', gap: 8, padding: '8px 14px', borderBottom: '1px solid #1e1e1e', background: '#111111', flexShrink: 0 },
  title:      { fontSize: 11, color: '#888888', letterSpacing: 3, flex: 1 },
  count:      { fontSize: 10, color: '#888888' },
  refreshBtn: { background: 'transparent', border: '1px solid #1e1e1e', color: '#888', fontSize: 9, padding: '3px 8px', fontFamily: 'inherit', cursor: 'pointer', letterSpacing: 1 },
  msg:        { color: '#444', fontSize: 11, letterSpacing: 1, padding: 12 },
  empty:      { color: '#1e1e1e', fontSize: 11, textAlign: 'center', padding: '64px 12px', letterSpacing: 3 },
  grid:       { display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 },
  card:       { background: '#111', border: '1px solid #1e1e1e', cursor: 'pointer', transition: 'border-color .15s' },
  thumb:      { background: '#0a0a0a', overflow: 'hidden', height: 160 },
  cardFoot:   { padding: '6px 10px', borderTop: '1px solid #1e1e1e', display: 'flex', justifyContent: 'space-between', alignItems: 'center' },
  lightbox:   { position: 'fixed', inset: 0, background: 'rgba(0,0,0,.92)', zIndex: 1000, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', cursor: 'zoom-out' },
}
