import { useState, useEffect, useCallback } from 'react'
import useAgentStore, { API_BASE as API } from '../store/useAgentStore'

export default function Licenses() {
  const { token } = useAgentStore()
  const [licenses, setLicenses] = useState([])
  const [loading,  setLoading]  = useState(true)
  const [error,    setError]    = useState(null)
  const [adding,   setAdding]   = useState(false)
  const [copied,   setCopied]   = useState(null)
  const [form,     setForm]     = useState({ label: '', max_builds: '', expires_at: '' })

  const headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }

  const load = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      const r = await fetch(`${API}/phantom/licenses`, { headers })
      if (!r.ok) throw new Error((await r.json()).detail || r.statusText)
      setLicenses(await r.json())
    } catch (e) { setError(e.message) }
    finally     { setLoading(false) }
  }, [token])

  useEffect(() => { load() }, [load])

  const handleAdd = async e => {
    e.preventDefault()
    setAdding(true); setError(null)
    try {
      const body = { label: form.label }
      if (form.max_builds) body.max_builds = Number(form.max_builds)
      if (form.expires_at) body.expires_at  = new Date(form.expires_at).toISOString()
      const r = await fetch(`${API}/phantom/licenses`, {
        method: 'POST', headers, body: JSON.stringify(body),
      })
      if (!r.ok) throw new Error((await r.json()).detail || r.statusText)
      setForm({ label: '', max_builds: '', expires_at: '' })
      load()
    } catch (e) { setError(e.message) }
    finally     { setAdding(false) }
  }

  const handleRevoke = async key => {
    if (!confirm(`Revoke license ${key}?`)) return
    setError(null)
    try {
      const r = await fetch(`${API}/phantom/licenses/${key}`, { method: 'DELETE', headers })
      if (r.status !== 204 && !r.ok) throw new Error((await r.json()).detail || r.statusText)
      load()
    } catch (e) { setError(e.message) }
  }

  const copyKey = key => {
    navigator.clipboard.writeText(key)
    setCopied(key)
    setTimeout(() => setCopied(null), 1500)
  }

  const fmtDate = iso => {
    if (!iso) return '—'
    return new Date(iso).toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit', year: '2-digit' })
  }

  const fmtBuilds = lic => {
    const used = lic.build_count
    const max  = lic.max_builds
    if (max == null) return `${used} / ∞`
    return `${used} / ${max}`
  }

  const cols = '160px 1fr 72px 72px 80px 60px'

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '20px 24px' }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20 }}>
        <span style={{ fontSize: 9, color: '#3fb950', letterSpacing: 3 }}>PHANTOM LICENSES</span>
        <div style={{ flex: 1, height: 1, background: '#1e1e1e' }} />
        <button onClick={load}
          style={{ background: 'transparent', border: '1px solid #1e1e1e', color: '#888', fontSize: 9, padding: '3px 8px', fontFamily: 'inherit', cursor: 'pointer', letterSpacing: 1 }}>
          REFRESH
        </button>
      </div>

      {error && (
        <p style={{ color: '#f85149', fontSize: 10, letterSpacing: 1, marginBottom: 12 }}>
          // {error.toUpperCase()} //
        </p>
      )}

      {/* Table header */}
      <div style={{ display: 'grid', gridTemplateColumns: cols, gap: 1, marginBottom: 4 }}>
        {['KEY', 'LABEL', 'STATUS', 'BUILDS', 'EXPIRES', ''].map(h => (
          <div key={h} style={{ fontSize: 9, color: '#333', letterSpacing: 2, padding: '4px 8px' }}>{h}</div>
        ))}
      </div>

      {/* Rows */}
      {loading ? (
        <div style={{ color: '#444', fontSize: 11, padding: '12px 8px', letterSpacing: 1 }}>loading...</div>
      ) : licenses.length === 0 ? (
        <div style={{ color: '#333', fontSize: 11, padding: '12px 8px', letterSpacing: 1 }}>no licenses</div>
      ) : licenses.map(lic => {
        const isRevoked  = !lic.is_active
        const isExhausted = lic.max_builds != null && lic.build_count >= lic.max_builds
        const isExpired  = lic.expires_at && new Date(lic.expires_at) < new Date()
        const dead = isRevoked || isExhausted || isExpired

        return (
          <div key={lic.key} className="hover-row"
            style={{ display: 'grid', gridTemplateColumns: cols, gap: 1, borderBottom: '1px solid #111', opacity: dead ? 0.45 : 1 }}>

            {/* KEY — copyable */}
            <div style={{ padding: '8px 8px', display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ fontSize: 10, fontFamily: 'monospace', color: dead ? '#444' : '#dde1e8', letterSpacing: 0.5 }}>
                {lic.key}
              </span>
              <button onClick={() => copyKey(lic.key)} title="Copy key"
                style={{ background: 'transparent', border: 'none', color: copied === lic.key ? '#3fb950' : '#333', cursor: 'pointer', fontSize: 11, padding: '0 2px', lineHeight: 1, flexShrink: 0 }}>
                {copied === lic.key ? '✓' : '⎘'}
              </button>
            </div>

            {/* LABEL */}
            <div style={{ padding: '8px 8px', fontSize: 11, color: '#888', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {lic.label || <span style={{ color: '#2a2a2a' }}>—</span>}
            </div>

            {/* STATUS */}
            <div style={{ padding: '6px 8px', display: 'flex', alignItems: 'center' }}>
              <span className={`badge badge-${dead ? 'red' : 'green'}`} style={{ fontSize: 8 }}>
                {isRevoked ? 'REVOKED' : isExhausted ? 'SPENT' : isExpired ? 'EXPIRED' : 'ACTIVE'}
              </span>
            </div>

            {/* BUILDS */}
            <div style={{ padding: '8px 8px', fontSize: 10, color: isExhausted ? '#f85149' : '#888', fontFamily: 'monospace' }}>
              {fmtBuilds(lic)}
            </div>

            {/* EXPIRES */}
            <div style={{ padding: '8px 8px', fontSize: 10, color: isExpired ? '#f85149' : '#555', fontFamily: 'monospace' }}>
              {fmtDate(lic.expires_at)}
            </div>

            {/* REVOKE */}
            <div style={{ padding: '6px 8px', display: 'flex', alignItems: 'center' }}>
              {!isRevoked && (
                <button onClick={() => handleRevoke(lic.key)}
                  style={{ background: 'transparent', border: '1px solid #2d1818', color: '#f85149', fontSize: 9, padding: '3px 7px', fontFamily: 'inherit', cursor: 'pointer', letterSpacing: 1 }}>
                  REV
                </button>
              )}
            </div>
          </div>
        )
      })}

      {/* Divider */}
      <div style={{ borderTop: '1px solid #1e1e1e', margin: '24px 0 16px' }} />

      {/* Create form */}
      <div style={{ fontSize: 9, color: '#444', letterSpacing: 3, marginBottom: 12 }}>NEW LICENSE</div>
      <form onSubmit={handleAdd} style={{ display: 'flex', flexDirection: 'column', gap: 8, maxWidth: 340 }}>
        <input className="k-input" placeholder="Label (client name, ref…)" autoComplete="off"
          value={form.label} onChange={e => setForm(f => ({ ...f, label: e.target.value }))} />
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          <input className="k-input" type="number" min={1} placeholder="Max builds (blank = ∞)"
            value={form.max_builds} onChange={e => setForm(f => ({ ...f, max_builds: e.target.value }))} />
          <input className="k-input" type="date" title="Expiry date (optional)"
            value={form.expires_at} onChange={e => setForm(f => ({ ...f, expires_at: e.target.value }))} />
        </div>
        <button type="submit" disabled={adding}
          style={{ background: 'transparent', border: '1px solid #3fb950', color: '#3fb950', padding: '9px', fontFamily: 'inherit', fontSize: 10, letterSpacing: 3, cursor: 'pointer' }}>
          {adding ? '[ GENERATING... ]' : '[ GENERATE LICENSE ]'}
        </button>
      </form>

    </div>
  )
}
