import { useState, useEffect, useCallback } from 'react'
import useAgentStore, { API_BASE as API } from '../store/useAgentStore'

function genPassword(len = 20) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%&*'
  const arr = new Uint8Array(len)
  crypto.getRandomValues(arr)
  return Array.from(arr, b => chars[b % chars.length]).join('')
}

export default function Users() {
  const { token } = useAgentStore()
  const [users,    setUsers]    = useState([])
  const [licenses, setLicenses] = useState([])
  const [loading,  setLoading]  = useState(true)
  const [error,    setError]    = useState(null)
  const [adding,   setAdding]   = useState(false)
  const [newCreds, setNewCreds] = useState(null) // {username, password} shown once after creation
  const [copied,   setCopied]   = useState(null)
  const [form,     setForm]     = useState({
    username: '', password: '', role: 'operator', license_key: '',
  })

  const headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }

  const load = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      const [ru, rl] = await Promise.all([
        fetch(`${API}/auth/users`, { headers }),
        fetch(`${API}/phantom/licenses`, { headers }),
      ])
      if (!ru.ok) throw new Error((await ru.json()).detail || ru.statusText)
      setUsers(await ru.json())
      if (rl.ok) setLicenses(await rl.json())
    } catch (e) { setError(e.message) }
    finally     { setLoading(false) }
  }, [token])

  useEffect(() => { load() }, [load])

  const handleAdd = async e => {
    e.preventDefault()
    setAdding(true); setError(null); setNewCreds(null)
    try {
      const body = {
        username: form.username,
        password: form.password,
        role:     form.role,
      }
      if (form.role === 'client') body.license_key = form.license_key
      const r = await fetch(`${API}/auth/users`, {
        method: 'POST', headers, body: JSON.stringify(body),
      })
      if (!r.ok) throw new Error((await r.json()).detail || r.statusText)
      if (form.role === 'client') {
        setNewCreds({ username: form.username, password: form.password })
      }
      setForm({ username: '', password: '', role: 'operator', license_key: '' })
      load()
    } catch (e) { setError(e.message) }
    finally     { setAdding(false) }
  }

  const handleDelete = async username => {
    if (!confirm(`Delete user "${username}"?`)) return
    setError(null)
    try {
      const r = await fetch(`${API}/auth/users/${username}`, { method: 'DELETE', headers })
      if (r.status !== 204 && !r.ok) throw new Error((await r.json()).detail || r.statusText)
      if (newCreds?.username === username) setNewCreds(null)
      load()
    } catch (e) { setError(e.message) }
  }

  const copy = (text, key) => {
    navigator.clipboard.writeText(text)
    setCopied(key); setTimeout(() => setCopied(null), 1500)
  }

  const activeLicenses = licenses.filter(l => l.is_active && (l.max_builds == null || l.build_count < l.max_builds))
  const isClient = form.role === 'client'

  const roleColor = r => r === 'admin' ? '#f59e0b' : r === 'client' ? '#3fb950' : '#888'
  const cols = '1fr 80px 80px 120px 56px'

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '20px 24px' }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20 }}>
        <span style={{ fontSize: 9, color: '#ff3131', letterSpacing: 3 }}>ACCOUNTS</span>
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

      {/* One-time credential display */}
      {newCreds && (
        <div style={{ background: '#0d1f14', border: '1px solid #1a3d24', padding: '12px 14px', marginBottom: 16, maxWidth: 420 }}>
          <div style={{ fontSize: 9, color: '#3fb950', letterSpacing: 3, marginBottom: 8 }}>CLIENT CREATED — SAVE CREDENTIALS NOW</div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 6, alignItems: 'center' }}>
            <span style={{ fontSize: 10, color: '#555', width: 80, flexShrink: 0, letterSpacing: 1 }}>USERNAME</span>
            <span style={{ fontSize: 11, color: '#dde1e8', fontFamily: 'monospace', flex: 1 }}>{newCreds.username}</span>
            <button onClick={() => copy(newCreds.username, 'u')}
              style={{ background: 'transparent', border: 'none', color: copied === 'u' ? '#3fb950' : '#333', cursor: 'pointer', fontSize: 12 }}>
              {copied === 'u' ? '✓' : '⎘'}
            </button>
          </div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 10, alignItems: 'center' }}>
            <span style={{ fontSize: 10, color: '#555', width: 80, flexShrink: 0, letterSpacing: 1 }}>PASSWORD</span>
            <span style={{ fontSize: 11, color: '#dde1e8', fontFamily: 'monospace', flex: 1, wordBreak: 'break-all' }}>{newCreds.password}</span>
            <button onClick={() => copy(newCreds.password, 'p')}
              style={{ background: 'transparent', border: 'none', color: copied === 'p' ? '#3fb950' : '#333', cursor: 'pointer', fontSize: 12 }}>
              {copied === 'p' ? '✓' : '⎘'}
            </button>
          </div>
          <button onClick={() => setNewCreds(null)}
            style={{ background: 'transparent', border: '1px solid #1a3d24', color: '#3fb950', fontSize: 9, padding: '3px 10px', fontFamily: 'inherit', cursor: 'pointer', letterSpacing: 1 }}>
            DISMISS
          </button>
        </div>
      )}

      {/* Table header */}
      <div style={{ display: 'grid', gridTemplateColumns: cols, gap: 1, marginBottom: 4 }}>
        {['USERNAME', 'ROLE', 'STATUS', 'LICENSE', ''].map(h => (
          <div key={h} style={{ fontSize: 9, color: '#333', letterSpacing: 2, padding: '4px 8px' }}>{h}</div>
        ))}
      </div>

      {/* Rows */}
      {loading ? (
        <div style={{ color: '#444', fontSize: 11, padding: '12px 8px', letterSpacing: 1 }}>loading...</div>
      ) : users.length === 0 ? (
        <div style={{ color: '#333', fontSize: 11, padding: '12px 8px', letterSpacing: 1 }}>no accounts</div>
      ) : users.map(u => (
        <div key={u.username} className="hover-row"
          style={{ display: 'grid', gridTemplateColumns: cols, gap: 1, borderBottom: '1px solid #111' }}>
          <div style={{ padding: '9px 8px', fontSize: 12, color: '#dde1e8' }}>{u.username}</div>
          <div style={{ padding: '9px 8px', fontSize: 10, color: roleColor(u.role), letterSpacing: 1 }}>
            {u.role.toUpperCase()}
          </div>
          <div style={{ padding: '7px 8px', display: 'flex', alignItems: 'center' }}>
            <span className={`badge badge-${u.is_active ? 'green' : 'gray'}`} style={{ fontSize: 9 }}>
              {u.is_active ? 'ACTIVE' : 'OFF'}
            </span>
          </div>
          <div style={{ padding: '9px 8px', fontSize: 10, color: '#444', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {u.license_key || <span style={{ color: '#222' }}>—</span>}
          </div>
          <div style={{ padding: '6px 8px', display: 'flex', alignItems: 'center' }}>
            <button onClick={() => handleDelete(u.username)}
              style={{ background: 'transparent', border: '1px solid #2d1818', color: '#f85149', fontSize: 9, padding: '3px 7px', fontFamily: 'inherit', cursor: 'pointer', letterSpacing: 1 }}>
              DEL
            </button>
          </div>
        </div>
      ))}

      {/* Divider */}
      <div style={{ borderTop: '1px solid #1e1e1e', margin: '24px 0 16px' }} />

      {/* Add form */}
      <div style={{ fontSize: 9, color: '#444', letterSpacing: 3, marginBottom: 12 }}>NEW ACCOUNT</div>
      <form onSubmit={handleAdd} style={{ display: 'flex', flexDirection: 'column', gap: 8, maxWidth: 340 }}>
        <input className="k-input" placeholder="username" autoComplete="off" required
          value={form.username} onChange={e => setForm(f => ({ ...f, username: e.target.value }))} />

        <div style={{ display: 'flex', gap: 6 }}>
          <input className="k-input" type="text" placeholder="password" autoComplete="new-password" required
            value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
            style={{ flex: 1 }} />
          <button type="button"
            onClick={() => setForm(f => ({ ...f, password: genPassword() }))}
            title="Auto-generate strong password"
            style={{ background: 'transparent', border: '1px solid #1e1e1e', color: '#555', fontSize: 9, padding: '0 10px', fontFamily: 'inherit', cursor: 'pointer', letterSpacing: 1, flexShrink: 0 }}>
            GEN
          </button>
        </div>

        <select className="k-input" value={form.role}
          onChange={e => setForm(f => ({ ...f, role: e.target.value, license_key: '' }))}>
          <option value="operator">operator</option>
          <option value="admin">admin</option>
          <option value="client">client (phantom portal)</option>
        </select>

        {/* License picker — only for client role */}
        {isClient && (
          <select className="k-input" required value={form.license_key}
            onChange={e => setForm(f => ({ ...f, license_key: e.target.value }))}>
            <option value="">— select license —</option>
            {activeLicenses.map(l => (
              <option key={l.key} value={l.key}>
                {l.key}{l.label ? ` · ${l.label}` : ''} ({l.build_count}/{l.max_builds ?? '∞'})
              </option>
            ))}
            {activeLicenses.length === 0 && (
              <option disabled>no active licenses available</option>
            )}
          </select>
        )}

        <button type="submit" disabled={adding || (isClient && !form.license_key)}
          style={{ background: 'transparent', border: `1px solid ${isClient ? '#3fb950' : '#ff3131'}`, color: isClient ? '#3fb950' : '#ff3131', padding: '9px', fontFamily: 'inherit', fontSize: 10, letterSpacing: 3, cursor: 'pointer' }}>
          {adding ? '[ CREATING... ]' : isClient ? '[ CREATE CLIENT ]' : '[ ADD OPERATOR ]'}
        </button>
      </form>

    </div>
  )
}
