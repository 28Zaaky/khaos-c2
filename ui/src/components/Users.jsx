import { useState, useEffect, useCallback } from 'react'
import useAgentStore, { API_BASE as API } from '../store/useAgentStore'

export default function Users() {
  const { token } = useAgentStore()
  const [users,   setUsers]   = useState([])
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)
  const [form,    setForm]    = useState({ username: '', password: '', role: 'operator' })
  const [adding,  setAdding]  = useState(false)

  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`,
  }

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const r = await fetch(`${API}/auth/users`, { headers })
      if (!r.ok) throw new Error((await r.json()).detail || r.statusText)
      setUsers(await r.json())
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [token])

  useEffect(() => { load() }, [load])

  const handleAdd = async e => {
    e.preventDefault()
    setAdding(true)
    setError(null)
    try {
      const r = await fetch(`${API}/auth/users`, {
        method: 'POST', headers,
        body: JSON.stringify(form),
      })
      if (!r.ok) throw new Error((await r.json()).detail || r.statusText)
      setForm({ username: '', password: '', role: 'operator' })
      load()
    } catch (e) {
      setError(e.message)
    } finally {
      setAdding(false)
    }
  }

  const handleDelete = async username => {
    if (!confirm(`Delete operator "${username}"?`)) return
    setError(null)
    try {
      const r = await fetch(`${API}/auth/users/${username}`, { method: 'DELETE', headers })
      if (r.status !== 204 && !r.ok) throw new Error((await r.json()).detail || r.statusText)
      load()
    } catch (e) {
      setError(e.message)
    }
  }

  const cols = '1fr 90px 80px 56px'

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '20px 24px' }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20 }}>
        <span style={{ fontSize: 9, color: '#ff3131', letterSpacing: 3 }}>OPERATORS</span>
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
        {['USERNAME', 'ROLE', 'STATUS', ''].map(h => (
          <div key={h} style={{ fontSize: 9, color: '#333', letterSpacing: 2, padding: '4px 8px' }}>{h}</div>
        ))}
      </div>

      {/* Rows */}
      {loading ? (
        <div style={{ color: '#444', fontSize: 11, padding: '12px 8px', letterSpacing: 1 }}>loading...</div>
      ) : users.length === 0 ? (
        <div style={{ color: '#333', fontSize: 11, padding: '12px 8px', letterSpacing: 1 }}>no operators</div>
      ) : users.map(u => (
        <div key={u.username} className="hover-row"
          style={{ display: 'grid', gridTemplateColumns: cols, gap: 1, borderBottom: '1px solid #111111' }}>
          <div style={{ padding: '9px 8px', fontSize: 12, color: '#dde1e8' }}>{u.username}</div>
          <div style={{ padding: '9px 8px', fontSize: 10, color: u.role === 'admin' ? '#f59e0b' : '#888888', letterSpacing: 1 }}>
            {u.role.toUpperCase()}
          </div>
          <div style={{ padding: '7px 8px', display: 'flex', alignItems: 'center' }}>
            <span className={`badge badge-${u.is_active ? 'green' : 'gray'}`} style={{ fontSize: 9 }}>
              {u.is_active ? 'ACTIVE' : 'OFF'}
            </span>
          </div>
          <div style={{ padding: '6px 8px', display: 'flex', alignItems: 'center' }}>
            <button onClick={() => handleDelete(u.username)} title={`Delete ${u.username}`}
              style={{ background: 'transparent', border: '1px solid #2d1818', color: '#f85149', fontSize: 9, padding: '3px 7px', fontFamily: 'inherit', cursor: 'pointer', letterSpacing: 1 }}>
              DEL
            </button>
          </div>
        </div>
      ))}

      {/* Divider */}
      <div style={{ borderTop: '1px solid #1e1e1e', margin: '24px 0 16px' }} />

      {/* Add form */}
      <div style={{ fontSize: 9, color: '#444', letterSpacing: 3, marginBottom: 12 }}>ADD OPERATOR</div>
      <form onSubmit={handleAdd} style={{ display: 'flex', flexDirection: 'column', gap: 8, maxWidth: 300 }}>
        <input className="k-input" placeholder="username" autoComplete="off"
          value={form.username} onChange={e => setForm(f => ({ ...f, username: e.target.value }))} required />
        <input className="k-input" type="password" placeholder="password"
          value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))} required />
        <select className="k-input" value={form.role}
          onChange={e => setForm(f => ({ ...f, role: e.target.value }))}>
          <option value="operator">operator</option>
          <option value="admin">admin</option>
        </select>
        <button type="submit" disabled={adding} className="k-btn k-btn-outline"
          style={{ background: 'transparent', border: '1px solid #ff3131', color: '#ff3131', padding: '9px', fontFamily: 'inherit', fontSize: 10, letterSpacing: 3, cursor: 'pointer' }}>
          {adding ? '[ CREATING... ]' : '[ ADD OPERATOR ]'}
        </button>
      </form>

    </div>
  )
}
