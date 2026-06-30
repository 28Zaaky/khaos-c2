import { useState, useRef, useCallback } from 'react'
import useAgentStore from '../store/useAgentStore'

// Agent is considered offline if last_seen > OFFLINE_MS ms ago
const OFFLINE_MS = 15 * 60 * 1000 // 15 min

function agentIsOffline(agent) {
  if (!agent?.last_seen) return false
  return Date.now() - new Date(agent.last_seen + 'Z').getTime() > OFFLINE_MS
}

export default function FileManager({ agent }) {
  const { sendTask, fetchTasks } = useAgentStore()

  const [dlPath,   setDlPath]   = useState('')
  const [ulPath,   setUlPath]   = useState('')
  const [ulFile,   setUlFile]   = useState(null)
  const [result,   setResult]   = useState(null) // { ok, msg }
  const [busy,     setBusy]     = useState(false)
  const [xferMsg,  setXferMsg]  = useState('')
  const fileRef                  = useRef(null)
  const cancelRef                = useRef(false)

  const cancel = () => { cancelRef.current = true }

  const offline = agentIsOffline(agent)

  // Poll until task reaches terminal status (acked or error).
  // max=90 → 3 min (accounts for: exec time + beacon interval ~30s + jitter)
  const pollTask = useCallback((agentId, taskId, max = 90) =>
    new Promise(resolve => {
      let n = 0
      cancelRef.current = false
      const id = setInterval(async () => {
        if (cancelRef.current) { clearInterval(id); resolve(null); return }
        n++
        const tasks = await fetchTasks(agentId)
        const t = (tasks || []).find(t => t.task_id === taskId)
        if (t) {
          if (t.status === 'pending') setXferMsg('Waiting for agent pickup…')
          else if (t.status === 'sent') setXferMsg(`Sent — waiting for result… (${Math.round(n * 2)}s)`)
          if (t.status === 'acked' || t.status === 'error') { clearInterval(id); resolve(t); return }
        }
        if (n >= max) { clearInterval(id); resolve(null) }
      }, 2000)
    }), [fetchTasks])

  const download = async () => {
    if (!dlPath.trim()) return
    setResult(null); setBusy(true); setXferMsg('Queuing task…')
    try {
      const task = await sendTask(agent.agent_id, 'download', dlPath.trim())
      if (!task) { setResult({ ok: false, msg: 'task queue failed' }); return }
      if (offline) {
        setResult({ ok: null, msg: `queued [${task.task_id?.slice(0,8)}] — will run on next agent check-in` })
        return
      }
      const res = await pollTask(agent.agent_id, task.task_id)
      if (!res) { setResult({ ok: false, msg: 'timeout — no response from agent' }); return }
      if (res.status === 'error') { setResult({ ok: false, msg: res.output || 'agent error' }); return }
      // output format: line1=[task:id] [download] rc=0\nline2=[download] path:...\n<b64>
      const lines = (res.output || '').split('\n')
      if (lines[0]?.includes('rc=-1')) { setResult({ ok: false, msg: lines.slice(1).join('\n').trim() || 'agent error' }); return }
      const b64 = lines.slice(2).join('').trim()
      if (!b64) { setResult({ ok: false, msg: 'empty response' }); return }
      const raw   = atob(b64)
      const bytes = new Uint8Array([...raw].map(c => c.charCodeAt(0)))
      const url   = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }))
      const a     = document.createElement('a')
      a.href = url; a.download = dlPath.split(/[\\/]/).pop(); a.click()
      URL.revokeObjectURL(url)
      setResult({ ok: true, msg: `downloaded ${bytes.length} bytes` })
    } finally { setBusy(false); setXferMsg('') }
  }

  const upload = async () => {
    if (!ulPath.trim() || !ulFile) return
    setResult(null); setBusy(true); setXferMsg('Encoding file…')
    try {
      const b64  = await fileToB64(ulFile)
      setXferMsg('Sending to server…')
      const task = await sendTask(agent.agent_id, 'upload', ulPath.trim(), b64)
      if (!task) { setResult({ ok: false, msg: 'task queue failed' }); return }
      if (offline) {
        setResult({ ok: null, msg: `queued [${task.task_id?.slice(0,8)}] — will run on next agent check-in` })
        return
      }
      setXferMsg('Waiting for agent pickup…')
      const res = await pollTask(agent.agent_id, task.task_id)
      if (!res) {
        setResult({ ok: false, msg: cancelRef.current ? 'cancelled' : 'timeout — agent did not respond in time' })
        return
      }
      setResult(res.status === 'error'
        ? { ok: false, msg: res.output || 'agent error' }
        : { ok: true,  msg: res.output || 'ok' })
    } finally { setBusy(false); setXferMsg('') }
  }

  return (
    <div style={s.wrap}>
      {/* Header */}
      <div style={s.header}>
        <span style={s.title}>FILE TRANSFER</span>
        <span style={s.agent}>{agent.agent_id} · {agent.hostname}</span>
        {offline && (
          <span style={{ marginLeft: 'auto', fontSize: 9, letterSpacing: 2, color: '#f0a500', border: '1px solid #f0a500', padding: '2px 8px' }}>
            ⚠ OFFLINE
          </span>
        )}
      </div>

      <div style={s.body}>
        <div style={s.grid}>

          {/* ── Download ── */}
          <Section icon="▼" label="DOWNLOAD" sub="agent → operator">
            <div style={s.inputRow}>
              <InputField
                placeholder="C:\path\to\file.ext"
                value={dlPath}
                onChange={setDlPath}
                onEnter={download}
              />
              <Btn onClick={download} disabled={busy || !dlPath.trim()}>PULL</Btn>
            </div>
          </Section>

          {/* ── Upload ── */}
          <Section icon="▲" label="UPLOAD" sub="operator → agent">
            <div style={s.inputRow}>
              <InputField
                placeholder="C:\destination\path.ext"
                value={ulPath}
                onChange={setUlPath}
              />
            </div>
            <div style={{ ...s.inputRow, marginTop: 8 }}>
              <button className="k-btn" onClick={() => fileRef.current.click()}
                style={s.fileBtn}>
                <span style={{ color: '#888888', marginRight: 6 }}>⎘</span>
                {ulFile ? ulFile.name : 'CHOOSE FILE'}
              </button>
              <input ref={fileRef} type="file" style={{ display: 'none' }}
                onChange={e => setUlFile(e.target.files[0] || null)} />
              <Btn onClick={upload} disabled={busy || !ulPath.trim() || !ulFile}>PUSH</Btn>
            </div>
          </Section>

        </div>

        {/* ── Status ── */}
        {busy && (
          <div style={s.busyBar}>
            <span style={{ animation: 'blink 0.5s infinite', marginRight: 8, color: '#ff3131' }}>▮</span>
            <span style={{ flex: 1 }}>{xferMsg || 'TRANSFERRING…'}</span>
            <button onClick={cancel} style={{
              background: 'transparent', border: '1px solid #2a2a2a',
              color: '#666', fontFamily: 'inherit', fontSize: 9,
              letterSpacing: 2, cursor: 'pointer', padding: '3px 10px',
            }}>CANCEL</button>
          </div>
        )}

        {result && (
          <div style={{ ...s.resultBox, borderLeftColor: result.ok === true ? '#3fb950' : result.ok === null ? '#f0a500' : '#f85149' }}>
            <span style={{ color: result.ok === true ? '#3fb950' : result.ok === null ? '#f0a500' : '#f85149', marginRight: 8 }}>
              {result.ok === true ? '✓' : result.ok === null ? '⏳' : '✗'}
            </span>
            <pre style={{ ...s.resultPre, color: result.ok === true ? '#888888' : result.ok === null ? '#f0a500' : '#f85149' }}>
              {result.msg}
            </pre>
          </div>
        )}
      </div>
    </div>
  )
}

/* ── Sub-components ── */

function Section({ icon, label, sub, children }) {
  return (
    <div style={sc.wrap}>
      <div style={sc.head}>
        <span style={{ color: '#ff3131', marginRight: 8 }}>{icon}</span>
        <span style={sc.label}>{label}</span>
        <span style={sc.sub}>{sub}</span>
      </div>
      <div style={sc.body}>{children}</div>
    </div>
  )
}
const sc = {
  wrap:  { background: '#111111', border: '1px solid #1e1e1e' },
  head:  { display: 'flex', alignItems: 'center', padding: '8px 14px', borderBottom: '1px solid #1e1e1e' },
  label: { fontSize: 11, color: '#dde1e8', letterSpacing: 3 },
  sub:   { fontSize: 10, color: '#888888', letterSpacing: 2, marginLeft: 10 },
  body:  { padding: '14px' },
}

function InputField({ placeholder, value, onChange, onEnter }) {
  return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', background: '#0a0a0a', border: '1px solid #888888' }}>
      <span style={{ color: '#ff3131', padding: '0 8px', fontSize: 13, flexShrink: 0 }}>›</span>
      <input className="k-input"
        placeholder={placeholder} value={value}
        onChange={e => onChange(e.target.value)}
        onKeyDown={e => e.key === 'Enter' && onEnter?.()}
        style={{ border: 'none', flex: 1, padding: '7px 6px' }} />
    </div>
  )
}

function Btn({ children, onClick, disabled }) {
  return (
    <button className="k-btn k-btn-outline" onClick={onClick} disabled={disabled}
      style={{
        background: 'transparent', border: `1px solid ${disabled ? '#1e1e1e' : '#ff3131'}`,
        color: disabled ? '#888888' : '#ff3131', padding: '7px 20px',
        fontSize: 10, fontFamily: 'inherit', letterSpacing: 3,
        cursor: disabled ? 'not-allowed' : 'pointer', flexShrink: 0,
      }}>
      {children}
    </button>
  )
}

function fileToB64(file) {
  return new Promise((res, rej) => {
    const r = new FileReader()
    r.onload  = () => res(r.result.split(',')[1])
    r.onerror = rej
    r.readAsDataURL(file)
  })
}

const s = {
  wrap:   { display: 'flex', flexDirection: 'column', height: '100%', background: '#0a0a0a' },
  header: { display: 'flex', alignItems: 'center', gap: 12, padding: '8px 14px', borderBottom: '1px solid #1e1e1e', background: '#111111', flexShrink: 0 },
  title:  { fontSize: 11, color: '#888888', letterSpacing: 3, flex: 1 },
  agent:  { fontSize: 11, color: '#888888', letterSpacing: 1 },
  body:   { flex: 1, padding: '24px', overflowY: 'auto' },
  grid:   { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 },
  inputRow: { display: 'flex', gap: 8, alignItems: 'stretch' },
  fileBtn:{ flex: 1, background: '#0a0a0a', border: '1px solid #888888', padding: '7px 12px', color: '#888888', fontSize: 10, fontFamily: 'inherit', cursor: 'pointer', textAlign: 'left', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', letterSpacing: 1 },
  busyBar:{ display: 'flex', alignItems: 'center', color: '#888888', fontSize: 11, letterSpacing: 3, padding: '12px 0' },
  resultBox: { marginTop: 16, background: '#0a0a0a', border: '1px solid #1e1e1e', borderLeft: '2px solid', padding: '10px 14px', display: 'flex', alignItems: 'flex-start' },
  resultPre: { fontSize: 11, fontFamily: 'inherit', margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' },
}
