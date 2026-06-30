import { useEffect, useState } from 'react'
import useAgentStore from '../store/useAgentStore'

const CFG = {
  success: { dot: '#3fb950', label: 'OK' },
  agent:   { dot: '#60a5fa', label: 'NEW' },
  info:    { dot: '#888888', label: 'INFO' },
  error:   { dot: '#f85149', label: 'ERR' },
}

function ToastItem({ toast }) {
  const { removeToast } = useAgentStore()
  const [show, setShow] = useState(false)

  useEffect(() => {
    requestAnimationFrame(() => setShow(true))
  }, [])

  const cfg = CFG[toast.type] || CFG.info
  const text = toast.agentId
    ? `${toast.agentId}  ${toast.text}`
    : toast.text

  return (
    <div
      onClick={() => removeToast(toast.id)}
      style={{
        display: 'flex', alignItems: 'center', gap: 7,
        padding: '4px 10px 4px 8px',
        background: 'rgba(14,14,14,0.92)',
        border: '1px solid #1e1e1e',
        backdropFilter: 'blur(4px)',
        cursor: 'pointer',
        transform: show ? 'translateY(0)' : 'translateY(10px)',
        opacity: show ? 1 : 0,
        transition: 'transform .18s ease, opacity .18s ease',
        whiteSpace: 'nowrap',
        maxWidth: 320,
        boxShadow: '0 2px 12px rgba(0,0,0,.4)',
      }}
    >
      <span style={{
        width: 5, height: 5, borderRadius: '50%', flexShrink: 0,
        background: cfg.dot, boxShadow: `0 0 6px ${cfg.dot}88`,
      }} />
      <span style={{ fontSize: 9, color: cfg.dot, letterSpacing: 2, flexShrink: 0 }}>
        {cfg.label}
      </span>
      <span style={{
        fontSize: 10, color: '#888888', letterSpacing: .5,
        overflow: 'hidden', textOverflow: 'ellipsis',
      }}>
        {text}
      </span>
    </div>
  )
}

export default function ToastContainer() {
  const { toasts } = useAgentStore()
  return (
    <div style={{
      position: 'fixed', bottom: 32, right: 12,
      zIndex: 9999,
      display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4,
      pointerEvents: 'none',
    }}>
      {toasts.map(t => (
        <div key={t.id} style={{ pointerEvents: 'auto' }}>
          <ToastItem toast={t} />
        </div>
      ))}
    </div>
  )
}
