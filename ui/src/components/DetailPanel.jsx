import { useEffect, useState } from 'react'
import useAgentStore from '../store/useAgentStore'

function relTime(iso) {
  if (!iso) return '—'
  const s = Math.floor((Date.now() - new Date(iso + 'Z')) / 1000)
  if (s < 60)   return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  return `${Math.floor(s / 3600)}h ago`
}

function absTime(iso) {
  if (!iso) return '—'
  return new Date(iso + 'Z').toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' })
}

function Chip({ label, color = '#888888', bg = '#111111', border = '#1e1e1e' }) {
  return (
    <span style={{ fontSize: 11, color, background: bg, border: `1px solid ${border}`,
      padding: '2px 7px', letterSpacing: 1, display: 'inline-block' }}>
      {label}
    </span>
  )
}

function Row({ label, val, mono = true, accent }) {
  return (
    <div style={{ display: 'flex', gap: 10, padding: '5px 0', borderBottom: '1px solid #111111' }}>
      <span style={{ fontSize: 9, color: '#888888', letterSpacing: 2, minWidth: 44, flexShrink: 0, paddingTop: 3, textTransform: 'uppercase' }}>
        {label}
      </span>
      <span style={{ fontSize: 12, color: accent || '#dde1e8', wordBreak: 'break-all',
        lineHeight: 1.5, fontFamily: mono ? 'inherit' : 'sans-serif' }}>
        {val || '—'}
      </span>
    </div>
  )
}

export default function DetailPanel({ visible, width = 240, onOpenTerminal, onOpenFiles, onOpenTasks }) {
  const { selectedAgent: a, openConsoleTab, taskHistory, fetchTasks, patchAgent } = useAgentStore()
  const [tagInput, setTagInput] = useState('')
  const [editingTags, setEditingTags] = useState(false)

  useEffect(() => {
    if (a?.agent_id) fetchTasks(a.agent_id)
  }, [a?.agent_id])

  /* sync tag input when agent changes */
  useEffect(() => {
    setTagInput(a?.tags || '')
    setEditingTags(false)
  }, [a?.agent_id])

  const saveTags = async () => {
    if (!a) return
    await patchAgent(a.agent_id, { tags: tagInput })
    setEditingTags(false)
  }

  const tagList = (a?.tags || '').split(',').map(t => t.trim()).filter(Boolean)

  if (!visible) return null

  return (
    <aside style={{ ...s.panel, width, minWidth: width }}>
      <div style={s.header}>
        <span style={s.title}>AGENT DETAIL</span>
      </div>

      {!a ? (
        <div style={s.empty}>
          <span style={{ fontSize: 22, display: 'block', marginBottom: 8, opacity: .15 }}>⊡</span>
          NO SESSION SELECTED
        </div>
      ) : (
        <div className="scroll" style={s.body}>



          {/* Identity */}
          <Section title="IDENTITY">
            <Row label="ID"   val={a.agent_id} accent="#ff3131" />
            <Row label="IP"   val={a.ip || '—'} accent="#4fc3f7" />
            <Row label="HOST" val={a.hostname} />
            <Row label="USER" val={a.username} />
            <Row label="OS"   val={a.os_info} />
            <Row label="PRIV" val={a.privileges?.toUpperCase()}
              accent={a.privileges === 'elevated' ? '#f85149' : '#888888'} />
          </Section>

          {/* Timing */}
          <Section title="TIMING">
            <Row label="SEEN"  val={relTime(a.last_seen)} />
            <Row label="FIRST" val={absTime(a.first_seen)} />
          </Section>

          {/* Tags */}
          <Section title="TAGS">
            {editingTags ? (
              <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                <input
                  className="k-input"
                  style={{ flex: 1, fontSize: 11, padding: '4px 6px' }}
                  value={tagInput}
                  onChange={e => setTagInput(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter') saveTags(); if (e.key === 'Escape') setEditingTags(false) }}
                  placeholder="red-team, dc01, prod"
                  autoFocus
                />
                <button onClick={saveTags}
                  style={{ background: '#0d1f14', border: '1px solid #1a3d24', color: '#3fb950',
                    fontSize: 10, padding: '4px 8px', fontFamily: 'inherit', cursor: 'pointer' }}>✓</button>
                <button onClick={() => setEditingTags(false)}
                  style={{ background: 'transparent', border: '1px solid #1e1e1e', color: '#888888',
                    fontSize: 10, padding: '4px 8px', fontFamily: 'inherit', cursor: 'pointer' }}>✕</button>
              </div>
            ) : (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, alignItems: 'center' }}>
                {tagList.length === 0 && (
                  <span style={{ fontSize: 10, color: '#333', letterSpacing: 1 }}>no tags</span>
                )}
                {tagList.map(tag => (
                  <span key={tag} style={{ fontSize: 10, color: '#60a5fa', background: '#0d1929',
                    border: '1px solid #1a3a5c', padding: '1px 6px', letterSpacing: .5 }}>
                    {tag}
                  </span>
                ))}
                <button onClick={() => setEditingTags(true)}
                  style={{ background: 'transparent', border: '1px solid #1e1e1e', color: '#555',
                    fontSize: 9, padding: '1px 5px', fontFamily: 'inherit', cursor: 'pointer', marginLeft: 2 }}>
                  + EDIT
                </button>
              </div>
            )}
          </Section>

          {/* Last tasks */}
          <Section title="LAST TASKS">
            {taskHistory.length === 0 ? (
              <p style={{ fontSize: 10, color: '#333', letterSpacing: 2, padding: '6px 0' }}>NO TASKS YET</p>
            ) : taskHistory.slice(0, 4).map((t, i) => (
              <div key={t.task_id || i} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 0', borderBottom: '1px solid #111' }}>
                <span style={{
                  fontSize: 9, padding: '1px 5px', letterSpacing: 1, flexShrink: 0,
                  color: t.status === 'acked' ? '#3fb950' : t.status === 'pending' ? '#f59e0b' : '#888888',
                  background: t.status === 'acked' ? '#0d1f14' : t.status === 'pending' ? '#231a0a' : '#111',
                  border: `1px solid ${t.status === 'acked' ? '#1a3d24' : t.status === 'pending' ? '#4a3412' : '#1e1e1e'}`,
                }}>{t.status?.toUpperCase() || '?'}</span>
                <span style={{ fontSize: 11, color: '#dde1e8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{t.cmd}</span>
              </div>
            ))}
          </Section>

        </div>
      )}
    </aside>
  )
}

function Section({ title, children }) {
  return (
    <div style={{ padding: '30px 14px 30px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 13 }}>
        <span style={{ width: 2, height: 9, background: '#ff3131', flexShrink: 0, display: 'inline-block', opacity: .7 }} />
        <span style={{ fontSize: 9, color: '#888888', letterSpacing: 4 }}>{title}</span>
      </div>
      {children}
    </div>
  )
}

const s = {
  panel: {
    width: 240, flexShrink: 0,
    background: '#0a0a0a', borderLeft: '1px solid #1e1e1e',
    display: 'flex', flexDirection: 'column', overflow: 'hidden',
  },
  header: {
    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    padding: '9px 14px', borderBottom: '1px solid #1e1e1e', flexShrink: 0,
  },
  title: { fontSize: 10, color: '#888888', letterSpacing: 3 },
  body:  { flex: 1 },
  empty: {
    flex: 1, display: 'flex', flexDirection: 'column',
    alignItems: 'center', justifyContent: 'center',
    color: '#1e1e1e', fontSize: 11, letterSpacing: 3, textAlign: 'center',
    padding: '40px 16px',
  },
}
