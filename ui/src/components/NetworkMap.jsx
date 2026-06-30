import { useEffect, useState, useRef, useCallback } from 'react'
import useAgentStore, { API_BASE } from '../store/useAgentStore'

/* ── Layout ── */
const R    = 34
const HGAP = 220
const VGAP = 170

/* ── Privilege ── */
const PRIV = {
  SYSTEM:   { color: '#ff3131', glow: '#ff313188', badge: '★', ring: '#ff313133' },
  High:     { color: '#f59e0b', glow: '#f59e0b88', badge: '▲', ring: '#f59e0b33' },
  elevated: { color: '#f59e0b', glow: '#f59e0b88', badge: '▲', ring: '#f59e0b33' },
  Medium:   { color: '#3fb950', glow: '#3fb95088', badge: '●', ring: '#3fb95033' },
  user:     { color: '#3fb950', glow: '#3fb95088', badge: '●', ring: '#3fb95033' },
  Low:      { color: '#4a9eff', glow: '#4a9eff88', badge: '○', ring: '#4a9eff33' },
}
const getPriv = a => PRIV[a.privileges] ?? PRIV.user

/* ── Node type ── */
const getType = a => {
  const os = (a.os_info || '').toLowerCase()
  const h  = (a.hostname || '').toLowerCase()
  if (/\bdc\b|\bdomain/.test(h))                  return 'dc'
  if (/server/.test(os) || /srv|server/.test(h))  return 'server'
  return 'pc'
}

/* ── BFS layout ── */
function buildLayout(nodes, edges) {
  const childOf  = {}
  const parentOf = {}
  const ids = new Set(nodes.map(n => n.agent_id))
  nodes.forEach(n => { childOf[n.agent_id] = [] })
  edges.forEach(e => {
    if (ids.has(e.source) && ids.has(e.target)) {
      childOf[e.target].push(e.source)
      parentOf[e.source] = e.target
    }
  })
  const roots = nodes.filter(n => !parentOf[n.agent_id]).map(n => n.agent_id)
  const depth = {}
  const q = [...roots]
  roots.forEach(r => { depth[r] = 0 })
  while (q.length) {
    const id = q.shift()
    for (const c of childOf[id]) {
      if (depth[c] === undefined) { depth[c] = depth[id] + 1; q.push(c) }
    }
  }
  nodes.forEach(n => { if (depth[n.agent_id] === undefined) depth[n.agent_id] = 0 })
  const byLv = {}
  nodes.forEach(n => { const lv = depth[n.agent_id]; (byLv[lv] = byLv[lv] || []).push(n.agent_id) })
  const pos = {}
  Object.entries(byLv).forEach(([lv, grp]) => {
    const w = (grp.length - 1) * HGAP
    grp.forEach((id, i) => { pos[id] = { x: -w / 2 + i * HGAP, y: Number(lv) * VGAP } })
  })
  return pos
}

/* ─────────── Icons ─────────── */
function IconPC({ color, active }) {
  return (
    <g>
      <rect x="-15" y="-14" width="30" height="20" rx="2.5"
        fill="#070707" stroke={color} strokeWidth="1.3"/>
      <rect x="-13" y="-12" width="26" height="16" rx="1" fill={color} opacity="0.05"/>
      {[-7,-2,3].map(y => (
        <line key={y} x1="-12" y1={y} x2="12" y2={y}
          stroke={color} strokeWidth="0.7" opacity="0.14"/>
      ))}
      {active && (
        <circle cx="11" cy="-10" r="1.8" fill={color}>
          <animate attributeName="opacity" values="1;0.15;1" dur="1.2s" repeatCount="indefinite"/>
        </circle>
      )}
      <line x1="0" y1="6" x2="0" y2="11" stroke={color} strokeWidth="1.4"/>
      <line x1="-7" y1="11" x2="7" y2="11" stroke={color} strokeWidth="1.8"/>
    </g>
  )
}

function IconServer({ color }) {
  return (
    <g>
      <rect x="-14" y="-18" width="28" height="36" rx="2"
        fill="#070707" stroke={color} strokeWidth="1.3"/>
      {[-13,-6,1,8].map((y, i) => (
        <g key={i}>
          <rect x="-11" y={y} width="18" height="5" rx="0.7"
            fill={color} opacity="0.08" stroke={color} strokeWidth="0.4" opacity2="0.3"/>
          <circle cx="10" cy={y + 2.5} r="1.7" fill={color}>
            <animate attributeName="opacity"
              values="1;0.1;1" dur={`${0.7 + i * 0.22}s`} repeatCount="indefinite"/>
          </circle>
        </g>
      ))}
    </g>
  )
}

function IconDC({ color }) {
  return (
    <g>
      <path d="M0,-20 L15,-11 L15,7 Q15,18 0,22 Q-15,18 -15,7 L-15,-11 Z"
        fill="#070707" stroke={color} strokeWidth="1.3"/>
      <circle cx="0" cy="2" r="8" fill="none" stroke={color} strokeWidth="1" opacity="0.55"/>
      <text textAnchor="middle" dominantBaseline="middle" y="3"
        style={{ fontSize: '8px', fill: color, fontFamily: 'monospace', fontWeight: 700, letterSpacing: 1 }}>
        DC
      </text>
      <circle cx="0" cy="-14" r="3" fill="none" stroke={color} strokeWidth="0.8" opacity="0.4"/>
    </g>
  )
}

function NodeIcon({ type, color, active }) {
  if (type === 'server') return <IconServer color={color}/>
  if (type === 'dc')     return <IconDC     color={color}/>
  return <IconPC color={color} active={active}/>
}

/* ─────────── Edge with flowing packets ─────────── */
function FlowEdge({ x1, y1, x2, y2, active }) {
  const len = Math.max(1, Math.hypot(x2 - x1, y2 - y1))
  const dur  = `${Math.max(0.7, len / 110).toFixed(2)}s`
  const dur2 = `${Math.max(0.7, len / 110).toFixed(2)}s`

  return (
    <g>
      {/* Glow base */}
      {active && (
        <line x1={x1} y1={y1} x2={x2} y2={y2}
          stroke="#3fb950" strokeWidth="5" opacity="0.03"/>
      )}
      {/* Wire */}
      <line x1={x1} y1={y1} x2={x2} y2={y2}
        stroke={active ? '#0e2414' : '#111'} strokeWidth="1.5"/>
      {/* Packet 1 */}
      {active && (
        <line x1={x1} y1={y1} x2={x2} y2={y2}
          stroke="#3fb950" strokeWidth="2"
          strokeDasharray={`8 ${len}`}
          opacity="0.85">
          <animate attributeName="stroke-dashoffset"
            from={len + 8} to={0} dur={dur} repeatCount="indefinite"/>
        </line>
      )}
      {/* Packet 2 (offset) */}
      {active && len > 90 && (
        <line x1={x1} y1={y1} x2={x2} y2={y2}
          stroke="#3fb950" strokeWidth="1.5"
          strokeDasharray={`5 ${len}`}
          opacity="0.4">
          <animate attributeName="stroke-dashoffset"
            from={len + 5} to={0} dur={dur2}
            begin={`${(len / 110 * 0.45).toFixed(2)}s`}
            repeatCount="indefinite"/>
        </line>
      )}
    </g>
  )
}

/* ─────────── Main component ─────────── */
export default function NetworkMap() {
  const { token } = useAgentStore()
  const [graph,    setGraph]    = useState({ nodes: [], edges: [] })
  const [loading,  setLoading]  = useState(true)
  const [fetchErr, setFetchErr] = useState(null)
  const [selected, setSelected] = useState(null)
  const [pan,      setPan]      = useState({ x: 0, y: 0 })
  const [zoom,     setZoom]     = useState(1)
  const svgRef   = useRef(null)
  const panRef   = useRef(null)
  const panning  = useRef(false)

  const load = useCallback(async () => {
    setLoading(true); setFetchErr(null)
    try {
      const r = await fetch(`${API_BASE}/agents/graph`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (r.ok) {
        setGraph(await r.json())
      } else {
        const txt = await r.text().catch(() => r.statusText)
        setFetchErr(`${r.status} ${txt.slice(0, 120)}`)
      }
    } catch (e) {
      setFetchErr(e.message)
    } finally {
      setLoading(false)
    }
  }, [token])

  useEffect(() => { load() }, [load])

  const onMouseDown = useCallback(e => {
    if (e.button !== 0) return
    panning.current = true
    panRef.current  = { sx: e.clientX - pan.x, sy: e.clientY - pan.y }
  }, [pan])
  const onMouseMove = useCallback(e => {
    if (!panning.current) return
    setPan({ x: e.clientX - panRef.current.sx, y: e.clientY - panRef.current.sy })
  }, [])
  const onMouseUp = useCallback(() => { panning.current = false }, [])

  const onWheel = useCallback(e => {
    e.preventDefault()
    setZoom(z => Math.max(0.2, Math.min(4, z * (e.deltaY < 0 ? 1.1 : 0.9))))
  }, [])
  useEffect(() => {
    const el = svgRef.current; if (!el) return
    el.addEventListener('wheel', onWheel, { passive: false })
    return () => el.removeEventListener('wheel', onWheel)
  }, [onWheel])

  /* ── States ── */
  if (loading) return (
    <div style={s.center}>
      <span style={{ color: '#1a3a1a', fontSize: 10, letterSpacing: 3 }}>
        SCANNING NETWORK<span style={{ animation: 'pulse 1s infinite', display: 'inline' }}>…</span>
      </span>
    </div>
  )
  if (fetchErr) return (
    <div style={{ ...s.center, flexDirection: 'column', gap: 12 }}>
      <span style={{ color: '#f85149', fontSize: 10, letterSpacing: 1 }}>// {fetchErr} //</span>
      <button onClick={load} style={s.smBtn}>RETRY</button>
    </div>
  )

  const { nodes, edges } = graph
  if (nodes.length === 0) return (
    <div style={{ ...s.center, flexDirection: 'column', gap: 8 }}>
      <div style={{ color: '#111', fontSize: 40 }}>◎</div>
      <p style={{ color: '#1e2a1e', fontSize: 11, letterSpacing: 4 }}>NO AGENTS</p>
    </div>
  )

  const pos     = buildLayout(nodes, edges)
  const nodeMap = Object.fromEntries(nodes.map(n => [n.agent_id, n]))
  const selNode = selected ? nodeMap[selected] : null

  /* Canvas center pivot = mid of SVG */
  const CX = '50%', CY = '40%'

  return (
    <div style={s.wrap}>
      {/* ── Header ── */}
      <div style={s.header}>
        <span style={s.title}>NETWORK MAP</span>
        <span style={{ fontSize: 10, color: '#1a3a1a', letterSpacing: 1 }}>
          <span style={{ color: nodes.filter(n => n.is_active).length > 0 ? '#3fb950' : '#333' }}>
            {nodes.filter(n => n.is_active).length}
          </span>
          <span style={{ color: '#333' }}>/{nodes.length}</span>
          <span style={{ color: '#1a2a1a', marginLeft: 5 }}>NODES</span>
        </span>
        <button onClick={() => { setPan({ x: 0, y: 0 }); setZoom(1) }} style={s.smBtn}>RESET</button>
        <button onClick={load} style={s.smBtn}>REFRESH</button>
      </div>

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden', position: 'relative' }}>
        {/* ── SVG canvas ── */}
        <svg ref={svgRef}
          style={{ flex: 1, background: '#050505', cursor: panning.current ? 'grabbing' : 'grab', userSelect: 'none' }}
          onMouseDown={onMouseDown} onMouseMove={onMouseMove}
          onMouseUp={onMouseUp} onMouseLeave={onMouseUp}
          onClick={() => setSelected(null)}
        >
          <defs>
            {/* Glow filters per color */}
            {Object.entries(PRIV).map(([k, v]) => (
              <filter key={k} id={`glow-${k}`} x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur in="SourceGraphic" stdDeviation="6" result="blur"/>
                <feComposite in="SourceGraphic" in2="blur" operator="over"/>
              </filter>
            ))}
            <filter id="glow-dead" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur in="SourceGraphic" stdDeviation="4" result="blur"/>
              <feComposite in="SourceGraphic" in2="blur" operator="over"/>
            </filter>
            {/* Dot grid pattern */}
            <pattern id="dotgrid" width="40" height="40" patternUnits="userSpaceOnUse">
              <circle cx="20" cy="20" r="0.8" fill="#0e1a0e"/>
            </pattern>
            {/* Arrow marker */}
            <marker id="arrow-green" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
              <path d="M0,0 L0,6 L6,3 Z" fill="#3fb95055"/>
            </marker>
          </defs>

          {/* Background grid */}
          <rect width="100%" height="100%" fill="url(#dotgrid)"/>

          {/* Scan line overlay */}
          <rect width="100%" height="2" y="0" fill="#0e1a0e" opacity="0.4">
            <animateTransform attributeName="transform" type="translate" from="0,0" to="0,100%" dur="4s" repeatCount="indefinite"/>
          </rect>

          <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
            {/* Pivot to SVG center */}
            <g ref={el => {}}>
              <g transform="translate(500, 120)">

                {/* ── Edges ── */}
                {edges.map((e, i) => {
                  const sp = pos[e.source]; const tp = pos[e.target]
                  if (!sp || !tp) return null
                  const active = nodeMap[e.source]?.is_active
                  return (
                    <FlowEdge key={i}
                      x1={sp.x} y1={sp.y} x2={tp.x} y2={tp.y} active={active}/>
                  )
                })}

                {/* ── Nodes ── */}
                {nodes.map(node => {
                  const p    = pos[node.agent_id]; if (!p) return null
                  const priv = getPriv(node)
                  const type = getType(node)
                  const dead = !node.is_active
                  const color = dead ? '#2a2a2a' : priv.color
                  const isSel = selected === node.agent_id
                  const filterId = dead ? 'glow-dead' : `glow-${Object.keys(PRIV).find(k => PRIV[k].color === priv.color) ?? 'Medium'}`

                  return (
                    <g key={node.agent_id}
                      transform={`translate(${p.x},${p.y})`}
                      onClick={e => { e.stopPropagation(); setSelected(isSel ? null : node.agent_id) }}
                      style={{ cursor: 'pointer' }}>

                      {/* Outer glow ring (selected) */}
                      {isSel && (
                        <circle r={R + 14} fill="none" stroke={color} strokeWidth="1" opacity="0.25"/>
                      )}

                      {/* Active pulse */}
                      {!dead && (
                        <circle r={R + 4} fill="none" stroke={priv.color} strokeWidth="1" opacity="0.0">
                          <animate attributeName="r"       values={`${R+4};${R+22};${R+4}`} dur="3s" repeatCount="indefinite"/>
                          <animate attributeName="opacity" values="0.3;0;0.3"               dur="3s" repeatCount="indefinite"/>
                          <animate attributeName="stroke-width" values="1.5;0.3;1.5"        dur="3s" repeatCount="indefinite"/>
                        </circle>
                      )}

                      {/* Glow circle */}
                      {!dead && (
                        <circle r={R} fill={priv.ring} filter={`url(#${filterId})`}/>
                      )}

                      {/* Main node circle */}
                      <circle r={R}
                        fill={isSel ? color + '18' : '#0a0a0a'}
                        stroke={color}
                        strokeWidth={isSel ? 2 : 1.2}/>

                      {/* Inner ring */}
                      <circle r={R - 6} fill="none" stroke={color} strokeWidth="0.4" opacity="0.3"/>

                      {/* Icon */}
                      <NodeIcon type={type} color={color} active={!dead}/>

                      {/* Privilege badge */}
                      {!dead && (priv.badge === '★' || priv.badge === '▲') && (
                        <g transform={`translate(${R - 4}, ${-R + 4})`}>
                          <circle r="8" fill="#0a0a0a" stroke={color} strokeWidth="1"/>
                          <text textAnchor="middle" dominantBaseline="middle"
                            style={{ fontSize: '9px', fill: color, fontFamily: 'monospace' }}>
                            {priv.badge}
                          </text>
                        </g>
                      )}

                      {/* Dead overlay X */}
                      {dead && (
                        <g opacity="0.4">
                          <line x1="-8" y1="-8" x2="8" y2="8" stroke="#444" strokeWidth="1.5"/>
                          <line x1="8" y1="-8" x2="-8" y2="8" stroke="#444" strokeWidth="1.5"/>
                        </g>
                      )}

                      {/* Hostname label */}
                      <text y={R + 16} textAnchor="middle"
                        style={{ fontSize: '10px', fill: dead ? '#333' : color, fontFamily: 'monospace', letterSpacing: '0.5px' }}>
                        {(node.hostname || node.agent_id.slice(0, 8)).slice(0, 16)}
                      </text>

                      {/* OS label */}
                      <text y={R + 28} textAnchor="middle"
                        style={{ fontSize: '8px', fill: '#2a3a2a', fontFamily: 'monospace', letterSpacing: '0.5px' }}>
                        {(node.os_info || '').slice(0, 16)}
                      </text>
                    </g>
                  )
                })}
              </g>
            </g>
          </g>

          {/* Zoom indicator */}
          <text x="12" y="calc(100% - 10)" style={{ fontSize: '9px', fill: '#0e1a0e', fontFamily: 'monospace' }}>
            {Math.round(zoom * 100)}%
          </text>
        </svg>

        {/* ── Detail panel ── */}
        {selNode && (() => {
          const priv = getPriv(selNode)
          const color = selNode.is_active ? priv.color : '#333'
          return (
            <div style={{ ...s.detail, borderLeft: `1px solid ${color}22` }}>
              <div style={{ fontSize: 9, color: color, letterSpacing: 3, marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: color, display: 'inline-block',
                  boxShadow: selNode.is_active ? `0 0 6px ${color}` : 'none' }}/>
                NODE DETAIL
              </div>
              {[
                ['ID',       selNode.agent_id],
                ['HOST',     selNode.hostname   || '—'],
                ['IP',       selNode.ip         || '—'],
                ['USER',     selNode.username   || '—'],
                ['OS',       selNode.os_info    || '—'],
                ['PRIV',     selNode.privileges || '—'],
                ['TYPE',     getType(selNode).toUpperCase()],
                ['TAGS',     selNode.tags       || '—'],
                ['PARENT',   selNode.parent_id  || '—'],
                ['SEEN',     selNode.last_seen ? new Date(selNode.last_seen + 'Z').toLocaleTimeString('fr-FR') : '—'],
                ['STATUS',   selNode.is_active ? 'ACTIVE' : 'DEAD'],
              ].map(([k, v]) => (
                <div key={k} style={{ display: 'flex', gap: 8, marginBottom: 8, borderBottom: '1px solid #0d1a0d', paddingBottom: 6 }}>
                  <span style={{ fontSize: 9, color: '#1a3a1a', letterSpacing: 2, minWidth: 50, flexShrink: 0 }}>{k}</span>
                  <span style={{ fontSize: 10, color: k === 'STATUS' ? color : '#888', wordBreak: 'break-all', letterSpacing: 0.5 }}>{v}</span>
                </div>
              ))}
              <button onClick={() => setSelected(null)}
                style={{ ...s.smBtn, width: '100%', marginTop: 8, borderColor: color + '44', color }}>
                CLOSE
              </button>
            </div>
          )
        })()}
      </div>
    </div>
  )
}

const s = {
  wrap:   { display: 'flex', flexDirection: 'column', height: '100%', background: '#050505' },
  header: { display: 'flex', alignItems: 'center', gap: 10, padding: '8px 14px', borderBottom: '1px solid #0e1a0e', background: '#080808', flexShrink: 0 },
  title:  { fontSize: 11, color: '#1a3a1a', letterSpacing: 3, flex: 1 },
  center: { flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#050505' },
  detail: { width: 240, background: '#080808', padding: 16, flexShrink: 0, overflowY: 'auto' },
  smBtn:  { background: 'transparent', border: '1px solid #0e1a0e', color: '#1a3a1a', fontSize: 9, padding: '3px 10px', fontFamily: 'inherit', cursor: 'pointer', letterSpacing: 1 },
}
