import { useCallback } from 'react'
import Terminal from './Terminal'

const TITLE_H = 34

export default function TerminalWindow({
  agent, win, active,
  onFocus, onClose, onMinimize, onDrag, onResize,
}) {
  const onTitleDown = useCallback((e) => {
    if (e.button !== 0 || e.target.closest('button')) return
    e.preventDefault()
    onFocus()
    const ox = e.clientX - win.x, oy = e.clientY - win.y
    const move = (e) => onDrag(e.clientX - ox, e.clientY - oy)
    const up = () => {
      window.removeEventListener('mousemove', move)
      window.removeEventListener('mouseup', up)
    }
    window.addEventListener('mousemove', move)
    window.addEventListener('mouseup', up)
  }, [win.x, win.y, onFocus, onDrag])

  const onResizeDown = useCallback((e) => {
    e.preventDefault()
    e.stopPropagation()
    const sx = e.clientX, sy = e.clientY, sw = win.w, sh = win.h
    const move = (e) => onResize(
      Math.max(380, sw + e.clientX - sx),
      Math.max(180, sh + e.clientY - sy)
    )
    const up = () => {
      window.removeEventListener('mousemove', move)
      window.removeEventListener('mouseup', up)
    }
    window.addEventListener('mousemove', move)
    window.addEventListener('mouseup', up)
  }, [win.w, win.h, onResize])

  const isMin = win.minimized

  return (
    <div
      onMouseDown={onFocus}
      style={{
        position: 'fixed',
        left: win.x,
        top: win.y,
        width: isMin ? 240 : win.w,
        height: isMin ? TITLE_H : win.h,
        zIndex: win.z,
        display: 'flex',
        flexDirection: 'column',
        border: `1px solid ${active ? '#ff313155' : '#222'}`,
        background: '#0a0a0a',
        boxShadow: active
          ? '0 16px 48px rgba(0,0,0,.9), 0 0 0 1px #ff313118'
          : '0 4px 20px rgba(0,0,0,.7)',
        overflow: 'hidden',
        minWidth: 240,
      }}
    >
      {/* Title bar */}
      <div
        onMouseDown={onTitleDown}
        style={{
          height: TITLE_H,
          flexShrink: 0,
          background: active ? '#130808' : '#111',
          borderBottom: isMin ? 'none' : '1px solid #1a1a1a',
          display: 'flex',
          alignItems: 'center',
          gap: 7,
          padding: '0 6px 0 10px',
          cursor: 'move',
          userSelect: 'none',
        }}
      >
        <span style={{ fontSize: 8, color: agent.is_active ? '#3fb950' : '#444', flexShrink: 0 }}>●</span>
        <span style={{
          fontSize: 11, color: active ? '#ff3131' : '#666',
          letterSpacing: .5, flex: 1,
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>
          {agent.agent_id}
          {agent.hostname && (
            <span style={{ color: '#383838', marginLeft: 7, fontSize: 10 }}>{agent.hostname}</span>
          )}
        </span>
        {agent.privileges === 'elevated' && (
          <span style={{ fontSize: 9, color: '#f59e0b', flexShrink: 0 }} title="elevated">▲</span>
        )}
        <WinBtn onClick={onMinimize} title={isMin ? 'restore' : 'minimize'}>
          {isMin ? '▢' : '─'}
        </WinBtn>
        <WinBtn onClick={onClose} danger title="close">✕</WinBtn>
      </div>

      {/* Terminal body — always mounted, collapsed to 0 when minimized */}
      <div style={{
        height: isMin ? 0 : win.h - TITLE_H,
        overflow: 'hidden',
        position: 'relative',
        flex: isMin ? 0 : 1,
      }}>
        <Terminal agent={agent} active={active && !isMin} />
      </div>

      {/* Resize grip */}
      {!isMin && (
        <div
          onMouseDown={onResizeDown}
          style={{
            position: 'absolute', bottom: 0, right: 0,
            width: 20, height: 20,
            cursor: 'nwse-resize',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: '#2a2a2a', fontSize: 10, userSelect: 'none', zIndex: 2,
          }}
        >⌟</div>
      )}
    </div>
  )
}

function WinBtn({ onClick, children, title, danger }) {
  return (
    <button
      onClick={(e) => { e.stopPropagation(); onClick() }}
      title={title}
      style={{
        background: 'transparent',
        border: '1px solid #252525',
        color: danger ? '#f85149' : '#555',
        cursor: 'pointer',
        width: 20, height: 20, fontSize: 10,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontFamily: 'inherit', padding: 0, flexShrink: 0,
        transition: 'background .1s, color .1s',
      }}
      onMouseEnter={e => {
        e.currentTarget.style.background = danger ? '#2d1818' : '#1e1e1e'
        e.currentTarget.style.color = danger ? '#f85149' : '#dde1e8'
      }}
      onMouseLeave={e => {
        e.currentTarget.style.background = 'transparent'
        e.currentTarget.style.color = danger ? '#f85149' : '#555'
      }}
    >
      {children}
    </button>
  )
}
