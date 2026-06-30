import { create } from 'zustand'
import axios from 'axios'

// Dev: Vite proxies /api → localhost:8000. Prod Tauri: sidecar binds localhost:8000.
export const API_BASE = import.meta.env.DEV ? '/api' : 'http://localhost:8000'
const API = API_BASE

axios.interceptors.request.use(cfg => {
  const t = localStorage.getItem('lc2_token')
  if (t) cfg.headers.Authorization = `Bearer ${t}`
  return cfg
})

const useAgentStore = create((set, get) => ({

  /* ── Auth ─────────────────────────────────────────────── */
  token:     localStorage.getItem('lc2_token') || null,
  authError: null,
  operator:  null,

  login: async (username, password) => {
    try {
      const { data } = await axios.post(`${API}/auth/login`, { username: username.trim(), password: password.trim() })
      localStorage.setItem('lc2_token', data.access_token)
      set({ token: data.access_token, authError: null })
      if ('Notification' in window && Notification.permission === 'default')
        Notification.requestPermission()
      get().connectWS()
      return true
    } catch (err) {
      const status = err?.response?.status
      const msg = status === 401 ? 'Invalid credentials'
                : status        ? `Server error ${status}`
                :                 'Cannot reach server'
      set({ authError: msg })
      return false
    }
  },

  logout: () => {
    get().ws?.close()
    localStorage.removeItem('lc2_token')
    set({ token: null, agents: [], selectedAgent: null, multiSelect: new Set(),
          ws: null, wsConnected: false, consoleTabs: [], activeConsoleTab: null, toasts: [] })
  },

  /* ── Agents ───────────────────────────────────────────── */
  agents:        [],
  selectedAgent: null,
  multiSelect:   new Set(),
  loadingAgents: false,

  fetchAgents: async () => {
    set({ loadingAgents: true })
    try {
      const { data } = await axios.get(`${API}/agents`)
      set(s => ({
        agents: data,
        selectedAgent: s.selectedAgent
          ? (data.find(a => a.agent_id === s.selectedAgent.agent_id) ?? s.selectedAgent)
          : null,
      }))
    } catch {}
    finally { set({ loadingAgents: false }) }
  },

  selectAgent: agent => set({ selectedAgent: agent, taskOutput: null }),

  toggleMultiSelect: (agentId) => set(s => {
    const next = new Set(s.multiSelect)
    if (next.has(agentId)) next.delete(agentId)
    else next.add(agentId)
    return { multiSelect: next }
  }),
  clearMultiSelect: () => set({ multiSelect: new Set() }),
  broadcastTask: async (cmd, args = '') => {
    const ids = [...get().multiSelect]
    return Promise.all(ids.map(id => get().sendTask(id, cmd, args)))
  },

  deleteAgent: async (agentId) => {
    try {
      await axios.delete(`${API}/agents/${agentId}`)
    } catch {}
    set(s => ({
      agents: s.agents.filter(a => a.agent_id !== agentId),
      selectedAgent: s.selectedAgent?.agent_id === agentId ? null : s.selectedAgent,
      consoleTabs: s.consoleTabs.filter(t => t.agent_id !== agentId),
      activeConsoleTab: s.activeConsoleTab === agentId
        ? (s.consoleTabs.filter(t => t.agent_id !== agentId).at(-1)?.agent_id ?? null)
        : s.activeConsoleTab,
    }))
  },

  patchAgent: async (agentId, patch) => {
    try {
      const { data } = await axios.patch(`${API}/agents/${agentId}`, patch)
      set(s => ({
        agents: s.agents.map(a => a.agent_id === agentId ? { ...a, ...data } : a),
        selectedAgent: s.selectedAgent?.agent_id === agentId ? { ...s.selectedAgent, ...data } : s.selectedAgent,
      }))
      return data
    } catch { return null }
  },

  /* ── Agent aliases (client-side, persistent via localStorage) ── */
  agentAliases: JSON.parse(localStorage.getItem('lc2_aliases') || '{}'),

  setAgentAlias: (agentId, alias) => set(s => {
    const next = { ...s.agentAliases, [agentId]: alias.trim() }
    localStorage.setItem('lc2_aliases', JSON.stringify(next))
    return { agentAliases: next }
  }),

  clearAgentAlias: (agentId) => set(s => {
    const next = { ...s.agentAliases }
    delete next[agentId]
    localStorage.setItem('lc2_aliases', JSON.stringify(next))
    return { agentAliases: next }
  }),

  killAll: async () => {
    try {
      const { data } = await axios.post(`${API}/agents/killall`)
      return data
    } catch { return null }
  },

  /* ── Console tabs ─────────────────────────────────────── */
  consoleTabs:      [],   // agent objects
  activeConsoleTab: null, // agent_id

  openConsoleTab: (agent) => {
    set(s => {
      const exists = s.consoleTabs.find(t => t.agent_id === agent.agent_id)
      return {
        selectedAgent:    agent,
        taskOutput:       null,
        consoleTabs:      exists ? s.consoleTabs : [...s.consoleTabs, agent],
        activeConsoleTab: agent.agent_id,
      }
    })
  },

  closeConsoleTab: (agentId) => {
    set(s => {
      const remaining = s.consoleTabs.filter(t => t.agent_id !== agentId)
      const newActive = s.activeConsoleTab === agentId
        ? (remaining[remaining.length - 1]?.agent_id ?? null)
        : s.activeConsoleTab
      return { consoleTabs: remaining, activeConsoleTab: newActive }
    })
  },

  setActiveConsoleTab: (agentId) => {
    const agent = get().consoleTabs.find(t => t.agent_id === agentId)
    if (agent) set({ activeConsoleTab: agentId, selectedAgent: agent })
  },

  /* ── Tasks ────────────────────────────────────────────── */
  taskOutput:       null,
  taskHistory:      [],
  sendingTask:      false,
  lastAckedTask:    null, // { task_id, agent_id, output, cmd }

  sendTask: async (agentId, cmd, args = '', dataB64 = '') => {
    set({ sendingTask: true })
    try {
      const { data } = await axios.post(`${API}/agents/${agentId}/task`,
        { cmd, args, data_b64: dataB64 })
      set(s => ({ taskHistory: [data, ...s.taskHistory] }))
      return data
    } catch { return null }
    finally { set({ sendingTask: false }) }
  },

  fetchOutput: async agentId => {
    try {
      const { data } = await axios.get(`${API}/agents/${agentId}/output`)
      set({ taskOutput: data })
      return data
    } catch { return null }
  },

  fetchTasks: async agentId => {
    try {
      const { data } = await axios.get(`${API}/agents/${agentId}/tasks`)
      set({ taskHistory: data })
      return data
    } catch { return null }
  },

  /* ── Logs ─────────────────────────────────────────────── */
  logs:        [],
  loadingLogs: false,

  fetchLogs: async (agentId = null) => {
    set({ loadingLogs: true })
    try {
      const { data } = await axios.get(`${API}/logs`,
        { params: agentId ? { agent_id: agentId } : {} })
      set({ logs: data })
    } finally { set({ loadingLogs: false }) }
  },

  /* ── WebSocket ────────────────────────────────────────── */
  ws:          null,
  wsConnected: false,
  _wsRetry:    null,

  _notify: (title, body) => {
    if (!('Notification' in window) || Notification.permission !== 'granted') return
    new Notification(title, { body, icon: '/favicon-32x32.png' })
  },

  connectWS: () => {
    const token = localStorage.getItem('lc2_token')
    if (!token) return
    const _ws = get().ws
    if (_ws && (_ws.readyState === WebSocket.OPEN || _ws.readyState === WebSocket.CONNECTING)) return

    const url = import.meta.env.DEV
      ? `ws://${location.hostname}:${location.port || 80}/ws-proxy?token=${encodeURIComponent(token)}`
      : `ws://localhost:8000/ws?token=${encodeURIComponent(token)}`

    const ws = new WebSocket(url)

    ws.onopen = () => {
      set({ wsConnected: true })
      clearTimeout(get()._wsRetry)
    }

    ws.onmessage = e => {
      try { get()._handleWsEvent(JSON.parse(e.data)) } catch {}
    }

    ws.onclose = () => {
      set({ wsConnected: false, ws: null })
      const retry = setTimeout(() => get().connectWS(), 4000)
      set({ _wsRetry: retry })
    }

    ws.onerror = () => ws.close()

    set({ ws })
  },

  _handleWsEvent: (msg) => {
    const { type, agent_id } = msg

    if (type === 'task_acked') {
      set(s => ({
        lastAckedTask: { task_id: msg.task_id, agent_id, output: msg.output, cmd: msg.cmd },
        taskHistory: s.taskHistory.map(t =>
          t.task_id === msg.task_id ? { ...t, status: 'acked', output: msg.output } : t
        ),
      }))
      get().addToast({ type: 'success', text: `[${msg.cmd}] output ready`, agentId: agent_id })
    }

    if (type === 'agent_seen') {
      set(s => ({
        agents: s.agents.map(a =>
          a.agent_id === agent_id
            ? { ...a, last_seen: msg.last_seen, is_active: true }
            : a
        ),
      }))
    }

    if (type === 'agent_new' || type === 'agent_handshake') {
      get().fetchAgents()
      get().addToast({ type: 'agent', text: `New agent: ${agent_id}`, agentId: agent_id })
      if (document.visibilityState === 'hidden')
        get()._notify('New agent', agent_id)
    }

    if (type === 'agent_lost') {
      set(s => ({
        agents: s.agents.map(a =>
          a.agent_id === agent_id ? { ...a, is_active: false } : a
        ),
      }))
      get().addToast({ type: 'error', text: `Agent lost: ${agent_id}`, agentId: agent_id })
    }
  },

  /* ── Toasts ───────────────────────────────────────────── */
  toasts: [],

  addToast: (toast) => {
    const id = Date.now() + Math.random()
    set(s => ({ toasts: [...s.toasts.slice(-4), { ...toast, id }] }))
    setTimeout(() => get().removeToast(id), 5000)
  },

  removeToast: (id) => {
    set(s => ({ toasts: s.toasts.filter(t => t.id !== id) }))
  },

  /* ── Credentials ──────────────────────────────────────── */
  creds: [],

  fetchCreds: async (agentId = null) => {
    try {
      const params = agentId ? { agent_id: agentId } : {}
      const { data } = await axios.get(`${API}/creds`, { params })
      set({ creds: data })
    } catch {}
  },

  saveCred: async (body) => {
    try {
      const { data } = await axios.post(`${API}/creds`, body)
      set(s => ({ creds: [data, ...s.creds] }))
      return data
    } catch { return null }
  },

  deleteCred: async (credId) => {
    try {
      await axios.delete(`${API}/creds/${credId}`)
    } catch {}
    set(s => ({ creds: s.creds.filter(c => c.cred_id !== credId) }))
  },
}))

export default useAgentStore
