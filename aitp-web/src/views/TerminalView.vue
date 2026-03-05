<script setup>
import { reactive, ref, onMounted, nextTick } from 'vue'

// ── STATE ──────────────────────────────────────────────────────────
const S = reactive({
  connected: false,
  sessionId: null,
  sessions: 0,
  blocked: 0,
  alerts: 0,
  aiCalls: 0,
  trustScores: [],
  clients: [],
  phase: 'idle',
  config: {
    provider: 'gemini',
    model: 'gemini-2.0-flash',
    apiKey: '',
    trustMode: 'hybrid',
    timeout: 4000,
  }
})

const serverLogs = ref([])
const clientLogs = ref([])
const commandInput = ref('')
const serverLogContainer = ref(null)
const clientLogContainer = ref(null)
const modalOpen = ref(false)

// ── UTILS ─────────────────────────────────────────────────────────
const ts = () => {
  const n = new Date()
  return [n.getHours(), n.getMinutes(), n.getSeconds()].map(x => String(x).padStart(2, '0')).join(':')
    + '.' + String(n.getMilliseconds()).padStart(3, '0')
}
const rh = n => [...Array(n)].map(() => Math.floor(Math.random() * 16).toString(16)).join('')
const ri = (a, b) => Math.floor(Math.random() * (b - a + 1)) + a
const delay = ms => new Promise(r => setTimeout(r, ms))
const randIp = () => `${ri(10, 220)}.${ri(0, 255)}.${ri(0, 255)}.${ri(2, 254)}`

const scrollToBottom = async (containerRef) => {
  await nextTick()
  if (containerRef.value) {
    containerRef.value.scrollTop = containerRef.value.scrollHeight
  }
}

// ── LOGGING ───────────────────────────────────────────────────────
const slog = (html) => {
  serverLogs.value.push({ html, time: ts() })
  scrollToBottom(serverLogContainer)
}
const clog = (html) => {
  clientLogs.value.push({ html, time: ts() })
  scrollToBottom(clientLogContainer)
}

const L = (level, cls, msg) =>
  `<div class="ll"><span class="lv ${cls}">${level}</span><span class="lm">${msg}</span></div>`

const ok = m => L('OK   ', 'v-ok', m)
const info = m => L('INFO ', 'v-info', m)
const warn = m => L('WARN ', 'v-warn', m)
const err = m => L('ERR  ', 'v-err', m)
const ai = m => L('AI   ', 'v-ai', m)
const net = m => L('NET  ', 'v-net', m)
const sys = m => L('SYS  ', 'v-sys', m)
const sep = () => `<div class="ll"><span class="lt"></span><span class="lm vd">${'─'.repeat(55)}</span></div>`

function alertBlock(title, rows) {
  const rs = rows.map(([k, v, vc]) => `<div class="ab-row"><span class="ab-key">${k}</span><span class="ab-val ${vc || ''}">${v}</span></div>`).join('')
  return `<div class="alert-block"><div class="ab-head">⚠ ${title}</div>${rs}</div>`
}

function flowLine(src, dst, bytes, intent, trust, dir = '→') {
  const tc = trust > 150 ? 'vg' : trust > 100 ? 'va' : 'vr'
  return `<div class="flow-line">
    <span class="flow-src">${src}</span>
    <span class="flow-arrow">${dir}</span>
    <span class="flow-dst">${dst}</span>
    <span class="flow-bytes">${bytes}B</span>
    <span class="flow-intent">[${intent}]</span>
    <span class="flow-trust ${tc}" style="margin-left:auto">T:${trust}</span>
  </div>`
}

// ── AI EVALUATION ─────────────────────
async function callAI(ctx) {
  S.aiCalls++
  const provider = S.config.provider
  const apiKey = S.config.apiKey
  const model = S.config.model

  if (provider === 'rules' || !apiKey) {
    await delay(ri(80, 200))
    const score = ri(140, 220)
    return { score, verdict: 'Allow', reason: 'rules_engine', latency: ri(80, 200), source: 'rules' }
  }

  const prompt = `You are AITP's AI trust engine. Evaluate this connection and return ONLY valid JSON.
Context:
${JSON.stringify(ctx, null, 2)}
Scoring: 0-63=Deny, 64-127=Monitor, 128-255=Allow`

  try {
    let response
    if (provider === 'gemini') {
      response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { temperature: 0.1, maxOutputTokens: 200 } })
      })
      const data = await response.json()
      if (data.error) throw new Error(data.error.message)
      const text = data.candidates?.[0]?.content?.parts?.[0]?.text || '{}'
      const clean = text.replace(/```json?|```/g, '').trim()
      const parsed = JSON.parse(clean)
      return { score: parsed.trust_score || 180, verdict: parsed.verdict || 'Allow', reason: parsed.primary_risk || 'ai_eval', reasoning: parsed.reasoning || '', latency: parsed.eval_ms || ri(800, 2500), source: 'gemini' }
    }
  } catch (e) {
    await delay(100)
    return { score: ri(150, 200), verdict: 'Allow', reason: 'fallback_rules', latency: 150, source: 'rules_fallback', error: e.message }
  }
  return { score: ri(150, 200), verdict: 'Allow', reason: 'mock', latency: 100, source: 'mock' }
}

// ── COMMANDS ──────────────────────────────────────────────────────
async function run(cmd) {
  const guards = ['inference', 'agent', 'sync', 'status', 'revoke']
  if (guards.includes(cmd) && !S.connected) {
    clog(warn(`Not connected. Run <span class="va">Connect</span> first.`)); return
  }
  switch (cmd) {
    case 'connect': await doConnect(); break
    case 'inference': await doInference(); break
    case 'agent': await doAgent(); break
    case 'sync': await doSync(); break
    case 'anon': await doAnon(); break
    case 'flood': await doFlood(); break
    case 'replay': await doReplay(); break
    case 'status': await doStatus(); break
    case 'revoke': await doRevoke(); break
  }
}

async function doConnect() {
  if (S.connected) { clog(warn(`Already connected. Revoke first.`)); return }
  const srvIp = '192.168.1.100'
  S.phase = 'handshaking'
  clog(sep())
  clog(net(`<b>Initiating AITP handshake</b> → <span class="vc">${srvIp}:9999</span>`))

  await delay(150); clog(net(`<span class="arrow-r">→</span> <b>AITP_HELLO</b>  version:<span class="vc">1</span>  nonce:<span class="hash">${rh(12)}</span>`))
  await delay(120); slog(net(`<span class="arrow-l">←</span> <b>AITP_HELLO</b> from <span class="vc">192.168.1.55:${ri(50000, 65000)}</span>`))
  await delay(80); slog(info(`  version_match:<span class="vg">✓</span>  sig_valid:<span class="vg">✓</span>`))

  await delay(200); slog(net(`<span class="arrow-r">→</span> <b>AITP_IDENTITY_EXCHANGE</b>  challenge:<span class="hash">${rh(12)}</span>`))
  await delay(180); clog(ok(`<b>AITP_IDENTITY_EXCHANGE</b> received`))

  await delay(150); clog(net(`<span class="arrow-r">→</span> <b>AITP_INTENT_DECLARE</b>  intent:<span class="vp">ModelInference</span>`))
  await delay(130); slog(net(`<span class="arrow-l">←</span> <b>AITP_INTENT_DECLARE</b>  intent:<span class="vp">ModelInference</span>`))

  await delay(100); slog(ai(`<b>Trust evaluation</b> started — mode:<span class="vp">${S.config.trustMode}</span>`))
  const ctx = { intent: 'ModelInference' }
  const t0 = performance.now()
  const result = await callAI(ctx)
  const latency = Math.round(performance.now() - t0)

  const score = result.score
  S.trustScores.push(score)
  const vc = score > 150 ? 'vg' : score > 100 ? 'va' : 'vr'
  slog(ai(`  → <span class="vp">${result.source}</span>: score:<span class="${vc}">${score}</span>  latency:<span class="vc">${latency}ms</span>`))

  S.sessionId = '0x' + rh(8).toUpperCase()
  await delay(200); slog(ok(`<b>AITP_SESSION_GRANT</b>  session:<span class="vc">${S.sessionId}</span>  trust:<span class="${vc}">${score}</span>`))
  await delay(200); clog(ok(`<b>SESSION_GRANT</b> received  session:<span class="vc">${S.sessionId}</span>  trust:<span class="${vc}">${score}</span>`))

  S.connected = true; S.sessions++
  S.clients = [{ name: 'client-beta', ip: '192.168.1.55', port: ri(50000, 65000), trust: score, intent: 'ModelInference' }]
  S.phase = 'connected'
}

async function doInference() {
  const bytes = ri(256, 2048)
  const score = ri(170, 220); S.trustScores.push(score)
  clog(net(`<span class="arrow-r">→</span> <b>DATA</b>  intent:<span class="vp">ModelInference</span>  bytes:<span class="vc">${bytes}</span>`))
  await delay(100); slog(net(flowLine('client-beta', 'server-alpha', bytes, 'ModelInference', score)))
  await delay(150); slog(ok(`Payload decrypted  bytes:<span class="vg">${bytes}</span>`))
  const rspBytes = ri(128, 512)
  await delay(100); slog(net(flowLine('server-alpha', 'client-beta', rspBytes, 'ModelInference.Response', score, '←')))
  await delay(50); clog(ok(`Response <span class="vg">ACK</span>  bytes:<span class="vc">${rspBytes}</span>`))
}

async function doAgent() {
  const bytes = ri(512, 4096)
  clog(net(`<span class="arrow-r">→</span> <b>DATA</b>  intent:<span class="vp">AgentCoordinate</span>  bytes:<span class="vc">${bytes}</span>`))
  await delay(120); slog(net(flowLine('client-beta', 'server-alpha', bytes, 'AgentCoordinate', ri(160, 210))))
  await delay(200); slog(info(`AgentCoordinate logic processed`))
}

async function doSync() {
  const bytes = ri(4096, 32768)
  clog(net(`<span class="arrow-r">→</span> <b>DATA</b>  intent:<span class="vp">DataSync</span>  bytes:<span class="vc">${bytes}</span>`))
  await delay(200); slog(net(flowLine('client-beta', 'server-alpha', bytes, 'DataSync', ri(155, 200))))
  await delay(300); slog(ok(`DataSync complete`))
}

async function doAnon() {
  clog(warn(`Sending <b>anonymous connection</b> attempt...`))
  await delay(350); slog(err(`entity_id is zeroed — anonymous attempt blocked`))
  S.blocked++; S.alerts++
}

async function doFlood() {
  clog(warn(`<b>⚡ SYN Flood simulation</b> starting...`))
  await delay(150)
  slog(alertBlock('DDoS FLOOD MITIGATED', [['dropped:', '9,841 / 10,000', 'vg']]))
  S.blocked += 9841; S.alerts++
}

async function doReplay() {
  clog(info(`Captured nonce for replay test...`))
  await delay(350); slog(err(`<b>REPLAY DETECTED</b> nonce already seen`))
  S.blocked++; S.alerts++
}

async function doStatus() {
  clog(sep()); clog(sys(`<b>Session Status</b>`))
  clog(info(`session_id: <span class="vc">${S.sessionId}</span>`))
  clog(info(`trust_score: <span class="vg">${S.trustScores[S.trustScores.length - 1] || '—'}</span>`))
}

async function doRevoke() {
  if (!S.connected) return
  clog(net(`<span class="arrow-r">→</span> <b>AITP_REVOKE</b>`))
  await delay(250); slog(warn(`<b>AITP_REVOKE</b> received`))
  S.connected = false; S.sessionId = null; S.clients = []; S.sessions = Math.max(0, S.sessions - 1); S.phase = 'idle'
}

function handleKey(e) {
  if (e.key !== 'Enter') return
  const v = e.target.value.trim(); if (!v) return
  clog(sys(`<span class="vd">$ ${v}</span>`))
  commandInput.value = ''
  if (v.includes('connect')) run('connect')
  else if (v.includes('inference')) run('inference')
  else if (v.includes('agent')) run('agent')
  else if (v.includes('sync')) run('sync')
  else if (v.includes('flood')) run('flood')
  else if (v.includes('replay')) run('replay')
  else if (v.includes('status')) run('status')
  else if (v.includes('revoke')) run('revoke')
}

const avgTrust = () => S.trustScores.length ? Math.round(S.trustScores.reduce((a, b) => a + b) / S.trustScores.length) : '—'

onMounted(() => {
  slog(sys(`<b>AITP Server Node v0.2.0</b> starting`))
  slog(ok(`Server READY — awaiting AITP connections`))
  clog(sys(`<b>AITP Client v0.2.0</b> ready`))
})
</script>

<template>
  <div class="fixed inset-0 z-[100] bg-[#04080e] text-[#b8ccd8] font-mono text-[11.5px] flex flex-col overflow-hidden">
    
    <!-- TOP BAR -->
    <div class="h-[42px] bg-[#080f18] border-b border-[#132030] flex items-center px-4 gap-3.5 shrink-0 relative">
      <div class="font-['Orbitron'] font-black text-[15px] text-[#00e5ff] tracking-[4px] shadow-[0_0_20px_rgba(0,229,255,0.5)]">AITP <span class="text-[9px] text-[#4a6a7a] tracking-[1px] ml-0.5">v0.2.0</span></div>
      <div class="w-px h-5 bg-[#132030]"></div>
      <div class="flex items-center gap-1.5 bg-[#0d1620] border border-[#132030] rounded-[3px] px-2.5 py-[3px] text-[10px] cursor-pointer hover:border-[#c77dff] transition-all" @click="modalOpen = true">
        <div class="w-[7px] h-[7px] rounded-full bg-[#c77dff] shadow-[0_0_8px_#c77dff] animate-pulse"></div>
        <span class="text-[#c77dff] font-bold tracking-[1px]">{{ S.config.provider.toUpperCase() }}</span>
        <span class="text-[#4a6a7a]">{{ S.config.model }}</span>
        <span class="text-[#2a4050] ml-1">▾ configure</span>
      </div>
      <div class="w-px h-5 bg-[#132030]"></div>
      <div class="flex gap-3 ml-auto">
        <div class="text-[10px] text-[#4a6a7a] flex items-center gap-1.5 font-bold uppercase tracking-widest px-3 py-1.5 border border-[#00ff88]/30 bg-[#00ff88]/5 text-[#00ff88] rounded-sm">
          <div class="w-1.5 h-1.5 bg-[#00ff88] rounded-full animate-pulse"></div>
          PROTOCOL ACTIVE
        </div>
        <div class="text-[10px] text-[#4a6a7a] flex items-center gap-1.2 justify-center">SESSIONS <span class="text-[#00e5ff] font-bold ml-1">{{ S.sessions }}</span></div>
        <div class="text-[10px] text-[#4a6a7a] flex items-center gap-1.2 justify-center">BLOCKED <span class="text-[#ff2244] font-bold ml-1">{{ S.blocked }}</span></div>
        <div class="text-[10px] text-[#4a6a7a] flex items-center gap-1.2 justify-center">TRUST AVG <span class="text-[#00ff88] font-bold ml-1">{{ avgTrust() }}</span></div>
        <div class="text-[10px] text-[#4a6a7a] flex items-center gap-1.2 justify-center">eBPF <span class="text-[#00ff88] font-bold ml-1">ENFORCING</span></div>
      </div>
    </div>

    <!-- MAIN GRID -->
    <div class="grid grid-cols-2 flex-1 overflow-hidden">
      
      <!-- SERVER PANEL -->
      <div class="flex flex-col overflow-hidden min-w-0">
        <div class="h-9 bg-[#080f18] border-b border-[#132030] flex items-center px-3 gap-2 shrink-0">
          <div class="flex gap-1.25">
             <div class="w-2.25 h-2.25 rounded-full bg-[#ff5f57]"></div>
             <div class="w-2.25 h-2.25 rounded-full bg-[#febc2e]"></div>
             <div class="w-2.25 h-2.25 rounded-full bg-[#28c840]"></div>
          </div>
          <div class="text-[10px] font-bold tracking-[2px] uppercase text-[#00ff88] ml-1">⬡ SERVER NODE — ALPHA</div>
          <div class="ml-auto flex items-center gap-1.2 text-[10px] font-bold text-[#00ff88]">
            <div class="w-[5px] h-[5px] rounded-full bg-[#00ff88] shadow-[0_0_6px_#00ff88] animate-pulse"></div>
            LISTENING
          </div>
          <div class="bg-[#0d1620] border border-[#132030] rounded-[2px] px-1.75 py-0.5 text-[9px] text-[#4a6a7a]">0.0.0.0:9999/UDP</div>
        </div>

        <div class="bg-[#0d1620] border-b border-[#132030] px-3 py-1.5 shrink-0">
          <div class="text-[9px] text-[#4a6a7a] uppercase tracking-[2px] mb-1.25">● connected clients ({{ S.clients.length }})</div>
          <div class="flex flex-col gap-0.75 max-h-[72px] overflow-hidden">
            <div v-if="!S.clients.length" class="text-[#2a4050] text-[10px] italic">No clients connected yet.</div>
            <div v-for="c in S.clients" :key="c.name" class="flex items-center gap-1.5 text-[10px] py-0.5 border-b border-white/2 overflow-hidden text-ellipsis whitespace-nowrap">
              <div class="w-1.5 h-1.5 rounded-full shrink-0" :style="{ background: c.trust > 150 ? '#00ff88' : '#ffaa00', boxShadow: '0 0 6px ' + (c.trust>150?'#00ff88':'#ffaa00') }"></div>
              <div class="text-[#00e5ff] min-w-[100px]">{{ c.name }}</div>
              <div class="text-[#4a6a7a] min-w-[120px] text-[9px]">{{ c.ip }}:{{ c.port }}</div>
              <div class="font-bold min-w-8" :class="c.trust > 150 ? 'text-[#00ff88]' : 'text-[#ffaa00]'">{{ c.trust }}</div>
              <div class="text-[#c77dff] text-[9px] ml-auto">{{ c.intent }}</div>
            </div>
          </div>
        </div>

        <div class="flex-1 overflow-y-auto p-[10px_12px] scrollbar-thin scrollbar-thumb-[#1e3040] scrollbar-track-transparent" ref="serverLogContainer">
          <div v-for="(l, i) in serverLogs" :key="i" class="mb-0.25 flex gap-2 animate-fade-slide">
            <span class="text-[#2a4050] text-[10px] whitespace-nowrap pt-0.5">{{ l.time }}</span>
            <div class="lm overflow-hidden" v-html="l.html"></div>
          </div>
        </div>

        <div class="h-16 bg-[#080f18] border-t border-[#132030] grid grid-cols-5 shrink-0">
          <div class="text-center p-[7px_4px] border-r border-[#132030]"><div class="font-['Orbitron'] text-base font-bold text-[#00ff88] shadow-[0_0_10px_rgba(0,255,136,0.4)]">{{ S.sessions }}</div><div class="text-[8px] text-[#4a6a7a] tracking-[1px] uppercase mt-0.25">Sessions</div></div>
          <div class="text-center p-[7px_4px] border-r border-[#132030]"><div class="font-['Orbitron'] text-base font-bold text-[#00e5ff] shadow-[0_0_10px_rgba(0,229,255,0.4)]">{{ avgTrust() }}</div><div class="text-[8px] text-[#4a6a7a] tracking-[1px] uppercase mt-0.25">Avg Trust</div></div>
          <div class="text-center p-[7px_4px] border-r border-[#132030]"><div class="font-['Orbitron'] text-base font-bold text-[#ff2244] shadow-[0_0_10px_rgba(255,34,68,0.4)]">{{ S.blocked }}</div><div class="text-[8px] text-[#4a6a7a] tracking-[1px] uppercase mt-0.25">Blocked</div></div>
          <div class="text-center p-[7px_4px] border-r border-[#132030]"><div class="font-['Orbitron'] text-base font-bold text-[#ffaa00] shadow-[0_0_10px_rgba(255,170,0,0.4)]">{{ S.alerts }}</div><div class="text-[8px] text-[#4a6a7a] tracking-[1px] uppercase mt-0.25">Alerts</div></div>
          <div class="text-center p-[7px_4px]"><div class="font-['Orbitron'] text-base font-bold text-[#c77dff] shadow-[0_0_10px_rgba(199,125,255,0.4)]">{{ S.aiCalls }}</div><div class="text-[8px] text-[#4a6a7a] tracking-[1px] uppercase mt-0.25">AI Evals</div></div>
        </div>
      </div>

      <!-- CLIENT PANEL -->
      <div class="flex flex-col overflow-hidden min-w-0 border-l border-[#132030]">
        <div class="h-9 bg-[#080f18] border-b border-[#132030] flex items-center px-3 gap-2 shrink-0">
          <div class="flex gap-1.25">
             <div class="w-2.25 h-2.25 rounded-full bg-[#ff5f57]"></div>
             <div class="w-2.25 h-2.25 rounded-full bg-[#febc2e]"></div>
             <div class="w-2.25 h-2.25 rounded-full bg-[#00e5ff]"></div>
          </div>
          <div class="text-[10px] font-bold tracking-[2px] uppercase text-[#00e5ff] ml-1">◈ CLIENT NODE — BETA</div>
          <div class="ml-auto flex items-center gap-1.2 text-[10px] font-bold" :class="S.connected ? 'text-[#00ff88]' : 'text-[#4a6a7a]'">
            <div class="w-[5px] h-[5px] rounded-full animate-pulse" :style="{ background: S.connected ? '#00ff88' : '#00e5ff', boxShadow: '0 0 6px ' + (S.connected?'#00ff88':'#00e5ff') }"></div>
            {{ S.connected ? 'CONNECTED' : 'READY' }}
          </div>
          <div class="bg-[#0d1620] border border-[#132030] rounded-[2px] px-1.75 py-0.5 text-[9px] text-[#4a6a7a] tracking-tight uppercase">{{ S.connected ? '192.168.1.100:9999' : 'NOT CONNECTED' }}</div>
        </div>

        <div class="flex-1 overflow-y-auto p-[10px_12px] scrollbar-thin scrollbar-thumb-[#1e3040] scrollbar-track-transparent" ref="clientLogContainer">
          <div v-for="(l, i) in clientLogs" :key="i" class="mb-0.25 flex gap-2 animate-fade-slide">
            <span class="text-[#2a4050] text-[10px] whitespace-nowrap pt-0.5">{{ l.time }}</span>
            <div class="lm overflow-hidden" v-html="l.html"></div>
          </div>
        </div>

        <div class="bg-[#080f18] border-t border-[#132030] p-2 shrink-0">
          <div class="text-[9px] text-[#2a4050] uppercase tracking-[2px] mb-2 px-1">▸ commands</div>
          <div class="flex gap-1.25 flex-wrap px-1 mb-1">
            <button class="cb" @click="run('connect')"><span class="cbn">🔗 Connect</span><span class="cbc">--connect</span></button>
            <button class="cb ai-cmd" @click="run('inference')"><span class="cbn">🤖 Infer</span><span class="cbc">ModelInference</span></button>
            <button class="cb ai-cmd" @click="run('agent')"><span class="cbn">🕸 Agent</span><span class="cbc">AgentCoordinate</span></button>
            <button class="cb" @click="run('sync')"><span class="cbn">⟳ Sync</span><span class="cbc">DataSync</span></button>
            <button class="cb danger" @click="run('anon')"><span class="cbn">👻 Anon</span><span class="cbc">--no-identity</span></button>
            <button class="cb danger" @click="run('flood')"><span class="cbn">💥 Flood</span><span class="cbc">--test ddos</span></button>
            <button class="cb danger" @click="run('replay')"><span class="cbn">↩ Replay</span><span class="cbc">--test replay</span></button>
            <button class="cb" @click="run('status')"><span class="cbn">📊 Status</span><span class="cbc">--status</span></button>
            <button class="cb danger" @click="run('revoke')"><span class="cbn">🚫 Revoke</span><span class="cbc">--revoke</span></button>
          </div>
        </div>

        <div class="h-10 bg-[#080f18] border-t border-[#132030] flex items-center px-4 shrink-0">
          <span class="text-[#00e5ff] font-bold text-xs whitespace-nowrap mr-2">aitp-client $</span>
          <input v-model="commandInput" class="flex-1 bg-transparent border-none outline-none text-[#b8ccd8] font-['JetBrains_Mono'] text-[11.5px] caret-[#00e5ff] placeholder:text-[#2a4050]" placeholder="aitp_client --server 192.168.1.100:9999 --intent ModelInference" @keydown="handleKey"/>
        </div>
      </div>
    </div>

    <!-- MODAL -->
    <div v-if="modalOpen" class="fixed inset-0 bg-black/75 flex items-center justify-center z-[200]">
      <div class="bg-[#080f18] border border-[#132030] rounded-md w-[460px] p-5 shadow-[0_0_60px_rgba(0,229,255,0.1)]">
        <div class="font-['Orbitron'] text-[13px] text-[#00e5ff] tracking-[2px] mb-4 flex items-center gap-2">⚙ AI TRUST ENGINE CONFIG</div>
        <div class="mb-3">
          <div class="text-[9px] text-[#4a6a7a] tracking-[1.5px] uppercase mb-1.25">AI Provider</div>
          <select v-model="S.config.provider" class="w-full bg-[#0d1620] border border-[#132030] text-[#b8ccd8] p-2 rounded-sm text-xs outline-none focus:border-[#00e5ff] transition-all">
            <option value="gemini">Google Gemini</option>
            <option value="rules">Rules Only (No AI)</option>
          </select>
        </div>
        <div v-if="S.config.provider !== 'rules'" class="mb-3">
          <div class="text-[9px] text-[#4a6a7a] tracking-[1.5px] uppercase mb-1.25">API Key</div>
          <input v-model="S.config.apiKey" type="password" class="w-full bg-[#0d1620] border border-[#132030] text-[#b8ccd8] p-2 rounded-sm text-xs outline-none focus:border-[#00e5ff] transition-all" placeholder="Paste your API key here..."/>
        </div>
        <div class="flex gap-2 mt-4">
          <button class="flex-1 bg-[#00e5ff]/10 border border-[#00e5ff] text-[#00e5ff] font-bold p-2 text-xs rounded-sm hover:bg-[#00e5ff]/20 transition-all uppercase tracking-widest" @click="modalOpen = false">Apply Config</button>
          <button class="bg-[#0d1620] border border-[#132030] text-[#4a6a7a] px-4 py-2 text-xs rounded-sm hover:border-[#4a6a7a] transition-all" @click="modalOpen = false">Close</button>
        </div>
      </div>
    </div>

  </div>
</template>

<style>
@keyframes fadeSlide { from { opacity: 0; transform: translateX(-6px); } to { opacity: 1; transform: none; } }
.animate-fade-slide { animation: fadeSlide .25s ease forwards; }

.lm b { color: #fff; font-weight: 700; }
.lm .vc { color: var(--cyan); }
.lm .vg { color: var(--green); }
.lm .vr { color: var(--red); }
.lm .va { color: var(--amber); }
.lm .vp { color: var(--purple); }
.lm .vd { color: var(--text2); font-size: 10.5px; }
.lm .hash { color: var(--text3); font-size: 10px; }

.lv { font-size: 8.5px; font-weight: 700; padding: 1px 5px; border-radius: 2px; flex-shrink: 0; align-self: flex-start; margin-top: 2px; letter-spacing: .8px; white-space: nowrap; }
.v-ok { background: rgba(0,255,136,.1); color: #00ff88; border: 1px solid rgba(0,255,136,.25); }
.v-info { background: rgba(68,136,255,.1); color: #4488ff; border: 1px solid rgba(68,136,255,.25); }
.v-warn { background: rgba(255,170,0,.1); color: #ffaa00; border: 1px solid rgba(255,170,0,.25); }
.v-err { background: rgba(255,34,68,.15); color: #ff2244; border: 1px solid rgba(255,34,68,.35); animation: alertGlow 1s ease 2; }
.v-ai { background: rgba(199,125,255,.1); color: #c77dff; border: 1px solid rgba(199,125,255,.25); }
.v-net { background: rgba(0,229,255,.08); color: #00e5ff; border: 1px solid rgba(0,229,255,.2); }
.v-sys { background: rgba(255,255,255,.04); color: #4a6a7a; border: 1px solid #132030; }

@keyframes alertGlow { 0%,100% { box-shadow: none; } 50% { box-shadow: 0 0 10px #ff2244; } }

.alert-block { margin: 6px 0; border: 1px solid #ff2244; background: rgba(255,34,68,.07); border-radius: 3px; padding: 7px 10px; animation: alertIn .3s ease; }
@keyframes alertIn { from { opacity: 0; transform: scaleY(.8); } to { opacity: 1; transform: none; } }
.ab-head { color: #ff2244; font-size: 10px; font-weight: 700; letter-spacing: 1.5px; display: flex; align-items: center; gap: 6px; margin-bottom: 5px; }
.ab-row { font-size: 10.5px; color: #b8ccd8; margin: 1px 0; display: flex; gap: 8px; }
.ab-key { color: #4a6a7a; min-width: 80px; }
.ab-val { color: #ff2244; }
.ab-val.vg { color: #00ff88; }

.flow-line { display: flex; align-items: center; gap: 6px; font-size: 10px; padding: 2px 0; margin: 1px 0; }
.flow-src { color: #00e5ff; min-width: 110px; font-size: 10px; }
.flow-arrow { color: #4a6a7a; flex-shrink: 0; }
.flow-dst { color: #00ff88; min-width: 110px; font-size: 10px; }
.flow-bytes { color: #4a6a7a; font-size: 9px; margin-left: 4px; }
.flow-intent { color: #c77dff; font-size: 9px; }
.flow-trust { font-weight: 700; font-size: 10px; }

.cb { background: #0d1620; border: 1px solid #132030; color: #b8ccd8; font-family: 'JetBrains Mono', monospace; font-size: 9.5px; padding: 5px 8px; border-radius: 3px; cursor: pointer; transition: all .15s; display: flex; flex-direction: column; align-items: flex-start; gap: 1px; min-width: 80px; }
.cb:hover { border-color: #00e5ff; color: #00e5ff; background: rgba(0,229,255,.04); }
.cb:active { transform: scale(.97); }
.cb .cbn { font-size: 10px; font-weight: 700; }
.cb .cbc { font-size: 8.5px; color: #4a6a7a; }
.cb.danger { border-color: rgba(255,34,68,.3); }
.cb.danger:hover { border-color: #ff2244; color: #ff2244; }
.cb.ai-cmd { border-color: rgba(199,125,255,.3); }
.cb.ai-cmd:hover { border-color: #c77dff; color: #c77dff; }

.arrow-r { color: #00ff88; }
.arrow-l { color: #00e5ff; }

:root {
  --cyan: #00e5ff;
  --green: #00ff88;
  --red: #ff2244;
  --amber: #ffaa00;
  --purple: #c77dff;
  --text2: #4a6a7a;
  --text3: #2a4050;
}
</style>
