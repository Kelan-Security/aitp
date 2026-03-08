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
  else if (v.includes('sentinel')) showSentinelModal()
}

const sentinelAnomalies = ref([])
const showSentinelModal = async () => {
    try {
        const r = await fetch('/api/sentinel/anomalies?limit=10')
        sentinelAnomalies.value = await r.json()
        modalOpen.value = 'sentinel'
    } catch(e) {
        clog(err(`Failed to fetch sentinel logs: ${e.message}`))
    }
}

const avgTrust = () => S.trustScores.length ? Math.round(S.trustScores.reduce((a, b) => a + b) / S.trustScores.length) : '—'

onMounted(() => {
  slog(sys(`<b>AITP Server Node v0.2.0</b> starting`))
  slog(ok(`Server READY — awaiting AITP connections`))
  clog(sys(`<b>AITP Client v0.2.0</b> ready`))
})
</script>

<template>
  <div class="fixed inset-0 z-[100] bg-white text-black font-mono text-[13px] flex flex-col overflow-hidden">
    
    <!-- TOP BAR -->
    <div class="h-[52px] bg-white border-b border-black flex items-center px-6 gap-5 shrink-0 relative">
      <div class="font-['Orbitron'] font-black text-[18px] text-black tracking-[3px]">AITP <span class="text-[11px] text-gray-500 tracking-[1px] ml-1">v0.2.0</span></div>
      <div class="w-px h-6 bg-gray-300"></div>
      <div class="flex items-center gap-2 bg-gray-100 border border-black rounded-[4px] px-3 py-[5px] text-[11px] cursor-pointer hover:bg-black hover:text-white transition-all group" @click="modalOpen = 'config'">
        <div class="w-[8px] h-[8px] rounded-full bg-black group-hover:bg-white transition-colors"></div>
        <span class="font-bold tracking-[1px]">{{ S.config.provider.toUpperCase() }}</span>
        <span>{{ S.config.model }}</span>
        <span class="ml-1 opacity-60">▾ configure</span>
      </div>
      <div class="w-px h-6 bg-gray-300"></div>
      <div class="flex items-center gap-2 bg-gray-100 border border-black rounded-[4px] px-3 py-[5px] text-[11px] cursor-pointer hover:bg-black hover:text-white transition-all" @click="showSentinelModal()">
        <span class="font-bold tracking-[1px]">SENTINEL</span>
        <span class="ml-1 opacity-60">LOGS</span>
      </div>
      <div class="w-px h-6 bg-gray-300"></div>
      <div class="flex gap-4 ml-auto">
        <div class="text-[11px] text-black flex items-center gap-2 font-bold uppercase tracking-widest px-4 py-2 border border-black rounded-sm">
          <div class="w-2 h-2 bg-black rounded-full animate-pulse"></div>
          PROTOCOL ACTIVE
        </div>
        <div class="text-[11px] text-gray-600 flex items-center gap-1.5 justify-center">SESSIONS <span class="text-black font-bold ml-1">{{ S.sessions }}</span></div>
        <div class="text-[11px] text-gray-600 flex items-center gap-1.5 justify-center">BLOCKED <span class="text-black font-bold ml-1">{{ S.blocked }}</span></div>
        <div class="text-[11px] text-gray-600 flex items-center gap-1.5 justify-center">TRUST AVG <span class="text-black font-bold ml-1">{{ avgTrust() }}</span></div>
        <div class="text-[11px] text-gray-600 flex items-center gap-1.5 justify-center">eBPF <span class="text-black font-bold ml-1">ENFORCING</span></div>
      </div>
    </div>

    <!-- MAIN GRID -->
    <div class="grid grid-cols-2 flex-1 overflow-hidden">
      
      <!-- SERVER PANEL -->
      <div class="flex flex-col overflow-hidden min-w-0">
        <div class="h-12 bg-gray-50 border-b border-black flex items-center px-4 gap-3 shrink-0">
          <div class="flex gap-1.5">
             <div class="w-3 h-3 rounded-full border border-black"></div>
             <div class="w-3 h-3 rounded-full border border-black"></div>
             <div class="w-3 h-3 rounded-full border border-black bg-black"></div>
          </div>
          <div class="text-[12px] font-bold tracking-[2px] uppercase text-black ml-2">⬡ SERVER NODE — ALPHA</div>
          <div class="ml-auto flex items-center gap-1.5 text-[11px] font-bold text-black">
            <div class="w-[6px] h-[6px] rounded-full bg-black animate-pulse"></div>
            LISTENING
          </div>
          <div class="bg-white border border-black rounded-[3px] px-2 py-1 text-[10px] text-black">0.0.0.0:9999/UDP</div>
        </div>

        <div class="bg-gray-50 border-b border-black px-4 py-3 shrink-0">
          <div class="text-[10px] text-gray-600 uppercase tracking-[2px] mb-2">● connected clients ({{ S.clients.length }})</div>
          <div class="flex flex-col gap-1.5 max-h-[100px] overflow-hidden">
            <div v-if="!S.clients.length" class="text-gray-500 text-[11px] italic">No clients connected yet.</div>
            <div v-for="c in S.clients" :key="c.name" class="flex items-center gap-2 text-[12px] py-1 border-b border-gray-200 overflow-hidden text-ellipsis whitespace-nowrap">
              <div class="w-2 h-2 rounded-full shrink-0 bg-black"></div>
              <div class="text-black font-bold min-w-[120px]">{{ c.name }}</div>
              <div class="text-gray-600 min-w-[140px] text-[11px]">{{ c.ip }}:{{ c.port }}</div>
              <div class="font-bold min-w-10 text-black border border-black px-1.5 rounded-sm">{{ c.trust }}</div>
              <div class="text-gray-500 text-[10px] ml-auto uppercase tracking-wide">{{ c.intent }}</div>
            </div>
          </div>
        </div>

        <div class="flex-1 overflow-y-auto p-[14px_16px] scrollbar-thin scrollbar-thumb-gray-300 scrollbar-track-transparent bg-white" ref="serverLogContainer">
          <div v-for="(l, i) in serverLogs" :key="i" class="mb-1.5 flex gap-3 animate-fade-slide">
            <span class="text-gray-400 text-[11px] whitespace-nowrap pt-0.5">{{ l.time }}</span>
            <div class="lm overflow-hidden text-black" v-html="l.html"></div>
          </div>
        </div>

        <div class="h-20 bg-gray-50 border-t border-black grid grid-cols-5 shrink-0">
          <div class="text-center p-[10px_6px] border-r border-black flex flex-col justify-center"><div class="font-['Orbitron'] text-xl font-bold text-black">{{ S.sessions }}</div><div class="text-[9px] text-gray-600 tracking-[1px] uppercase mt-1">Sessions</div></div>
          <div class="text-center p-[10px_6px] border-r border-black flex flex-col justify-center"><div class="font-['Orbitron'] text-xl font-bold text-black">{{ avgTrust() }}</div><div class="text-[9px] text-gray-600 tracking-[1px] uppercase mt-1">Avg Trust</div></div>
          <div class="text-center p-[10px_6px] border-r border-black flex flex-col justify-center bg-gray-100"><div class="font-['Orbitron'] text-xl font-bold text-black">{{ S.blocked }}</div><div class="text-[9px] text-black font-bold tracking-[1px] uppercase mt-1">Blocked</div></div>
          <div class="text-center p-[10px_6px] border-r border-black flex flex-col justify-center"><div class="font-['Orbitron'] text-xl font-bold text-black">{{ S.alerts }}</div><div class="text-[9px] text-gray-600 tracking-[1px] uppercase mt-1">Alerts</div></div>
          <div class="text-center p-[10px_6px] flex flex-col justify-center"><div class="font-['Orbitron'] text-xl font-bold text-black">{{ S.aiCalls }}</div><div class="text-[9px] text-gray-600 tracking-[1px] uppercase mt-1">AI Evals</div></div>
        </div>
      </div>

      <!-- CLIENT PANEL -->
      <div class="flex flex-col overflow-hidden min-w-0 border-l border-black">
        <div class="h-12 bg-gray-50 border-b border-black flex items-center px-4 gap-3 shrink-0">
          <div class="flex gap-1.5">
             <div class="w-3 h-3 rounded-full border border-black"></div>
             <div class="w-3 h-3 rounded-full border border-black"></div>
             <div class="w-3 h-3 rounded-full border border-black bg-black"></div>
          </div>
          <div class="text-[12px] font-bold tracking-[2px] uppercase text-black ml-2">◈ CLIENT NODE — BETA</div>
          <div class="ml-auto flex items-center gap-1.5 text-[11px] font-bold text-black">
            <div class="w-[6px] h-[6px] rounded-full animate-pulse bg-black" v-if="S.connected"></div>
            <div class="w-[6px] h-[6px] rounded-full border border-black" v-else></div>
            {{ S.connected ? 'CONNECTED' : 'READY' }}
          </div>
          <div class="bg-white border border-black rounded-[3px] px-2 py-1 text-[10px] text-black tracking-tight uppercase">{{ S.connected ? '192.168.1.100:9999' : 'NOT CONNECTED' }}</div>
        </div>

        <div class="flex-1 overflow-y-auto p-[14px_16px] scrollbar-thin scrollbar-thumb-gray-300 scrollbar-track-transparent bg-white" ref="clientLogContainer">
          <div v-for="(l, i) in clientLogs" :key="i" class="mb-1.5 flex gap-3 animate-fade-slide">
            <span class="text-gray-400 text-[11px] whitespace-nowrap pt-0.5">{{ l.time }}</span>
            <div class="lm overflow-hidden text-black" v-html="l.html"></div>
          </div>
        </div>

        <div class="bg-gray-50 border-t border-black p-4 shrink-0">
          <div class="text-[10px] text-black font-bold uppercase tracking-[2px] mb-3 px-1">▸ Commands</div>
          <div class="flex gap-2 flex-wrap px-1 mb-1">
            <button class="cb" @click="run('connect')"><span class="cbn">🔗 Connect</span><span class="cbc">--connect</span></button>
            <button class="cb ai-cmd" @click="run('inference')"><span class="cbn">🤖 Infer</span><span class="cbc">ModelInference</span></button>
            <button class="cb ai-cmd" @click="run('agent')"><span class="cbn">🕸 Agent</span><span class="cbc">AgentCoordinate</span></button>
            <button class="cb" @click="run('sync')"><span class="cbn">⟳ Sync</span><span class="cbc">DataSync</span></button>
            <button class="cb danger" @click="run('anon')"><span class="cbn">👻 Anon</span><span class="cbc">--no-identity</span></button>
            <button class="cb danger" @click="run('flood')"><span class="cbn">💥 Flood</span><span class="cbc">--test ddos</span></button>
            <button class="cb danger" @click="run('replay')"><span class="cbn">↩ Replay</span><span class="cbc">--test replay</span></button>
            <button class="cb" @click="run('status')"><span class="cbn">📊 Status</span><span class="cbc">--status</span></button>
            <button class="cb danger" @click="run('revoke')"><span class="cbn">🚫 Revoke</span><span class="cbc">--revoke</span></button>
            <button class="cb" @click="showSentinelModal()"><span class="cbn">👀 Sentinel</span><span class="cbc">anomaly logs</span></button>
          </div>
        </div>

        <div class="h-14 bg-white border-t border-black flex items-center px-5 shrink-0">
          <span class="text-black font-bold text-[13px] whitespace-nowrap mr-3">aitp-client $</span>
          <input v-model="commandInput" class="flex-1 bg-transparent border-none outline-none text-black font-['JetBrains_Mono'] text-[13px] placeholder:text-gray-400" placeholder="aitp_client --server 127.0.0.1:9999 --intent ModelInference" @keydown="handleKey"/>
        </div>
      </div>
    </div>

    <!-- CONFIG MODAL -->
    <div v-if="modalOpen === 'config'" class="fixed inset-0 bg-white/90 flex items-center justify-center z-[200] backdrop-blur-sm">
      <div class="bg-white border-[2px] border-black rounded-none w-[500px] p-8 shadow-[12px_12px_0_0_rgba(0,0,0,1)]">
        <div class="font-['Orbitron'] text-[16px] font-bold text-black tracking-[2px] mb-6 flex items-center gap-2 border-b-2 border-black pb-4">⚙ AI TRUST ENGINE CONFIG</div>
        <div class="mb-5">
          <div class="text-[11px] text-black font-bold tracking-[1.5px] uppercase mb-2">AI Provider</div>
          <select v-model="S.config.provider" class="w-full bg-white border-2 border-black text-black p-3 rounded-none text-[13px] outline-none hover:bg-gray-50 focus:ring-2 focus:ring-black focus:ring-offset-2 transition-all cursor-pointer">
            <option value="gemini">Google Gemini</option>
            <option value="rules">Rules Only (No AI)</option>
          </select>
        </div>
        <div v-if="S.config.provider !== 'rules'" class="mb-5">
          <div class="text-[11px] text-black font-bold tracking-[1.5px] uppercase mb-2">API Key</div>
          <input v-model="S.config.apiKey" type="password" class="w-full bg-white border-2 border-black text-black p-3 rounded-none text-[13px] outline-none focus:ring-2 focus:ring-black focus:ring-offset-2 transition-all" placeholder="Paste your API key here..."/>
        </div>
        <div class="flex gap-3 mt-8">
          <button class="flex-1 bg-black text-white font-bold p-3 text-[13px] rounded-none hover:bg-gray-800 transition-all uppercase tracking-widest border-2 border-black" @click="modalOpen = null">Apply Config</button>
          <button class="bg-white border-2 border-black text-black font-bold px-6 py-3 text-[13px] rounded-none hover:bg-gray-100 transition-all uppercase" @click="modalOpen = null">Close</button>
        </div>
      </div>
    </div>
    
    <!-- SENTINEL MODAL -->
    <div v-if="modalOpen === 'sentinel'" class="fixed inset-0 bg-white/90 flex items-center justify-center z-[200] backdrop-blur-sm">
      <div class="bg-white border-[2px] border-black rounded-none w-[700px] h-[500px] flex flex-col p-8 shadow-[12px_12px_0_0_rgba(0,0,0,1)]">
        <div class="font-['Orbitron'] text-[16px] font-bold text-black tracking-[2px] mb-6 flex items-center justify-between border-b-2 border-black pb-4">
           <span>👀 SENTINEL ANOMALY LOG</span>
           <button class="text-black hover:bg-black hover:text-white px-3 py-1 border-2 border-transparent hover:border-black font-bold transition-all" @click="modalOpen = null">✕ CLOSE</button>
        </div>
        
        <div class="flex-1 overflow-y-auto bg-gray-50 border-2 border-black p-5 space-y-4 font-mono">
            <div v-for="an in sentinelAnomalies" :key="an.detected_at" class="border-b-2 border-gray-200 pb-4 last:border-0">
                <div class="flex justify-between items-center mb-2">
                    <span :class="an.severity === 'Critical' ? 'bg-black text-white px-2 py-0.5 font-bold uppercase tracking-wider text-[11px]' : 'border border-black px-2 py-0.5 font-bold uppercase tracking-wider text-[11px]'">[{{ an.anomaly_type }}]</span>
                    <span class="text-gray-500 text-[11px] font-bold">{{ new Date(an.detected_at * 1000).toLocaleTimeString() }}</span>
                </div>
                <div class="text-black text-[13px] font-medium leading-relaxed my-2">{{ an.description }}</div>
                <div class="text-[11px] text-gray-500 mt-2 flex justify-between bg-white p-2 border border-black">
                    <span class="font-bold">Entity: <span class="text-black">{{ an.entity_id.substring(0,8) }}...</span></span>
                    <span class="font-bold uppercase text-black">Action: {{ an.recommended_action }}</span>
                </div>
            </div>
            <div v-if="!sentinelAnomalies.length" class="text-center mt-16 text-black font-bold tracking-widest uppercase opacity-50 text-[14px]">
               No anomalies detected in the last 24h
            </div>
        </div>
      </div>
    </div>

  </div>
</template>

<style>
@keyframes fadeSlide { from { opacity: 0; transform: translateX(-8px); } to { opacity: 1; transform: none; } }
.animate-fade-slide { animation: fadeSlide .3s cubic-bezier(0.16, 1, 0.3, 1) forwards; }

.lm b { color: #000; font-weight: 800; }
.lm .vc { color: #000; font-weight: bold; }
.lm .vg { color: #000; font-weight: bold; }
.lm .vr { color: #000; font-weight: bold; background: #eee; padding: 0 4px; }
.lm .va { color: #000; font-weight: bold; border-bottom: 2px solid #000; }
.lm .vp { color: #000; font-style: italic; font-weight: bold; }
.lm .vd { color: #666; font-size: 11px; }
.lm .hash { color: #666; font-size: 11px; font-family: monospace; }

.lv { font-size: 10px; font-weight: 800; padding: 2px 6px; border-radius: 0; flex-shrink: 0; align-self: flex-start; margin-top: 1px; letter-spacing: 1px; white-space: nowrap; border: 1px solid #000; }
.v-ok { background: #fff; color: #000; border: 2px solid #000; }
.v-info { background: #f3f4f6; color: #000; }
.v-warn { background: #e5e7eb; color: #000; border-bottom: 2px solid #000; }
.v-err { background: #000; color: #fff; border: 2px solid #000; }
.v-ai { background: #fff; color: #000; border: 1px dashed #000; }
.v-net { background: #fff; color: #000; border-left: 3px solid #000; border-right: none; border-top: none; border-bottom: none;}
.v-sys { background: #f9fafb; color: #6b7280; border: 1px solid #e5e7eb; }


.alert-block { margin: 8px 0; border: 2px solid #000; background: #fff; border-radius: 0; padding: 10px 14px; box-shadow: 4px 4px 0 0 #000; animation: alertIn .3s ease; }
@keyframes alertIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: none; } }
.ab-head { color: #000; font-size: 12px; font-weight: 900; letter-spacing: 2px; display: flex; align-items: center; gap: 8px; margin-bottom: 8px; text-transform: uppercase; border-bottom: 2px solid #000; padding-bottom: 4px;}
.ab-row { font-size: 12px; color: #000; margin: 3px 0; display: flex; gap: 12px; font-weight: 500;}
.ab-key { color: #666; min-width: 90px; font-weight: 700; text-transform: uppercase; font-size: 10px; padding-top: 2px; }
.ab-val { color: #000; font-weight: 800;}
.ab-val.vg { color: #000; background: #eee; padding: 0 4px; }

.flow-line { display: flex; align-items: center; gap: 8px; font-size: 11px; padding: 4px 0; margin: 2px 0; border-bottom: 1px dashed #ccc;}
.flow-src { color: #000; min-width: 130px; font-size: 11px; font-weight: 700; }
.flow-arrow { color: #999; flex-shrink: 0; font-weight: bold;}
.flow-dst { color: #000; min-width: 130px; font-size: 11px; font-weight: 700; }
.flow-bytes { color: #666; font-size: 10px; margin-left: auto; font-family: monospace;}
.flow-intent { color: #000; font-size: 10px; font-style: italic; font-weight: 600;}
.flow-trust { font-weight: 900; font-size: 11px; border: 1px solid #000; padding: 1px 4px; background: #fff;}
.flow-trust.vg { background: #f3f4f6; }
.flow-trust.va { border-bottom-width: 3px; }
.flow-trust.vr { background: #000; color: #fff;}

.cb { background: #fff; border: 2px solid #000; color: #000; font-family: 'JetBrains Mono', monospace; font-size: 11px; padding: 8px 12px; border-radius: 0; cursor: pointer; transition: all .2s; display: flex; flex-direction: column; align-items: flex-start; gap: 2px; min-width: 100px; box-shadow: 2px 2px 0 0 #000;}
.cb:hover { transform: translate(-1px, -1px); box-shadow: 4px 4px 0 0 #000; background: #f9fafb;}
.cb:active { transform: translate(2px, 2px); box-shadow: 0 0 0 0 #000; }
.cb .cbn { font-size: 12px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px;}
.cb .cbc { font-size: 10px; color: #666; font-weight: 600;}
.cb.danger { border-color: #000; }
.cb.danger:hover { background: #000; }
.cb.danger:hover .cbn, .cb.danger:hover .cbc { color: #fff; }
.cb.ai-cmd { border-style: dashed; }
.cb.ai-cmd:hover { background: #eee; border-style: solid;}

.arrow-r { color: #000; font-weight: 900;}
.arrow-l { color: #000; font-weight: 900;}

</style>
