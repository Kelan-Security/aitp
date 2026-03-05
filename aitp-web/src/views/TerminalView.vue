<script setup>
import { ref, onMounted, onUnmounted, nextTick } from 'vue'
import { useRouter } from 'vue-router'

const router = useRouter()

const serverLogs = ref([])
const clientLogs = ref([])
const commandInput = ref('')
const serverLogContainer = ref(null)
const clientLogContainer = ref(null)

const connectedClients = ref([
  { id: 'client-beta', ip: '192.168.1.55:52341', trust: 206, intent: 'ModelInference' }
])

// Server Stats
const stats = ref({
  sessions: 1,
  avgTrust: 195,
  blocked: 1000,
  alerts: 3
})

const addServerLog = (level, message, isHtml = false) => {
  serverLogs.value.push({
    time: new Date().toISOString().substring(11, 23),
    level,
    message,
    isHtml
  })
  scrollToBottom(serverLogContainer)
}

const addClientLog = (level, message, isHtml = false) => {
  clientLogs.value.push({
    time: new Date().toISOString().substring(11, 23),
    level,
    message,
    isHtml
  })
  scrollToBottom(clientLogContainer)
}

const scrollToBottom = async (containerRef) => {
  await nextTick()
  if (containerRef.value) {
    containerRef.value.scrollTop = containerRef.value.scrollHeight
  }
}

const executeCommand = (cmd) => {
  if (!cmd) return
  
  // Parse command intent
  addClientLog('INFO', `Executing: ${cmd}`)
  
  if (cmd.includes('--connect')) {
    addClientLog('OK', 'Connected to AITP Server at 192.168.1.100:9999')
    addServerLog('INFO', 'New connection from 192.168.1.100:54321')
    stats.value.sessions++
  } else if (cmd.includes('--test ddos')) {
    addClientLog('WARN', 'Starting SYN flood simulation (1000 packets)...', true)
    setTimeout(() => {
      addClientLog('OK', 'Flood sent. Server handled it. Your legitimate connection: still alive.')
      stats.value.blocked += 1000
    }, 1500)
  } else if (cmd.includes('--test replay')) {
    addClientLog('INFO', 'Capturing live DATA packet for replay test...')
    setTimeout(() => {
      addClientLog('WARN', 'Replaying captured packet immediately...')
      addClientLog('ALERT', 'Replay <span class="text-accent-red">REJECTED</span> reason: <span class="text-accent-red">NONCE_ALREADY_SEEN</span> window: 30s', true)
      addServerLog('WARN', 'Dropped: Replay attack detected from 192.168.1.100')
      stats.value.alerts++
    }, 1000)
  } else if (cmd.includes('--revoke')) {
    addClientLog('INFO', 'Session revoked.')
    addServerLog('INFO', 'Session revoked by client 192.168.1.100')
    if (stats.value.sessions > 0) stats.value.sessions--
  } else {
    addClientLog('INFO', `Data sent to server.`)
    addServerLog('INFO', `Payload received from client.`)
  }
  
  commandInput.value = ''
}

const handleTerminalSubmit = () => {
  if (commandInput.value.trim()) {
    executeCommand(commandInput.value.trim())
  }
}

const runCommand = (cmd) => {
  commandInput.value = `aitp_client ${cmd}`
  handleTerminalSubmit()
}

// Initial demo logs
onMounted(() => {
  addServerLog('INFO', 'AITP server started — listening on 0.0.0.0:9999/UDP')
  addServerLog('TRUST', 'Continuous re-eval session: <span class="text-accent-cyan">${currentSessionId}</span> score: <span class="text-accent-emerald">${s}</span> ΔΔ behavioral: nominal', true)
  
  setTimeout(() => {
    addServerLog('INFO', 'Heartbeat session: <span class="text-accent-cyan">${currentSessionId}</span> rtt: <span class="text-accent-cyan">${(Math.random()*8+8).toFixed(1)}ms</span>', true)
  }, 2000)

  addClientLog('INFO', 'Server sent: <span class="text-accent-red">AITP_REJECT(ANONYMOUS_IDENTITY)</span>', true)
  addClientLog('OK', 'Packet captured nonce: ${capturedNonce} timestamp: <span class="text-accent-cyan">${ts()}</span>', true)
})
</script>

<template>
  <div class="fixed inset-0 z-[100] bg-[#0a0f16] text-[#8a9cae] font-mono text-[13px] flex flex-col overflow-hidden selection:bg-accent-cyan/30">
    
    <!-- HEADER -->
    <header class="h-14 border-b border-white/5 flex items-center justify-between px-6 shrink-0 bg-[#0d131b]">
      <div class="flex items-center gap-6">
        <div class="flex items-center gap-4">
          <span class="font-display font-black text-2xl tracking-tighter text-accent-cyan">AITP</span>
          <span class="text-white/30 text-xs tracking-widest uppercase">Protocol</span>
        </div>
        <div class="h-4 w-px bg-white/10"></div>
        <span class="text-white/40 tracking-wider">v0.2.0 – Adaptive Intent Transport</span>
      </div>
      
      <div class="flex items-center gap-4 text-[10px] uppercase font-bold tracking-widest">
        <div class="flex items-center gap-2 px-3 py-1.5 border border-accent-emerald/30 bg-accent-emerald/5 text-accent-emerald rounded-sm">
          <div class="w-1.5 h-1.5 bg-accent-emerald rounded-full animate-pulse"></div>
          PROTOCOL ACTIVE
        </div>
        <div class="flex items-center gap-2 px-3 py-1.5 border border-accent-cyan/30 bg-accent-cyan/5 text-accent-cyan rounded-sm">
          GEMINI HYBRID
        </div>
        <div class="flex items-center gap-2 px-3 py-1.5 border border-accent-amber/30 bg-accent-amber/5 text-accent-amber rounded-sm">
          eBPF ENFORCING
        </div>
      </div>
    </header>

    <!-- WORKSPACE -->
    <div class="flex flex-1 min-h-0">
      
      <!-- LEFT PANEL: SERVER SIDE -->
      <div class="w-1/2 border-r border-white/5 flex flex-col min-h-0 bg-[#0a0f16]">
        
        <!-- Server Header -->
        <div class="h-12 border-b border-white/5 flex items-center justify-between px-4 bg-[#0d131b]">
          <div class="flex items-center gap-3">
            <div class="flex gap-1.5">
              <div class="w-2.5 h-2.5 rounded-full bg-accent-red"></div>
              <div class="w-2.5 h-2.5 rounded-full bg-accent-amber"></div>
              <div class="w-2.5 h-2.5 rounded-full bg-accent-emerald"></div>
            </div>
            <span class="text-accent-emerald font-bold tracking-[0.2em]">⬡ AITP SERVER NODE</span>
          </div>
          <div class="flex items-center gap-3">
            <div class="flex items-center gap-1.5 text-accent-emerald text-xs">
              <div class="w-1.5 h-1.5 bg-accent-emerald rounded-full"></div>
              LISTENING
            </div>
            <span class="bg-black/40 px-2 border border-white/5 text-white/50 py-0.5 rounded text-xs">0.0.0.0:9999/UDP</span>
          </div>
        </div>

        <!-- Connected Clients -->
        <div class="p-4 border-b border-white/5 bg-[#0a0f16]/50">
          <div class="text-xs text-white/40 tracking-widest mb-3 flex items-center gap-2">
            <div class="w-1.5 h-1.5 bg-white/20 rounded-full"></div>
            CONNECTED CLIENTS ({{stats.sessions}})
          </div>
          <div class="space-y-2">
            <div v-for="client in connectedClients" :key="client.id" class="flex items-center justify-between text-xs">
              <div class="flex items-center gap-2">
                <div class="w-1.5 h-1.5 bg-accent-emerald rounded-full shadow-[0_0_5px_#10b981]"></div>
                <span class="text-accent-cyan font-bold">{{client.id}}</span>
              </div>
              <span class="text-white/40">{{client.ip}}</span>
              <span class="text-accent-emerald font-bold">{{client.trust}}</span>
              <span class="text-purple-400">{{client.intent}}</span>
            </div>
          </div>
        </div>

        <!-- Server Logs -->
        <div class="flex-1 overflow-y-auto p-4 space-y-2" ref="serverLogContainer">
          <div v-for="(log, i) in serverLogs" :key="i" class="flex items-start gap-4 font-mono text-[11px] leading-relaxed">
            <span class="text-white/30 shrink-0">{{log.time}}</span>
            <span :class="{
              'bg-blue-500/10 text-blue-400 border-blue-500/30': log.level === 'INFO',
              'bg-purple-500/10 text-purple-400 border-purple-500/30': log.level === 'TRUST',
              'bg-emerald-500/10 text-emerald-400 border-emerald-500/30': log.level === 'OK',
              'bg-red-500/10 text-red-400 border-red-500/30': log.level === 'ALERT',
              'bg-amber-500/10 text-amber-400 border-amber-500/30': log.level === 'WARN'
            }" class="px-1.5 border leading-none py-0.5 rounded-sm shrink-0 min-w-[50px] text-center uppercase tracking-wider text-[10px]">
              {{log.level}}
            </span>
            <span class="text-white/70" v-if="log.isHtml" v-html="log.message"></span>
            <span class="text-white/70" v-else>{{log.message}}</span>
          </div>
        </div>

        <!-- Server Stats Footer -->
        <div class="h-16 border-t border-white/5 flex grid grid-cols-4 bg-[#0d131b]">
          <div class="flex flex-col items-center justify-center border-r border-white/5">
            <span class="font-display font-black text-2xl text-accent-emerald">{{stats.sessions}}</span>
            <span class="text-[10px] tracking-widest text-white/30 uppercase">Sessions</span>
          </div>
          <div class="flex flex-col items-center justify-center border-r border-white/5">
            <span class="font-display font-black text-2xl text-accent-cyan">{{stats.avgTrust}}</span>
            <span class="text-[10px] tracking-widest text-white/30 uppercase">Avg Trust</span>
          </div>
          <div class="flex flex-col items-center justify-center border-r border-white/5">
            <span class="font-display font-black text-2xl text-accent-red">{{stats.blocked}}</span>
            <span class="text-[10px] tracking-widest text-white/30 uppercase">Blocked</span>
          </div>
          <div class="flex flex-col items-center justify-center">
            <span class="font-display font-black text-2xl text-accent-amber">{{stats.alerts}}</span>
            <span class="text-[10px] tracking-widest text-white/30 uppercase">Alerts</span>
          </div>
        </div>

      </div>

      <!-- RIGHT PANEL: CLIENT SIDE -->
      <div class="w-1/2 flex flex-col min-h-0 bg-[#0a0f16]">
        
        <!-- Client Header -->
        <div class="h-12 border-b border-white/5 flex items-center justify-between px-4 bg-[#0d131b]">
          <div class="flex items-center gap-3">
            <div class="flex gap-1.5">
              <div class="w-2.5 h-2.5 rounded-full bg-accent-red"></div>
              <div class="w-2.5 h-2.5 rounded-full bg-accent-amber"></div>
              <div class="w-2.5 h-2.5 rounded-full bg-accent-cyan"></div>
            </div>
            <span class="text-accent-cyan font-bold tracking-[0.2em]">⬢ AITP CLIENT NODE</span>
          </div>
          <div class="flex items-center gap-3">
             <div class="flex items-center gap-1.5 text-accent-emerald text-xs">
              <div class="w-1.5 h-1.5 bg-accent-emerald rounded-full"></div>
              CONNECTED
            </div>
            <span class="bg-black/40 px-2 border border-white/5 text-white/50 py-0.5 rounded text-xs">192.168.1.100:9999</span>
          </div>
        </div>

        <!-- Client Logs -->
        <div class="flex-1 overflow-y-auto p-4 space-y-3" ref="clientLogContainer">
           <div v-for="(log, i) in clientLogs" :key="i" class="flex items-start gap-4 font-mono text-[11px] leading-relaxed">
            <span class="text-white/30 shrink-0">{{log.time}}</span>
            <span :class="{
              'bg-blue-500/10 text-blue-400 border-blue-500/30': log.level === 'INFO',
              'bg-emerald-500/10 text-emerald-400 border-emerald-500/30': log.level === 'OK',
              'bg-red-500/10 text-red-400 border-red-500/30': log.level === 'ALERT',
              'bg-amber-500/10 text-amber-400 border-amber-500/30': log.level === 'WARN'
            }" class="px-1.5 border leading-none py-0.5 rounded-sm shrink-0 min-w-[50px] text-center uppercase tracking-wider text-[10px]">
              {{log.level}}
            </span>
            <span class="text-white/80" v-if="log.isHtml" v-html="log.message"></span>
            <span class="text-white/80" v-else>{{log.message}}</span>
          </div>
        </div>

        <!-- Interactive Controls -->
        <div class="border-t border-white/5 bg-[#0d131b] p-4 flex flex-col gap-3">
          <div class="text-[10px] text-white/30 tracking-widest uppercase flex items-center gap-2">
            <span class="opacity-50">▶</span> AVAILABLE COMMANDS
          </div>
          
          <div class="grid grid-cols-4 gap-2">
            <button @click="runCommand('--connect 192.168.1.100:9999')" class="border border-white/5 hover:border-accent-cyan/50 hover:bg-accent-cyan/5 p-2 rounded flex flex-col items-center justify-center gap-1 text-white/60 hover:text-white transition-colors">
              <span class="text-sm">🔗 Connect</span>
              <span class="text-[9px] opacity-40">--connect</span>
            </button>
            <button @click="runCommand('--intent model')" class="border border-white/5 hover:border-accent-cyan/50 hover:bg-accent-cyan/5 p-2 rounded flex flex-col items-center justify-center gap-1 text-white/60 hover:text-white transition-colors">
              <span class="text-sm">🤖 Inference</span>
              <span class="text-[9px] opacity-40">--intent model</span>
            </button>
            <button @click="runCommand('--intent sync')" class="border border-white/5 hover:border-accent-cyan/50 hover:bg-accent-cyan/5 p-2 rounded flex flex-col items-center justify-center gap-1 text-white/60 hover:text-white transition-colors">
              <span class="text-sm">🔄 Data Sync</span>
              <span class="text-[9px] opacity-40">--intent sync</span>
            </button>
            <button @click="runCommand('--no-identity')" class="border border-white/5 hover:border-accent-red/50 hover:bg-accent-red/5 p-2 rounded flex flex-col items-center justify-center gap-1 text-white/60 hover:text-white transition-colors">
               <span class="text-sm">👻 Anon Test</span>
              <span class="text-[9px] opacity-40">--no-identity</span>
            </button>
            
            <button @click="runCommand('--test ddos')" class="border border-white/5 hover:border-accent-amber/50 hover:bg-accent-amber/5 p-2 rounded flex flex-col items-center justify-center gap-1 text-white/60 hover:text-white transition-colors">
               <span class="text-sm">💥 SYN Flood</span>
              <span class="text-[9px] opacity-40">--test ddos</span>
            </button>
            <button @click="runCommand('--test replay')" class="border border-white/5 hover:border-accent-amber/50 hover:bg-accent-amber/5 p-2 rounded flex flex-col items-center justify-center gap-1 text-white/60 hover:text-white transition-colors">
               <span class="text-sm">↩️ Replay Atk</span>
              <span class="text-[9px] opacity-40">--test replay</span>
            </button>
            <button @click="runCommand('--status')" class="border border-white/5 hover:border-emerald-400/50 hover:bg-emerald-400/5 p-2 rounded flex flex-col items-center justify-center gap-1 text-white/60 hover:text-white transition-colors">
               <span class="text-sm">📊 Status</span>
              <span class="text-[9px] opacity-40">--status</span>
            </button>
            <button @click="runCommand('--revoke')" class="border border-white/5 hover:border-accent-red/50 hover:bg-accent-red/5 p-2 rounded flex flex-col items-center justify-center gap-1 text-white/60 hover:text-white transition-colors">
               <span class="text-sm">🚫 Revoke</span>
              <span class="text-[9px] opacity-40">--revoke</span>
            </button>
          </div>
        </div>

        <!-- CLI Input -->
        <form @submit.prevent="handleTerminalSubmit" class="h-10 border-t border-white/5 bg-black flex items-center px-4 font-mono text-[13px]">
          <span class="text-accent-cyan font-bold shrink-0">aitp-client $</span>
          <input 
            v-model="commandInput" 
            type="text" 
            class="flex-1 bg-transparent border-none outline-none text-white/90 px-3 placeholder:text-white/20"
            placeholder="aitp_client --connect 192.168.1.100"
            autofocus
          />
        </form>

      </div>
    </div>
  </div>
</template>

<style scoped>
/* Custom scrollbar for terminals */
::-webkit-scrollbar {
  width: 6px;
  height: 6px;
}
::-webkit-scrollbar-track {
  background: transparent;
}
::-webkit-scrollbar-thumb {
  background-color: rgba(255, 255, 255, 0.1);
  border-radius: 10px;
}
::-webkit-scrollbar-corner {
  background: transparent;
}
</style>
