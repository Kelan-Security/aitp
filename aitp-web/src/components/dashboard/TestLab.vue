<script setup>
import { ref } from 'vue'
import { useAitpStore } from '../../stores/aitp'

const store = useAitpStore()
const isRunning = ref(false)
const testLog = ref([])
const activeCategory = ref('ddos')

const tests = {
  ddos: [
    { id: 'syn_flood', name: 'SYN Flood Attack', desc: 'Sends 10,000 SYN packets from simulated IPs.' },
    { id: 'udp_flood', name: 'UDP Flood Attack', desc: 'Sends 100,000 malformed UDP packets.' },
    { id: 'slow_handshake', name: 'Slow Handshake', desc: 'Opens 500 sessions without completion.' }
  ],
  replay: [
    { id: 'nonce_replay', name: 'Nonce Replay', desc: 'Captures and replays a valid packet.' },
    { id: 'hijack_attempt', name: 'Session Hijack', desc: 'Attempts to inject into an active session.' }
  ]
}

function runTest(testId) {
  isRunning.value = true
  testLog.value = []
  
  const addLog = (msg) => {
    testLog.value.push(`[${new Date().toLocaleTimeString()}] ${msg}`)
  }

  addLog(`Starting ${testId.toUpperCase()} defense verification...`)
  
  // Simulation steps
  setTimeout(() => addLog('Initializing simulated attack vector...'), 500)
  setTimeout(() => {
    addLog('ATTACK_STARTED: Flooding target identity...')
    store.addAttackEvent({
      type: 'SYN_FLOOD_BLOCKED',
      detail: 'Rate limit exceeded for 847 identities',
      src: '192.168.1.100'
    })
  }, 1500)
  
  setTimeout(() => {
    addLog('eBPF XDP: Dropping unauthorized traffic at kernel level.')
    addLog('Verification: Legitimate sessions remain unaffected ✓')
    addLog('TEST_PASSED: Defense operational.')
    isRunning.value = false
  }, 4000)
}
</script>

<template>
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-8 h-[calc(100vh-200px)] animate-in slide-in-from-bottom-4 duration-500">
    <!-- Left: Controls -->
    <div class="cyber-panel flex flex-col gap-8">
      <div class="space-y-4">
        <h2 class="text-2xl font-black uppercase tracking-tighter">Test Lab</h2>
        <p class="font-mono text-[10px] text-white/40 uppercase">Simulation Engine v0.1</p>
      </div>

      <div class="flex border-b border-white/5 font-mono text-[10px] uppercase tracking-widest">
        <button v-for="cat in ['ddos', 'replay', 'spoofing', 'load']" :key="cat"
                @click="activeCategory = cat"
                class="px-6 py-3 transition-colors"
                :class="activeCategory === cat ? 'text-accent-cyan border-b-2 border-accent-cyan' : 'text-white/20 hover:text-white'">
          {{ cat }}
        </button>
      </div>

      <div class="space-y-4 flex-1 overflow-y-auto pr-2">
        <div v-for="test in tests[activeCategory] || []" :key="test.id"
             class="cyber-panel bg-white/5 border-white/10 hover:border-accent-cyan/30 transition-all p-4 space-y-4">
          <div class="flex justify-between items-start">
            <div class="space-y-1">
              <h4 class="font-bold text-sm">{{ test.name }}</h4>
              <p class="text-[10px] text-white/40">{{ test.desc }}</p>
            </div>
            <button @click="runTest(test.id)" :disabled="isRunning"
                    class="btn-primary text-[10px] px-4 py-2 h-auto"
                    :class="{ 'opacity-50 cursor-not-allowed grayscale': isRunning }">
              {{ isRunning ? 'RUNNING' : 'RUN_TEST' }}
            </button>
          </div>
          <div class="flex gap-4 text-[8px] font-mono text-white/20 uppercase">
             <span>Difficulty: HIGH</span>
             <span>Category: INBOUND_SECURITY</span>
          </div>
        </div>
        
        <div v-if="!tests[activeCategory]" class="h-40 flex items-center justify-center opacity-10 font-mono text-xs uppercase italic">
          No tests available for this category yet.
        </div>
      </div>
    </div>

    <!-- Right: Terminal Output -->
    <div class="cyber-panel bg-black flex flex-col p-4 font-mono text-xs overflow-hidden border-white/10">
      <div class="flex justify-between items-center border-b border-white/10 pb-2 mb-4">
        <span class="text-[10px] text-accent-cyan">SIMULATION_TERMINAL_v1.0</span>
        <div class="flex gap-1">
          <div class="w-2 h-2 rounded-full bg-accent-red"></div>
          <div class="w-2 h-2 rounded-full bg-accent-amber"></div>
          <div class="w-2 h-2 rounded-full bg-accent-emerald"></div>
        </div>
      </div>
      
      <div class="flex-1 overflow-y-auto space-y-1 text-white/80">
        <div v-for="(log, idx) in testLog" :key="idx" class="fade-in duration-300">
          <span class="text-white/20 mr-2">></span> {{ log }}
        </div>
        <div v-if="isRunning" class="animate-pulse">_</div>
        <div v-if="testLog.length === 0" class="h-full flex items-center justify-center opacity-10 text-[10px] uppercase tracking-[0.5em]">
          Waiting for Simulation Input...
        </div>
      </div>
    </div>
  </div>
</template>
