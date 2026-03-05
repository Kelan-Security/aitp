<script setup>
import { ref } from 'vue'

const config = ref({
  node: {
    identity_id: '847a...f912',
    port: 9999,
    log_level: 'DEBUG'
  },
  ai: {
    engine: 'GEMINI_2.0',
    min_trust: 128,
    mode: 'HYBRID'
  },
  ebpf: {
    enabled: true,
    interface: 'eth0',
    mode: 'XDP_DRV'
  }
})

const isSaving = ref(false)

function saveConfig() {
  isSaving.value = true
  setTimeout(() => {
    isSaving.value = false
    alert('Config Synchronized with Control Plane')
  }, 1000)
}
</script>

<template>
  <div class="max-w-4xl mx-auto space-y-8 animate-in slide-in-from-bottom-4 duration-500 pb-20">
    <div class="flex justify-between items-center">
      <div class="space-y-1">
        <h2 class="text-2xl font-black uppercase tracking-tighter">Configuration</h2>
        <p class="font-mono text-[10px] text-white/40 uppercase">AITP.TOML TERMINAL EDITOR</p>
      </div>
      <button @click="saveConfig" :disabled="isSaving" 
              class="btn-primary px-8 h-12 text-xs">
        {{ isSaving ? 'SYNCHRONIZING...' : 'SAVE_AND_RELOAD' }}
      </button>
    </div>

    <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
      <!-- Node Settings -->
      <div class="cyber-panel space-y-6">
        <h3 class="font-display text-xs text-accent-cyan uppercase tracking-widest border-b border-white/5 pb-4">Core_Node</h3>
        <div class="space-y-4">
          <div class="space-y-1">
            <label class="font-mono text-[9px] text-white/40 uppercase">Identity_ID</label>
            <input v-model="config.node.identity_id" readonly class="w-full bg-black/40 border border-white/5 p-3 font-mono text-xs opacity-50 cursor-not-allowed">
          </div>
          <div class="grid grid-cols-2 gap-4">
            <div class="space-y-1">
              <label class="font-mono text-[9px] text-white/40 uppercase">Port</label>
              <input v-model="config.node.port" type="number" class="w-full bg-white/5 border border-white/10 p-3 font-mono text-xs focus:border-accent-cyan outline-none transition-colors">
            </div>
            <div class="space-y-1">
              <label class="font-mono text-[9px] text-white/40 uppercase">Log_Level</label>
              <select v-model="config.node.log_level" class="w-full bg-white/5 border border-white/10 p-3 font-mono text-xs focus:border-accent-cyan outline-none transition-colors appearance-none">
                <option>INFO</option>
                <option>DEBUG</option>
                <option>TRACE</option>
                <option>WARN</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      <!-- AI Settings -->
      <div class="cyber-panel space-y-6">
        <h3 class="font-display text-xs text-accent-emerald uppercase tracking-widest border-b border-white/5 pb-4">AI_Trust_Engine</h3>
        <div class="space-y-4">
           <div class="space-y-1">
            <label class="font-mono text-[9px] text-white/40 uppercase">Min_Trust_Threshold</label>
            <input v-model="config.ai.min_trust" type="range" min="0" max="255" class="w-full accent-accent-emerald">
            <div class="flex justify-between font-mono text-[8px] opacity-40">
               <span>0 (DENY_ALL)</span>
               <span class="text-accent-emerald font-bold">{{ config.ai.min_trust }}</span>
               <span>255 (ALLOW_ALL)</span>
            </div>
          </div>
          <div class="space-y-1">
            <label class="font-mono text-[9px] text-white/40 uppercase">Execution_Mode</label>
            <div class="flex gap-2 p-1 bg-white/5 rounded-sm">
               <button v-for="m in ['RULES', 'HYBRID', 'GEMINI']" :key="m"
                       @click="config.ai.mode = m"
                       class="flex-1 py-2 font-mono text-[9px] transition-all"
                       :class="config.ai.mode === m ? 'bg-accent-emerald text-bg-primary font-bold' : 'hover:bg-white/5'">
                 {{ m }}
               </button>
            </div>
          </div>
        </div>
      </div>

      <!-- eBPF Settings -->
      <div class="cyber-panel space-y-6 md:col-span-2">
        <h3 class="font-display text-xs text-accent-cyan uppercase tracking-widest border-b border-white/5 pb-4">Kernel_Enforcement (eBPF)</h3>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
           <div class="flex items-center gap-4">
             <div class="relative inline-block w-12 h-6 transition duration-200 ease-in-out bg-white/10 rounded-full cursor-pointer"
                  :class="{ 'bg-accent-cyan': config.ebpf.enabled }"
                  @click="config.ebpf.enabled = !config.ebpf.enabled">
               <div class="absolute w-4 h-4 bg-white rounded-full transition-transform duration-200 ease-in-out top-1 left-1"
                    :class="{ 'translate-x-6': config.ebpf.enabled }"></div>
             </div>
             <span class="font-mono text-[10px] uppercase">XDP_OFFLOAD_{{ config.ebpf.enabled ? 'ACTIVE' : 'DISABLED' }}</span>
           </div>
           <div class="space-y-1">
              <label class="font-mono text-[9px] text-white/40 uppercase">Interface</label>
              <input v-model="config.ebpf.interface" class="w-full bg-white/5 border border-white/10 p-3 font-mono text-xs focus:border-accent-cyan outline-none transition-colors">
           </div>
           <div class="space-y-1">
              <label class="font-mono text-[9px] text-white/40 uppercase">XDP_Mode</label>
              <input v-model="config.ebpf.mode" class="w-full bg-white/5 border border-white/10 p-3 font-mono text-xs focus:border-accent-cyan outline-none transition-colors">
           </div>
        </div>
      </div>
    </div>
  </div>
</template>
