<script setup>
import { ref, onMounted, onUnmounted } from 'vue'

const status = ref({ learning_entities: 0, monitored_entities: 0, anomalies_24h: 0, critical_24h: 0 })
const anomalies = ref([])
const baselines = ref([])
let timer

const fetchData = async () => {
    try {
        const [st, an, bl] = await Promise.all([
            fetch('/api/sentinel/status').then(r => r.json()),
            fetch('/api/sentinel/anomalies?limit=20').then(r => r.json()),
            fetch('/api/sentinel/baselines').then(r => r.json())
        ])
        status.value = st
        anomalies.value = an
        baselines.value = bl
    } catch(e) { console.error('Sentinel fetch error', e) }
}

const containEntity = async (entityId) => {
    if(!confirm(`Contain entity ${entityId}?`)) return
    try {
        await fetch('/api/sentinel/contain', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ entity_id: entityId, reason: 'Manual containment via Dashboard' })
        })
        await fetchData()
    } catch(e) { console.error(e) }
}

onMounted(() => {
    fetchData()
    timer = setInterval(fetchData, 10000)
})

onUnmounted(() => clearInterval(timer))

const getSeverityClass = (sev) => {
    if (sev === 'Critical') return 'text-accent-red font-bold'
    if (sev === 'Alert') return 'text-accent-amber font-bold'
    if (sev === 'Warning') return 'text-accent-amber'
    return 'text-accent-cyan'
}

const timeAgo = (ts) => {
    const s = Math.floor(Date.now() / 1000) - ts;
    if (s < 60) return `${s}s ago`
    const m = Math.floor(s / 60)
    if (m < 60) return `${m}m ago`
    return `${Math.floor(m / 60)}h ago`
}
</script>

<template>
  <div class="h-[calc(100vh-200px)] animate-in slide-in-from-bottom-4 duration-500 overflow-y-auto space-y-8 pr-4 scrollbar-thin scrollbar-thumb-white/10">
    
    <!-- Top Stats -->
    <div class="grid grid-cols-4 gap-4">
      <div class="cyber-panel flex flex-col items-center justify-center p-4">
         <span class="text-[10px] text-gray-500 font-mono mb-2 uppercase tracking-widest">Monitored Entities</span>
         <span class="font-display text-4xl text-black font-bold">{{ status.monitored_entities }}</span>
      </div>
      <div class="cyber-panel flex flex-col items-center justify-center p-4">
         <span class="text-[10px] text-gray-500 font-mono mb-2 uppercase tracking-widest">Learning</span>
         <span class="font-display text-4xl text-black font-bold">{{ status.learning_entities }}</span>
      </div>
      <div class="cyber-panel flex flex-col items-center justify-center p-4">
         <span class="text-[10px] text-gray-500 font-mono mb-2 uppercase tracking-widest">24h Anomalies</span>
         <span class="font-display text-4xl font-bold text-black">{{ status.anomalies_24h }}</span>
      </div>
      <div class="cyber-panel flex flex-col items-center justify-center p-4 border-l-4" :class="status.critical_24h > 0 ? 'border-black' : 'border-gray-200'">
         <span class="text-[10px] text-gray-500 font-mono mb-2 uppercase tracking-widest">Critical Threats</span>
         <span class="font-display text-4xl font-bold" :class="status.critical_24h > 0 ? 'text-black animate-pulse' : 'text-gray-300'">{{ status.critical_24h }}</span>
      </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
      
      <!-- Live Anomaly Log -->
      <div class="cyber-panel h-[400px] flex flex-col p-0">
        <h3 class="font-display text-[13px] font-bold uppercase tracking-widest border-b border-black p-4 flex justify-between items-center bg-gray-50">
          Live Anomaly Log
          <span class="text-[9px] font-mono text-black font-bold animate-pulse border border-black px-1">SENTINEL_ACTIVE</span>
        </h3>
        <div class="flex-1 overflow-y-auto bg-white p-2 text-[11px] font-mono scrollbar-thin">
           <div v-for="(an, i) in anomalies" :key="i" class="border-b-2 border-gray-100 p-3 flex flex-col gap-1 hover:bg-gray-50 transition-colors">
              <div class="flex justify-between items-center">
                 <span class="border border-black px-1.5 py-0.5 text-black font-bold uppercase text-[10px]">{{ an.anomaly_type }}</span>
                 <span class="text-gray-500 font-bold">{{ timeAgo(an.detected_at) }}</span>
              </div>
              <div class="text-black font-medium mt-1">{{ an.description }}</div>
              <div class="flex justify-between items-center mt-2">
                 <span class="text-gray-600 font-bold">Entity: <span class="text-black">{{ an.entity_id.substring(0,8) }}...</span></span>
                 <button v-if="an.severity === 'Critical' || an.severity === 'Alert'" @click="containEntity(an.entity_id)" class="text-[9px] border-2 border-black bg-black text-white px-3 py-1 font-bold rounded-none hover:bg-white flex items-center hover:text-black uppercase transition-colors">Contain</button>
              </div>
           </div>
           <div v-if="anomalies.length === 0" class="flex items-center justify-center p-8 opacity-40 font-bold text-gray-500 uppercase tracking-widest text-[13px]">No anomalies</div>
        </div>
      </div>

      <!-- Verified Baselines -->
      <div class="cyber-panel h-[400px] flex flex-col p-0">
        <h3 class="font-display text-[13px] font-bold uppercase tracking-widest border-b border-black p-4 bg-gray-50">Verified Baselines</h3>
        <div class="flex-1 overflow-y-auto bg-white text-[11px] font-mono p-2 scrollbar-thin">
           <div class="grid grid-cols-4 border-b-2 border-black pb-2 text-gray-600 font-bold uppercase tracking-wider mb-2 px-2 mt-2">
              <div>Entity</div>
              <div>Samples (50)</div>
              <div>Rate (/hr)</div>
              <div>Avg Trust</div>
           </div>
           <div v-for="(b, i) in baselines" :key="i" class="grid grid-cols-4 py-3 border-b border-gray-100 px-2 hover:bg-gray-50 transition-colors">
              <div class="text-black font-bold flex items-center">
                 {{ b.entity_id.substring(0,8) }}
              </div>
              <div>
                 <span class="font-bold text-black border border-black px-1">{{ b.session_count }}</span>
              </div>
              <div class="text-black font-medium">{{ b.avg_sessions_per_hour.toFixed(1) }}</div>
              <div class="text-black font-bold">{{ b.avg_trust_score.toFixed(0) }}</div>
           </div>
        </div>
      </div>

    </div>
  </div>
</template>
