<script setup>
import { useAitpStore } from '../../stores/aitp'

const store = useAitpStore()

function getSeverityColor(type) {
  if (type.includes('BLOCKED') || type.includes('INVALID')) return 'text-accent-red'
  if (type.includes('FLAGGED') || type.includes('LIMITED')) return 'text-accent-amber'
  return 'text-white/40'
}
</script>

<template>
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-8 h-[calc(100vh-200px)] animate-in slide-in-from-bottom-4 duration-500">
    <!-- Left: Threat Feed -->
    <div class="cyber-panel flex flex-col p-0 overflow-hidden">
      <h3 class="font-display text-xs uppercase tracking-widest border-b border-white/5 p-4 flex justify-between items-center">
        Live Threat Feed
        <span class="text-[8px] font-mono text-accent-red animate-pulse">MONITORING_ACTIVE</span>
      </h3>
      
      <div class="flex-1 overflow-y-auto p-4 font-mono text-[10px] space-y-2 bg-black/20">
        <div v-for="(event, idx) in store.attackEvents" :key="idx" 
             class="flex gap-4 border-b border-white/5 pb-2 hover:bg-white/5 transition-colors">
          <span class="text-white/20 whitespace-nowrap">[{{ new Date().toLocaleTimeString() }}]</span>
          <span class="font-bold whitespace-nowrap" :class="getSeverityColor(event.type)">{{ event.type }}</span>
          <span class="text-white/60 flex-1">{{ event.detail }}</span>
          <span class="text-white/20 whitespace-nowrap">{{ event.src }} → NODE</span>
        </div>
        
        <div v-if="store.attackEvents.length === 0" class="h-full flex items-center justify-center opacity-10 uppercase tracking-widest">
           Clean Terminal — No Threats Detected
        </div>
      </div>
    </div>

    <!-- Right: Attack Map Placeholder -->
    <div class="cyber-panel flex flex-col p-0 overflow-hidden">
      <h3 class="font-display text-xs uppercase tracking-widest border-b border-white/5 p-4">Global Attack Map</h3>
      <div class="flex-1 bg-black/40 flex items-center justify-center relative">
         <div class="w-full h-full opacity-20 pointer-events-none grayscale flex items-center justify-center text-8xl">🌍</div>
         <div class="absolute inset-0 flex items-center justify-center">
            <span class="font-mono text-[10px] opacity-30 uppercase tracking-[0.5em]">Geographical Engine Initializing...</span>
         </div>
      </div>
    </div>
  </div>
</template>
