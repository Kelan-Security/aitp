<script setup>
import { ref } from 'vue'
import { useAitpStore } from '../stores/aitp'
import { useAitpSocket } from '../composables/useAitpSocket'
import StatCard from '../components/dashboard/StatCard.vue'
import LiveNetworkGraph from '../components/dashboard/LiveNetworkGraph.vue'
import LiveSessions from '../components/dashboard/LiveSessions.vue'
import AttackMonitor from '../components/dashboard/AttackMonitor.vue'
import TestLab from '../components/dashboard/TestLab.vue'
import ConfigView from '../components/dashboard/ConfigView.vue'

const store = useAitpStore()
useAitpSocket() // Initialize real-time connection

const activeTab = ref('overview')

const navItems = [
  { id: 'overview', name: 'Overview', icon: '📊' },
  { id: 'sessions', name: 'Live Sessions', icon: '🔗' },
  { id: 'trust', name: 'Trust Engine', icon: '🧠' },
  { id: 'attacks', name: 'Attack Monitor', icon: '🛡️' },
  { id: 'lab', name: 'Test Lab', icon: '🧪' },
  { id: 'config', name: 'Configuration', icon: '⚙️' }
]
</script>

<template>
  <div class="h-screen flex bg-bg-primary overflow-hidden">
    <!-- Sidebar -->
    <aside class="w-64 border-r border-white/5 flex flex-col pt-24 bg-bg-secondary/30 backdrop-blur-xl z-20">
      <nav class="flex-1 px-4 space-y-2">
        <button v-for="item in navItems" :key="item.id"
                @click="activeTab = item.id"
                class="w-full flex items-center gap-4 px-4 py-3 rounded-sm transition-all duration-300 font-mono text-xs uppercase tracking-widest"
                :class="activeTab === item.id ? 'bg-accent-cyan/10 text-accent-cyan border-l-2 border-accent-cyan' : 'text-white/40 hover:text-white hover:bg-white/5'">
          <span class="text-lg opacity-60">{{ item.icon }}</span>
          {{ item.name }}
        </button>
      </nav>
      
      <div class="p-6 border-t border-white/5 space-y-4">
        <div class="flex items-center justify-between text-[10px] font-mono tracking-tighter uppercase">
          <span class="text-white/20">Node_Alpha</span>
          <span class="text-accent-emerald animate-pulse">ONLINE</span>
        </div>
        <div class="flex items-center justify-between text-[10px] font-mono tracking-tighter uppercase">
          <span class="text-white/20">Node_Beta</span>
          <span class="text-accent-emerald animate-pulse">ONLINE</span>
        </div>
      </div>
    </aside>

    <!-- Main Content -->
    <main class="flex-1 overflow-y-auto pt-24 px-8 pb-12 relative z-10">
      <!-- Grid Background -->
      <div class="fixed inset-0 cyber-grid-bg opacity-10 pointer-events-none"></div>

      <!-- Overview Tab -->
      <div v-if="activeTab === 'overview'" class="space-y-8 animate-in fade-in duration-500">
        <!-- Top Row: Stats -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <StatCard title="Active Sessions" :value="store.metrics.activeSessions" detail="+12 last 60s" color="cyan" />
          <StatCard title="Trust Score (avg)" :value="store.metrics.trustScoreAvg" detail="ALLOW status" color="emerald" />
          <StatCard title="Threats Blocked" :value="store.metrics.threatsBlocked" detail="last 1 hour" color="red" />
          <StatCard title="Gemini Calls" :value="store.metrics.geminiCalls" detail="avg 2.3ms" color="amber" />
        </div>

        <!-- Middle Row: Main Visuals -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div class="lg:col-span-2 cyber-panel h-[500px] flex flex-col p-0 overflow-hidden">
            <h3 class="font-display text-xs uppercase tracking-widest border-b border-white/5 p-4">Live Network Graph</h3>
            <div class="flex-1 relative bg-black/20">
               <LiveNetworkGraph />
               <div class="absolute bottom-4 left-4 font-mono text-[8px] opacity-30 flex gap-4 uppercase">
                 <div class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-accent-emerald"></span> Verified</div>
                 <div class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-accent-amber"></span> Monitoring</div>
                 <div class="flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-accent-red"></span> Alert</div>
               </div>
            </div>
          </div>
          
          <div class="cyber-panel h-[500px] flex flex-col">
            <h3 class="font-display text-sm uppercase tracking-widest border-b border-white/5 pb-4 mb-4">Trust Distribution</h3>
             <div class="flex-1 flex items-center justify-center border border-dashed border-white/5 rounded-sm bg-black/40">
                <span class="font-mono text-[10px] opacity-20 uppercase">Awaiting Data...</span>
             </div>
          </div>
        </div>

        <!-- Bottom Row: Timeline -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
           <div class="cyber-panel h-[300px]">
             <h3 class="font-display text-sm uppercase tracking-widest border-b border-white/5 pb-4 mb-4">Session Timeline</h3>
           </div>
           <div class="cyber-panel h-[300px]">
             <h3 class="font-display text-sm uppercase tracking-widest border-b border-white/5 pb-4 mb-4">Gemini Trust Engine Status</h3>
           </div>
        </div>
      </div>

      <!-- Live Sessions Tab -->
      <div v-else-if="activeTab === 'sessions'">
        <LiveSessions />
      </div>

      <!-- Attack Monitor Tab -->
      <div v-else-if="activeTab === 'attacks'">
        <AttackMonitor />
      </div>

      <!-- Test Lab Tab -->
      <div v-else-if="activeTab === 'lab'">
        <TestLab />
      </div>

      <!-- Configuration Tab -->
      <div v-else-if="activeTab === 'config'">
        <ConfigView />
      </div>

      <!-- Other Tabs Placeholders -->
      <div v-else class="h-full flex items-center justify-center">
        <div class="text-center space-y-4">
           <div class="text-6xl grayscale opacity-20">🚧</div>
           <h2 class="font-display text-xl uppercase tracking-widest opacity-40">{{ navItems.find(n => n.id === activeTab).name }} Terminal</h2>
           <p class="font-mono text-xs opacity-20 uppercase">Section Under Construction</p>
        </div>
      </div>
    </main>
  </div>
</template>

<style>
@keyframes loading-bar {
  0% { transform: translateX(-100%); }
  100% { transform: translateX(100%); }
}
.animate-loading-bar {
  animation: loading-bar 2s infinite linear;
}
</style>
