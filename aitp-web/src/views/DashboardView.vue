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
import SentinelFeed from '../components/dashboard/SentinelFeed.vue'

const store = useAitpStore()
useAitpSocket() // Initialize real-time connection

const activeTab = ref('overview')

const navItems = [
  { id: 'overview', name: 'Overview', icon: '📊' },
  { id: 'sessions', name: 'Live Sessions', icon: '🔗' },
  { id: 'trust', name: 'Trust Engine', icon: '🧠' },
  { id: 'sentinel', name: 'Sentinel AI', icon: '👀' },
  { id: 'attacks', name: 'Attack Monitor', icon: '🛡️' },
  { id: 'lab', name: 'Test Lab', icon: '🧪' },
  { id: 'config', name: 'Configuration', icon: '⚙️' }
]
</script>

<template>
  <div class="h-screen flex bg-gray-100 overflow-hidden text-black font-sans">
    <!-- Sidebar -->
    <aside class="w-64 border-r-2 border-black flex flex-col pt-24 bg-white z-20 shadow-[4px_0_0_0_#000]">
      <nav class="flex-1 px-4 space-y-2">
        <button v-for="item in navItems" :key="item.id"
                @click="activeTab = item.id"
                class="w-full flex items-center gap-4 px-4 py-3 rounded-none transition-all duration-200 font-mono text-xs uppercase tracking-widest font-bold"
                :class="activeTab === item.id ? 'bg-black text-white border-2 border-black shadow-[4px_4px_0_0_#ccc]' : 'text-gray-600 hover:text-black border-2 border-transparent hover:border-black'">
           <span class="text-lg opacity-80" :class="activeTab === item.id ? 'opacity-100' : ''">{{ item.icon }}</span>
           {{ item.name }}
        </button>
      </nav>
      
      <div class="p-6 border-t-2 border-black space-y-4">
        <div class="flex items-center justify-between text-[10px] font-mono font-bold tracking-tighter uppercase">
          <span class="text-gray-600">Node_Alpha</span>
          <span class="text-black animate-pulse border border-black px-1.5 py-0.5 shadow-[2px_2px_0_0_#000]">ONLINE</span>
        </div>
        <div class="flex items-center justify-between text-[10px] font-mono font-bold tracking-tighter uppercase">
          <span class="text-gray-600">Node_Beta</span>
          <span class="text-black animate-pulse border border-black px-1.5 py-0.5 shadow-[2px_2px_0_0_#000]">ONLINE</span>
        </div>
      </div>
    </aside>

    <!-- Main Content -->
    <main class="flex-1 overflow-y-auto pt-24 px-8 pb-12 relative z-10">
      <!-- Grid Background -->
      <div class="fixed inset-0 bg-[linear-gradient(#f3f4f6_1px,transparent_1px),linear-gradient(90deg,#f3f4f6_1px,transparent_1px)] bg-[size:30px_30px] opacity-80 pointer-events-none"></div>

      <!-- Overview Tab -->
      <div v-if="activeTab === 'overview'" class="space-y-8 animate-in fade-in duration-500">
        <!-- Top Row: Stats -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <StatCard title="Active Sessions" :value="store.metrics.activeSessions" detail="+12 last 60s" color="black" />
          <StatCard title="Trust Score (avg)" :value="store.metrics.trustScoreAvg" detail="ALLOW status" color="black" />
          <StatCard title="Threats Blocked" :value="store.metrics.threatsBlocked" detail="last 1 hour" color="black" />
          <StatCard title="Gemini Calls" :value="store.metrics.geminiCalls" detail="avg 2.3ms" color="black" />
        </div>

        <!-- Middle Row: Main Visuals -->
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
          <div class="lg:col-span-2 cyber-panel h-[500px] flex flex-col p-0 overflow-hidden bg-white border-2 border-black shadow-[6px_6px_0_0_#000]">
            <h3 class="font-display font-bold text-[13px] uppercase tracking-widest border-b-2 border-black p-4 bg-gray-50">Live Network Graph</h3>
            <div class="flex-1 relative bg-white">
               <LiveNetworkGraph />
               <div class="absolute bottom-4 left-4 font-mono text-[9px] font-bold text-gray-500 flex gap-4 uppercase border-2 border-gray-200 bg-white p-2">
                 <div class="flex items-center gap-1"><span class="w-2.5 h-2.5 rounded-none border border-black bg-white"></span> Verified</div>
                 <div class="flex items-center gap-1"><span class="w-2.5 h-2.5 rounded-none border border-black bg-gray-300"></span> Monitoring</div>
                 <div class="flex items-center gap-1"><span class="w-2.5 h-2.5 rounded-none border border-black bg-black"></span> Alert</div>
               </div>
            </div>
          </div>
          
          <div class="cyber-panel h-[500px] flex flex-col bg-white border-2 border-black shadow-[6px_6px_0_0_#000] p-4">
             <h3 class="font-display font-bold text-[13px] uppercase tracking-widest border-b-2 border-black pb-4 mb-4">Trust Distribution</h3>
             <div class="flex-1 flex items-center justify-center border-2 border-dashed border-gray-300 bg-gray-50">
                <span class="font-mono font-bold text-[11px] text-gray-400 uppercase tracking-widest">Awaiting Data...</span>
             </div>
          </div>
        </div>

        <!-- Bottom Row: Timeline -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
           <div class="cyber-panel h-[300px] bg-white border-2 border-black shadow-[6px_6px_0_0_#000] p-4">
             <h3 class="font-display font-bold text-[13px] uppercase tracking-widest border-b-2 border-black pb-4 mb-4">Session Timeline</h3>
           </div>
           <div class="cyber-panel h-[300px] bg-white border-2 border-black shadow-[6px_6px_0_0_#000] p-4">
             <h3 class="font-display font-bold text-[13px] uppercase tracking-widest border-b-2 border-black pb-4 mb-4">Gemini Trust Engine Status</h3>
           </div>
        </div>
      </div>

      <!-- Live Sessions Tab -->
      <div v-else-if="activeTab === 'sessions'">
        <LiveSessions />
      </div>

      <!-- Sentinel Tab -->
      <div v-else-if="activeTab === 'sentinel'">
        <SentinelFeed />
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
        <div class="text-center space-y-4 border-2 border-black bg-white shadow-[8px_8px_0_0_#ccc] p-12">
           <div class="text-6xl grayscale">🚧</div>
           <h2 class="font-display font-bold text-xl uppercase tracking-widest text-black">{{ navItems.find(n => n.id === activeTab).name }} Terminal</h2>
           <p class="font-mono font-bold text-xs text-gray-400 uppercase tracking-widest">Section Under Construction</p>
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
