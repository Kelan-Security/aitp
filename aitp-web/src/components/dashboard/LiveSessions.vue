<script setup>
import { useAitpStore } from '../../stores/aitp'

const store = useAitpStore()

function getStatusColor(status) {
  if (status === 'REVOKED') return 'text-black bg-white px-1 line-through'
  if (status === 'ESTABLISHED') return 'text-white font-bold'
  return 'text-white/40'
}

function getTrustColor(score) {
  if (score > 128) return 'border-white/40'
  if (score > 64) return 'border-white/20'
  return 'border-white/10'
}
</script>

<template>
  <div class="space-y-6 animate-in slide-in-from-bottom-4 duration-500">
    <div class="flex justify-between items-center">
      <h2 class="text-2xl font-black uppercase tracking-tighter">Live Sessions</h2>
      <div class="flex gap-4">
        <input type="text" placeholder="FILTER_BY_IDENTITY" 
               class="bg-white/5 border border-white/10 px-4 py-2 font-mono text-[10px] focus:border-accent-cyan outline-none transition-colors">
      </div>
    </div>

    <div class="cyber-panel p-0 overflow-hidden">
      <table class="w-full text-left font-mono text-xs">
        <thead class="bg-white/5 uppercase text-[10px] text-white/40 tracking-widest">
          <tr>
            <th class="p-4">Session_ID</th>
            <th class="p-4">Tier</th>
            <th class="p-4">Source</th>
            <th class="p-4">Destination</th>
            <th class="p-4">Intent</th>
            <th class="p-4 text-center">Trust</th>
            <th class="p-4">Status</th>
            <th class="p-4 text-right">Actions</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-white/5">
          <tr v-for="session in store.sessions" :key="session.id" 
              class="hover:bg-white/5 transition-colors group border-l-2"
              :class="getTrustColor(session.trust_score)">
            <td class="p-4 text-white/80">{{ session.id.substring(0, 8) }}...</td>
            <td class="p-4"><span class="px-2 py-0.5 border border-white/20 text-[10px]">{{ session.federation_level || 'LOCAL' }}</span></td>
            <td class="p-4 font-bold">{{ session.source.substring(0, 6) }}</td>
            <td class="p-4 text-white/60">{{ session.destination.substring(0, 6) }}</td>
            <td class="p-4"><span class="px-2 py-0.5 bg-white text-black font-bold text-[10px] uppercase">{{ session.intent }}</span></td>
            <td class="p-4 text-center font-bold text-white">
              {{ session.trust_score }}
            </td>
            <td class="p-4 uppercase text-[10px]" :class="getStatusColor(session.status)">{{ session.status }}</td>
            <td class="p-4 text-right">
              <button class="opacity-0 group-hover:opacity-100 text-white hover:bg-white hover:text-black transition-colors uppercase text-[10px] px-2 py-1">
                Revoke_Access
              </button>
            </td>
          </tr>
          <tr v-if="store.sessions.length === 0">
            <td colspan="8" class="p-12 text-center opacity-20 uppercase tracking-[0.3em]">
              No Active Sessions Detected
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
