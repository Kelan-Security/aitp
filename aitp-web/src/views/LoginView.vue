<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import gsap from 'gsap'

const router = useRouter()
const apiKey = ref('')
const nodeId = ref('')
const isLoggingIn = ref(false)

async function handleLogin() {
  isLoggingIn.value = true
  
  // Simulation of login vortex transition
  gsap.to('.login-vortex', {
    duration: 1.5,
    scale: 20,
    opacity: 0,
    rotate: 360,
    ease: 'expo.in',
    onComplete: () => {
      router.push('/terminal')
    }
  })
}
</script>

<template>
  <div class="h-screen flex items-center justify-center relative overflow-hidden bg-bg-primary">
    <!-- Spinning vortex background (Decorative) -->
    <div class="login-vortex absolute w-[400px] h-[400px] border border-accent-cyan/20 rounded-full blur-3xl animate-spin-slow pointer-events-none"></div>
    <div class="absolute inset-0 cyber-grid-bg opacity-20 pointer-events-none"></div>

    <div class="cyber-panel w-full max-w-md space-y-8 relative z-10 transition-all duration-700"
         :class="{ 'opacity-0 scale-90 blur-lg': isLoggingIn }">
      <div class="text-center space-y-2">
        <h2 class="text-3xl font-black text-white uppercase tracking-tighter">Enter Terminal</h2>
        <p class="font-mono text-xs text-accent-cyan/60 uppercase">Identity Verification Required</p>
      </div>

      <form @submit.prevent="handleLogin" class="space-y-6">
        <div class="space-y-4">
          <div class="space-y-1">
            <label class="font-mono text-[10px] text-white/40 uppercase tracking-widest pl-1">Node_Identity</label>
            <input v-model="nodeId" type="text" placeholder="ENTITY_ID_SHA256"
                   class="w-full bg-white/5 border border-white/10 p-4 font-mono text-sm focus:border-accent-cyan focus:outline-none transition-colors">
          </div>
          <div class="space-y-1">
            <label class="font-mono text-[10px] text-white/40 uppercase tracking-widest pl-1">Access_Key</label>
            <input v-model="apiKey" type="password" placeholder="••••••••••••••••"
                   class="w-full bg-white/5 border border-white/10 p-4 font-mono text-sm focus:border-accent-cyan focus:outline-none transition-colors">
          </div>
        </div>

        <button type="submit" :disabled="isLoggingIn"
                class="w-full btn-primary h-14 flex items-center justify-center gap-3">
          <span v-if="!isLoggingIn">ESTABLISH_SESSION</span>
          <span v-else class="animate-pulse">NEGOTIATING...</span>
        </button>
      </form>

      <div class="text-center">
        <button @click="router.push('/')" class="font-mono text-[10px] text-white/20 hover:text-white transition-colors uppercase tracking-[0.3em]">
          ← ABORT_AND_EXIT
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.animate-spin-slow {
  animation: spin 20s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}
</style>
