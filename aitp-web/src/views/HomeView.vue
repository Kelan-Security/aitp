<script setup>
import NetworkCanvas from '../components/NetworkCanvas.vue'
import { onMounted, ref } from 'vue'
import gsap from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'

gsap.registerPlugin(ScrollTrigger)

const sessionCount = ref(1247832)
const attackCount = ref(4821)
const trustEvals = ref(892441)

const features = [
  {
    title: 'Identity First',
    icon: '🔐',
    text: 'Every connection is cryptographically bound to an Ed25519 identity. No more IP-based trust.'
  },
  {
    title: 'Intent Declared',
    icon: '🎯',
    text: 'Packets declare what they want to do before they do it. Unknown intent = automatic scrutiny.'
  },
  {
    title: 'AI Trust Engine',
    icon: '🧠',
    text: 'Gemini AI evaluates every session in under 5ms. Malicious patterns detected before data flows.'
  }
]

onMounted(() => {
  // Animate counters
  gsap.to(sessionCount, { duration: 2, value: 1247954, roundProps: 'value', ease: 'power2.out' })
  
  // Feature animations
  gsap.from('.feature-card', {
    scrollTrigger: {
      trigger: '.features-grid',
      start: 'top 80%',
    },
    y: 100,
    opacity: 0,
    duration: 1,
    stagger: 0.3,
    ease: 'power3.out'
  })
})
</script>

<template>
  <main class="relative z-10">
    <!-- Hero Section -->
    <section class="h-screen flex flex-col items-center justify-center text-center px-4 relative overflow-hidden">
      <NetworkCanvas />
      
      <div class="relative z-20 space-y-6 max-w-4xl">
        <h1 class="text-8xl md:text-9xl font-black text-transparent bg-clip-text bg-gradient-to-b from-white to-accent-cyan/20 animate-pulse-slow">
          AITP
        </h1>
        <p class="font-mono text-xl md:text-2xl text-accent-cyan tracking-[0.2em] uppercase">
          Adaptive Intent Transport Protocol
        </p>
        <p class="text-lg md:text-xl text-text-primary/60 max-w-2xl mx-auto font-light">
          TCP was built in 1984 for bytes. AITP is built for the era of sovereign AI agents.
        </p>
        
        <div class="flex flex-col md:flex-row gap-6 pt-8 justify-center items-center">
          <button class="btn-primary min-w-[240px] text-lg uppercase tracking-[0.3em] h-16">
            GET_STARTED
          </button>
          <button class="btn-secondary min-w-[240px] text-lg uppercase tracking-[0.3em] h-16 group">
            READ_SPEC <span class="inline-block group-hover:translate-x-2 transition-transform duration-300">→</span>
          </button>
        </div>
      </div>

      <!-- Live Counters -->
      <div class="absolute bottom-12 left-0 w-full px-12 flex flex-wrap justify-between items-end gap-8">
        <div class="flex flex-col border-l-2 border-accent-cyan pl-4">
          <span class="text-[10px] font-mono text-white/40 uppercase tracking-[0.2em]">Sessions Protected</span>
          <span class="text-4xl font-mono text-white font-bold">{{ sessionCount.toLocaleString() }}</span>
        </div>
        <div class="flex flex-col text-right border-r-2 border-accent-red pr-4">
          <span class="text-[10px] font-mono text-white/40 uppercase tracking-[0.2em]">Attacks Blocked Today</span>
          <span class="text-4xl font-mono text-accent-red font-bold">{{ attackCount.toLocaleString() }}</span>
        </div>
        <div class="hidden lg:flex flex-col border-l-2 border-accent-emerald pl-4">
          <span class="text-[10px] font-mono text-white/40 uppercase tracking-[0.2em]">Trust Evaluations</span>
          <span class="text-4xl font-mono text-accent-emerald font-bold">{{ trustEvals.toLocaleString() }}</span>
        </div>
      </div>
    </section>

    <!-- How It Works Section -->
    <section class="min-h-screen py-32 px-8 bg-bg-primary relative">
      <div class="max-w-7xl mx-auto space-y-24">
        <div class="text-center space-y-4">
          <h2 class="text-5xl font-black uppercase">How It Works</h2>
          <div class="w-24 h-1 bg-accent-cyan mx-auto"></div>
        </div>

        <div class="features-grid grid md:grid-cols-3 gap-12">
          <div v-for="feature in features" :key="feature.title" 
            class="feature-card cyber-panel group hover:border-accent-cyan/50 transition-colors duration-500 overflow-hidden relative">
            <div class="absolute top-0 right-0 p-4 text-4xl opacity-20 group-hover:opacity-100 group-hover:scale-110 transition-all duration-500">
              {{ feature.icon }}
            </div>
            <div class="space-y-4 relative z-10">
              <h3 class="text-2xl font-bold text-accent-cyan">{{ feature.title }}</h3>
              <p class="text-text-primary/70 leading-relaxed font-light">
                {{ feature.text }}
              </p>
            </div>
            <!-- Decorative corner -->
            <div class="absolute bottom-0 right-0 w-8 h-8 border-b-2 border-r-2 border-accent-cyan/20 group-hover:border-accent-cyan transition-colors"></div>
          </div>
        </div>
      </div>
    </section>

    <!-- Comparison Section -->
    <section class="py-32 px-8 bg-bg-secondary/50 border-y border-white/5">
      <div class="max-w-5xl mx-auto space-y-16">
        <h2 class="text-4xl font-black text-center uppercase tracking-widest">Protocol Evolution</h2>
        
        <div class="grid grid-cols-2 gap-4 md:gap-8">
          <div class="text-center p-8 bg-white/5 border border-white/5">
            <span class="font-display text-2xl text-white/30">TCP/IP</span>
          </div>
          <div class="text-center p-8 bg-accent-cyan/10 border border-accent-cyan/50 shadow-[0_0_30px_rgba(0,245,255,0.1)]">
            <span class="font-display text-2xl text-accent-cyan">AITP</span>
          </div>
          
          <template v-for="item in [
            ['Connects Hosts', 'Connects Identities'],
            ['No Intent Awareness', 'Declarative Intent'],
            ['Trust Bolted On', 'Built-in Trust Engine'],
            ['Static Authorization', 'AI Re-evaluation'],
            ['Manual Revocation', 'Real-time Revocation']
          ]" :key="item[0]">
             <div class="p-6 text-white/40 font-mono text-sm border-b border-white/5">{{ item[0] }}</div>
             <div class="p-6 text-accent-cyan font-mono text-sm border-b border-accent-cyan/20 bg-accent-cyan/5">{{ item[1] }}</div>
          </template>
        </div>
      </div>
    </section>

    <!-- Footer -->
    <footer class="py-24 px-8 border-t border-white/5 text-center space-y-8">
      <div class="flex justify-center gap-12 font-mono text-sm uppercase tracking-widest opacity-60">
        <a href="#" class="hover:text-accent-cyan transition-colors">Documentation</a>
        <a href="#" class="hover:text-accent-cyan transition-colors">GitHub</a>
        <a href="#" class="hover:text-accent-cyan transition-colors">Discord</a>
      </div>
      <p class="text-[10px] font-mono opacity-20 uppercase tracking-widest">
        © 2026 AITP CONTRIBUTORS. LICENSED UNDER BSL 1.1.
      </p>
    </footer>
  </main>
</template>

<style scoped>
.animate-pulse-slow {
  animation: pulse-slow 8s infinite ease-in-out;
}

@keyframes pulse-slow {
  0%, 100% { opacity: 1; transform: scale(1); filter: brightness(1); }
  50% { opacity: 0.8; transform: scale(1.02); filter: brightness(1.2); }
}
</style>
