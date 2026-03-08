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
  <main class="relative z-10 bg-white">
    <!-- Hero Section -->
    <section class="min-h-screen flex flex-col items-center justify-center text-center px-4 relative overflow-hidden">
      <NetworkCanvas />
      
      <div class="relative z-20 space-y-8 max-w-5xl mt-20">
        <h1 class="text-7xl md:text-9xl font-black text-black tracking-tighter">
          AITP
        </h1>
        <p class="font-mono text-lg md:text-xl text-black/60 tracking-[0.2em] uppercase">
          Adaptive Intent Transport Protocol
        </p>
        <p class="text-xl md:text-2xl text-black/80 max-w-3xl mx-auto font-light leading-relaxed">
          TCP was built in 1984 for bytes. <br/> AITP is built for the era of sovereign AI agents.
        </p>
        
        <div class="flex flex-col sm:flex-row gap-6 pt-12 justify-center items-center">
          <button class="btn-primary min-w-[240px] text-sm md:text-base uppercase tracking-[0.2em]">
            GET STARTED
          </button>
          <button class="btn-secondary min-w-[240px] text-sm md:text-base uppercase tracking-[0.2em] group">
            READ SPEC <span class="inline-block group-hover:translate-x-2 transition-transform duration-300">→</span>
          </button>
        </div>
      </div>

      <!-- Live Counters -->
      <div class="absolute bottom-12 left-0 w-full px-8 md:px-16 flex flex-wrap justify-between items-end gap-8 z-20">
        <div class="flex flex-col border-l-4 border-black pl-5">
          <span class="text-xs font-mono text-black/50 uppercase tracking-[0.2em] mb-1">Sessions Protected</span>
          <span class="text-4xl md:text-5xl font-mono text-black font-bold tracking-tight">{{ sessionCount.toLocaleString() }}</span>
        </div>
        <div class="flex flex-col text-right border-r-4 border-black pr-5">
          <span class="text-xs font-mono text-black/50 uppercase tracking-[0.2em] mb-1">Attacks Blocked Today</span>
          <span class="text-4xl md:text-5xl font-mono text-black font-bold tracking-tight">{{ attackCount.toLocaleString() }}</span>
        </div>
        <div class="hidden lg:flex flex-col border-l-4 border-black/20 pl-5">
          <span class="text-xs font-mono text-black/50 uppercase tracking-[0.2em] mb-1">Trust Evaluations</span>
          <span class="text-4xl md:text-5xl font-mono text-black font-bold tracking-tight">{{ trustEvals.toLocaleString() }}</span>
        </div>
      </div>
    </section>

    <!-- How It Works Section -->
    <section class="py-32 px-8 bg-gray-50 border-t border-black/5 relative z-20">
      <div class="max-w-7xl mx-auto space-y-24">
        <div class="text-center space-y-6">
          <h2 class="text-4xl md:text-5xl font-black uppercase tracking-tight text-black">How It Works</h2>
          <div class="w-16 h-1 bg-black mx-auto"></div>
        </div>

        <div class="features-grid grid md:grid-cols-3 gap-8 md:gap-12">
          <div v-for="feature in features" :key="feature.title" 
            class="feature-card cyber-panel group relative overflow-hidden bg-white hover:bg-black hover:text-white transition-all duration-500">
            <div class="absolute top-6 right-6 text-4xl opacity-10 group-hover:opacity-20 group-hover:scale-125 transition-all duration-500 grayscale group-hover:grayscale-0">
              {{ feature.icon }}
            </div>
            <div class="space-y-6 relative z-10 flex flex-col h-full">
              <h3 class="text-2xl font-bold tracking-tight group-hover:text-white transition-colors duration-500">{{ feature.title }}</h3>
              <p class="text-gray-600 group-hover:text-gray-300 leading-relaxed font-light transition-colors duration-500 flex-grow">
                {{ feature.text }}
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- Comparison Section -->
    <section class="py-32 px-8 bg-white border-t border-black/5 z-20 relative">
      <div class="max-w-5xl mx-auto space-y-20">
        <div class="text-center space-y-6">
          <h2 class="text-4xl md:text-5xl font-black uppercase tracking-tight text-black">Protocol Evolution</h2>
          <p class="text-gray-500 font-mono tracking-widest uppercase text-sm">Legacy vs Modern</p>
        </div>
        
        <div class="grid grid-cols-2 gap-px bg-black/10 border border-black/10 rounded-lg overflow-hidden shadow-sm">
          <div class="text-center p-8 bg-gray-50">
            <span class="font-display text-2xl font-bold text-gray-400">TCP/IP</span>
          </div>
          <div class="text-center p-8 bg-black text-white">
            <span class="font-display text-2xl font-bold">AITP</span>
          </div>
          
          <template v-for="item in [
            ['Connects Hosts', 'Connects Identities'],
            ['No Intent Awareness', 'Declarative Intent'],
            ['Trust Bolted On', 'Built-in Trust Engine'],
            ['Static Authorization', 'AI Re-evaluation'],
            ['Manual Revocation', 'Real-time Revocation']
          ]" :key="item[0]">
             <div class="p-6 md:p-8 text-gray-500 font-mono text-sm bg-white flex items-center justify-center text-center">
               {{ item[0] }}
             </div>
             <div class="p-6 md:p-8 text-black font-mono text-sm bg-gray-50 font-medium flex items-center justify-center text-center border-l border-black/5">
               {{ item[1] }}
             </div>
          </template>
        </div>
      </div>
    </section>

    <!-- Footer -->
    <footer class="py-16 px-8 border-t border-black/10 text-center space-y-8 bg-gray-50 relative z-20">
      <div class="flex justify-center gap-12 font-mono text-sm uppercase tracking-widest text-black/60">
        <a href="#" class="hover:text-black transition-colors">Documentation</a>
        <a href="#" class="hover:text-black transition-colors">GitHub</a>
        <a href="#" class="hover:text-black transition-colors">Discord</a>
      </div>
      <p class="text-xs font-mono text-black/30 uppercase tracking-widest">
        © 2026 AITP CONTRIBUTORS. LICENSED UNDER BSL 1.1.
      </p>
    </footer>
  </main>
</template>

<style scoped>
/* Scoped styles removed as B&W styling is completely handle by utility classes */
</style>
