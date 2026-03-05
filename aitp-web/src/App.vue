<script setup>
import { RouterView } from 'vue-router'
</script>

<template>
  <div class="min-h-screen bg-bg-primary text-text-primary selection:bg-accent-cyan/30 selection:text-white">
    <!-- Navigation (Simple for now) -->
    <nav class="fixed top-0 left-0 w-full z-50 px-8 py-6 flex justify-between items-center bg-gradient-to-b from-bg-primary to-transparent pointer-events-none">
      <div class="flex items-center gap-2 pointer-events-auto cursor-pointer" @click="$router.push('/')">
        <div class="w-8 h-8 border-2 border-accent-cyan flex items-center justify-center rotate-45 group hover:rotate-90 transition-all duration-500">
          <div class="w-2 h-2 bg-accent-cyan animate-pulse"></div>
        </div>
        <span class="font-display text-xl tracking-tighter uppercase font-bold text-accent-cyan">AITP</span>
      </div>
      
      <div class="flex gap-8 pointer-events-auto">
        <router-link to="/" class="font-mono text-sm hover:text-accent-cyan transition-colors">SPEC</router-link>
        <router-link to="/login" class="font-mono text-sm hover:text-accent-cyan transition-colors">ENTER_TERMINAL</router-link>
      </div>
    </nav>

    <RouterView v-slot="{ Component }">
      <transition 
        enter-active-class="transition-opacity duration-700 ease-out"
        enter-from-class="opacity-0"
        enter-to-class="opacity-100"
        leave-active-class="transition-opacity duration-300 ease-in"
        leave-from-class="opacity-100"
        leave-to-class="opacity-0"
        mode="out-in"
      >
        <component :is="Component" />
      </transition>
    </RouterView>

    <!-- Global Cyber Grid Background -->
    <div class="fixed inset-0 cyber-grid-bg pointer-events-none z-0"></div>
    
    <!-- Ambient Glow -->
    <div class="fixed top-[-10%] left-[-10%] w-[40%] h-[40%] bg-accent-cyan/5 rounded-full blur-[120px] pointer-events-none"></div>
    <div class="fixed bottom-[-5%] right-[-5%] w-[30%] h-[30%] bg-accent-emerald/5 rounded-full blur-[100px] pointer-events-none"></div>
  </div>
</template>

<style>
.router-link-active {
  @apply text-accent-cyan underline underline-offset-8;
}
</style>
