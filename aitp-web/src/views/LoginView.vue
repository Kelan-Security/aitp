<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'

const router = useRouter()
const email = ref('')
const password = ref('')
const isLoggingIn = ref(false)
const isSignup = ref(false)
const errorMessage = ref('')

async function handleSubmit() {
  errorMessage.value = ''
  if (!email.value || !password.value) {
    errorMessage.value = 'Please complete all required fields.'
    return
  }

  isLoggingIn.value = true

  // For now, simulate network request since backend connection is next phase
  setTimeout(() => {
    isLoggingIn.value = false
    router.push('/terminal') // Routes to the terminal dashboard
  }, 1200)
}
</script>

<template>
  <div class="enterprise-container min-h-screen flex">
    <!-- Left Split: Branding / Graphic -->
    <div class="hidden lg:flex lg:w-1/2 bg-primary relative overflow-hidden items-center justify-center">
      <!-- Decorative enterprise grid -->
      <div class="absolute inset-0 grid-pattern opacity-10"></div>
      
      <div class="relative z-10 px-16 max-w-2xl">
        <div class="inline-flex items-center gap-3 mb-8">
          <div class="w-8 h-8 rounded-lg bg-blue flex items-center justify-center shadow-lg shadow-blue/30">
            <svg class="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          </div>
          <span class="text-white font-syne font-bold tracking-tight text-xl">AITP Protocol</span>
        </div>
        
        <h1 class="text-4xl lg:text-5xl font-syne font-bold text-white leading-tight mb-6">
          The Intelligence <br/>
          <span class="text-blue-light">Transport Layer.</span>
        </h1>
        <p class="text-surface2/80 font-sans text-lg mb-12 max-w-lg leading-relaxed">
          Secure, intent-bound, and context-aware communication infrastructure for the next generation of autonomous AI systems.
        </p>

        <div class="flex items-center gap-4 text-sm font-mono text-surface2/60">
          <div class="flex items-center gap-2">
            <div class="w-2 h-2 rounded-full bg-green animate-pulse"></div>
            Systems Operational
          </div>
          <div class="h-4 w-px bg-white/20"></div>
          <span>v0.2.0-beta</span>
        </div>
      </div>
      
      <!-- Abstract floating shapes -->
      <div class="absolute top-1/4 -right-12 w-64 h-64 bg-blue rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-blob"></div>
      <div class="absolute top-1/3 right-1/4 w-72 h-72 bg-blue-mid rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-blob animation-delay-2000"></div>
    </div>

    <!-- Right Split: Auth Form -->
    <div class="w-full lg:w-1/2 flex items-center justify-center p-8 sm:p-12 lg:p-24 bg-bg">
      <div class="w-full max-w-md bg-surface p-10 rounded-2xl shadow-xl shadow-primary/5 border border-surface2">
        
        <div class="mb-8">
          <h2 class="text-2xl font-syne font-bold text-primary mb-2">
            {{ isSignup ? 'Create Organization' : 'Welcome back' }}
          </h2>
          <p class="text-sm text-primary/60 font-sans">
            {{ isSignup ? 'Provision your network identity to get started.' : 'Enter your credentials to access the terminal.' }}
          </p>
        </div>

        <form @submit.prevent="handleSubmit" class="space-y-5">
          <div v-if="errorMessage" class="p-4 bg-red-l text-red text-sm rounded-lg font-medium border border-red/10 flex items-center gap-2">
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            {{ errorMessage }}
          </div>

          <div class="space-y-1.5">
            <label class="block text-sm font-medium text-primary">Email Address</label>
            <input 
              v-model="email" 
              type="email" 
              class="w-full px-4 py-3 rounded-xl bg-surface2 border-transparent focus:bg-surface focus:border-blue focus:ring-2 focus:ring-blue-light outline-none transition-all font-sans text-primary placeholder-primary/30"
              placeholder="admin@organization.com"
            >
          </div>

          <div class="space-y-1.5">
            <div class="flex items-center justify-between">
              <label class="block text-sm font-medium text-primary">Password</label>
              <a v-if="!isSignup" href="#" class="text-sm font-medium text-blue hover:text-blue-mid transition-colors">Forgot?</a>
            </div>
            <input 
              v-model="password" 
              type="password" 
              class="w-full px-4 py-3 rounded-xl bg-surface2 border-transparent focus:bg-surface focus:border-blue focus:ring-2 focus:ring-blue-light outline-none transition-all font-sans text-primary placeholder-primary/30"
              placeholder="••••••••••••"
            >
          </div>

          <button 
            type="submit" 
            :disabled="isLoggingIn"
            class="w-full py-3.5 px-4 bg-blue hover:bg-blue/90 text-white rounded-xl font-medium font-sans transition-all active:scale-[0.98] disabled:opacity-70 disabled:cursor-not-allowed flex items-center justify-center gap-2 shadow-lg shadow-blue/20"
          >
            <span v-if="!isLoggingIn">{{ isSignup ? 'Create Account' : 'Sign In' }}</span>
            <div v-else class="flex items-center gap-2">
              <svg class="animate-spin h-5 w-5 text-white/80" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
              <span>Authenticating...</span>
            </div>
          </button>
        </form>

        <div class="mt-8 text-center">
          <p class="text-sm text-primary/60 font-sans">
            {{ isSignup ? 'Already have an account?' : 'Need an organization account?' }}
            <button @click="isSignup = !isSignup" class="font-medium text-blue hover:text-blue-mid transition-colors ml-1 focus:outline-none">
              {{ isSignup ? 'Sign In' : 'Create one' }}
            </button>
          </p>
        </div>
        
      </div>
    </div>
  </div>
</template>

<style scoped>
/* Inject Enterprise Variables strictly into this view */
.enterprise-container {
  --bg: #f8fafc;
  --surface: #ffffff;
  --surface2: #f1f5f9;
  --primary: #0f172a;
  --blue: #2563eb;
  --blue-light: #eff6ff;
  --blue-mid: #dbeafe;
  --green: #059669;
  --red: #dc2626;
  --red-l: #fef2f2;
}

.bg-bg { background-color: var(--bg); }
.bg-surface { background-color: var(--surface); }
.bg-surface2 { background-color: var(--surface2); }
.bg-primary { background-color: var(--primary); }
.bg-blue { background-color: var(--blue); }
.bg-blue-light { background-color: var(--blue-light); }
.bg-blue-mid { background-color: var(--blue-mid); }
.bg-red-l { background-color: var(--red-l); }

.text-primary { color: var(--primary); }
.text-blue { color: var(--blue); }
.text-blue-light { color: var(--blue-light); }
.text-blue-mid { color: var(--blue-mid); }
.text-green { color: var(--green); }
.text-red { color: var(--red); }
.text-surface2 { color: var(--surface2); }

.border-surface2 { border-color: var(--surface2); }
.border-transparent { border-color: transparent; }

.focus\:border-blue:focus { border-color: var(--blue); }
.focus\:ring-blue-light:focus { --tw-ring-color: var(--blue-light); }

.opacity-10 { opacity: 0.1; }
.opacity-20 { opacity: 0.2; }
.opacity-25 { opacity: 0.25; }
.opacity-30 { opacity: 0.3; }
.opacity-60 { opacity: 0.6; }
.opacity-70 { opacity: 0.7; }
.opacity-75 { opacity: 0.75; }
.opacity-80 { opacity: 0.8; }

.grid-pattern {
  background-size: 30px 30px;
  background-image: linear-gradient(to right, rgba(255, 255, 255, 0.05) 1px, transparent 1px),
                    linear-gradient(to bottom, rgba(255, 255, 255, 0.05) 1px, transparent 1px);
}

.font-syne { font-family: 'Syne', sans-serif; }
.font-sans { font-family: 'DM Sans', sans-serif; }
.font-mono { font-family: 'IBM Plex Mono', monospace; }

.animate-blob {
  animation: blob 7s infinite;
}
.animation-delay-2000 {
  animation-delay: 2s;
}

@keyframes blob {
  0% { transform: translate(0px, 0px) scale(1); }
  33% { transform: translate(30px, -50px) scale(1.1); }
  66% { transform: translate(-20px, 20px) scale(0.9); }
  100% { transform: translate(0px, 0px) scale(1); }
}
</style>
