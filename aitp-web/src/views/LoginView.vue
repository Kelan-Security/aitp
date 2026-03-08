<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'

const router = useRouter()
const isSignup = ref(false)

// Sign In Refs
const siEmail = ref('demo@aitp.dev')
const siPassword = ref('demo1234')
const siLoading = ref(false)
const siError = ref('')

// Sign Up Refs
const suOrg = ref('')
const suIndustry = ref('')
const suEmail = ref('')
const suPassword = ref('')
const suPasswordConfirm = ref('')
const suApiKey = ref('')

const suLoading = ref(false)
const suError = ref('')
const suSuccess = ref('')

async function api(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } }
  if (body) opts.body = JSON.stringify(body)
  const r = await fetch(path, opts) // Vite proxies /api to backend
  const data = await r.json()
  if (!r.ok) throw new Error(data.error || r.statusText)
  return data
}

async function doSignin() {
  siError.value = ''
  if (!siEmail.value || !siPassword.value) {
    siError.value = 'Email and password are required.'
    return
  }
  siLoading.value = true
  try {
    const res = await api('POST', '/api/auth/signin', {
      email: siEmail.value,
      password: siPassword.value
    })
    localStorage.setItem('aitp_token', res.token)
    localStorage.setItem('aitp_org', JSON.stringify(res.org))
    router.push('/terminal')
  } catch (e) {
    siError.value = e.message || 'Failed to sign in'
  } finally {
    siLoading.value = false
  }
}

async function doSignup() {
  suError.value = ''
  suSuccess.value = ''
  
  if (!suOrg.value || !suEmail.value || !suPassword.value) {
    suError.value = 'Please fill out all required fields.'
    return
  }
  if (suPassword.value !== suPasswordConfirm.value) {
    suError.value = 'Passwords do not match.'
    return
  }
  if (suPassword.value.length < 8) {
    suError.value = 'Password must be at least 8 characters.'
    return
  }

  suLoading.value = true
  try {
    const res = await api('POST', '/api/auth/signup', {
      org_name: suOrg.value,
      industry: suIndustry.value,
      email: suEmail.value,
      password: suPassword.value,
      gemini_api_key: suApiKey.value || null
    })
    localStorage.setItem('aitp_token', res.token)
    localStorage.setItem('aitp_org', JSON.stringify(res.org))
    suSuccess.value = 'Organization created! Redirecting...'
    setTimeout(() => {
      router.push('/terminal')
    }, 900)
  } catch (e) {
    suError.value = e.message || 'Failed to create organization'
  } finally {
    suLoading.value = false
  }
}
</script>

<template>
  <div class="auth-view min-h-screen flex items-center justify-center relative bg-bg font-sans">
    <div class="auth-grid"></div>
    
    <div class="auth-card relative z-10 w-[400px]">
      <div class="auth-mark">AI</div>
      <div class="auth-title">AITP Platform</div>
      <div class="auth-sub">Intelligence Protocol Layer — Organization Access</div>
      
      <div class="tabs">
        <button class="tab" :class="{ 'on': !isSignup }" @click="isSignup = false; siError = ''">Sign In</button>
        <button class="tab" :class="{ 'on': isSignup }" @click="isSignup = true; suError = ''">Create Org</button>
      </div>

      <!-- SIGN IN -->
      <form v-if="!isSignup" @submit.prevent="doSignin">
        <div v-if="siError" class="msg err">{{ siError }}</div>
        
        <div class="fg">
          <label class="fl">Organization Email</label>
          <input v-model="siEmail" type="email" class="fi" placeholder="you@company.com" required />
        </div>
        <div class="fg">
          <label class="fl">Password</label>
          <input v-model="siPassword" type="password" class="fi" placeholder="••••••••" required />
        </div>
        
        <button type="submit" class="btn-p mt-2" :disabled="siLoading">
          {{ siLoading ? 'Signing in...' : 'Sign In →' }}
        </button>
        
        <p class="text-center mt-4 text-[11px] text-text3">
          Demo Access: demo@aitp.dev / demo1234
        </p>
      </form>

      <!-- SIGN UP -->
      <form v-else @submit.prevent="doSignup">
        <div v-if="suError" class="msg err">{{ suError }}</div>
        <div v-if="suSuccess" class="msg ok">{{ suSuccess }}</div>
        
        <div class="fr border-b border-border pb-3 mb-3">
          <div class="fg">
            <label class="fl">Organization Name</label>
            <input v-model="suOrg" type="text" class="fi" placeholder="Acme Corp" required />
          </div>
          <div class="fg">
            <label class="fl">Industry</label>
            <input v-model="suIndustry" type="text" class="fi" placeholder="AI / FinTech" />
          </div>
        </div>
        
        <div class="fg">
          <label class="fl">Work Email</label>
          <input v-model="suEmail" type="email" class="fi" placeholder="you@company.com" required />
        </div>
        
        <div class="fr">
          <div class="fg">
            <label class="fl">Password</label>
            <input v-model="suPassword" type="password" class="fi" placeholder="8+ chars" required />
          </div>
          <div class="fg">
            <label class="fl">Confirm</label>
            <input v-model="suPasswordConfirm" type="password" class="fi" placeholder="Repeat" required />
          </div>
        </div>
        
        <div class="fg mt-3">
          <label class="fl">AI Provider API Key (optional)</label>
          <input v-model="suApiKey" type="password" class="fi" placeholder="sk-..." />
        </div>
        
        <button type="submit" class="btn-p mt-3" :disabled="suLoading">
          {{ suLoading ? 'Creating...' : 'Create Organization →' }}
        </button>
      </form>
      
    </div>
  </div>
</template>

<style scoped>
.auth-view {
  --bg: #fff; 
  --surf: #fafafa;
  --text: #000;
  --text2: #333;
  --text3: #666;
  --border: #e5e7eb;
  background-color: var(--bg);
  color: var(--text);
}

.text-text3 { color: var(--text3); }

/* Minimalist B&W background pattern */
.auth-grid {
  position: absolute;
  inset: 0;
  background-image: 
    linear-gradient(#f3f4f6 1px, transparent 1px), 
    linear-gradient(90deg, #f3f4f6 1px, transparent 1px);
  background-size: 30px 30px;
  opacity: 0.8;
}

.auth-card {
  background: var(--bg);
  border: 2px solid #000;
  padding: 40px;
  width: 440px;
  box-shadow: 8px 8px 0 0 #000;
  animation: cardIn .4s cubic-bezier(0.16, 1, 0.3, 1);
}

@keyframes cardIn {
  from { opacity: 0; transform: translateY(16px); }
  to { opacity: 1; transform: none; }
}

.auth-mark {
  width: 42px;
  height: 42px;
  background: #000;
  display: flex;
  align-items: center;
  justify-content: center;
  font-family: 'Syne', sans-serif;
  font-weight: 900;
  font-size: 14px;
  color: #fff;
  letter-spacing: 1px;
  margin-bottom: 20px;
  box-shadow: 4px 4px 0 0 #ccc;
}

.auth-title {
  font-family: 'Syne', sans-serif;
  font-weight: 800;
  font-size: 24px;
  color: #000;
  margin-bottom: 6px;
  letter-spacing: -0.5px;
}

.auth-sub {
  font-size: 13px;
  color: var(--text3);
  margin-bottom: 28px;
  font-weight: 500;
}

.tabs {
  display: flex;
  background: #f9fafb;
  border: 2px solid #000;
  padding: 4px;
  margin-bottom: 24px;
  box-shadow: 2px 2px 0 0 #ccc;
}

.tab {
  flex: 1;
  padding: 10px;
  font-size: 13px;
  font-weight: 700;
  background: transparent;
  color: var(--text3);
  transition: all .2s;
  cursor: pointer;
  text-transform: uppercase;
  letter-spacing: 1px;
}

.tab.on {
  background: #000;
  color: #fff;
}

.fg { margin-bottom: 16px; }
.fl {
  font-size: 11px;
  font-weight: 800;
  color: #000;
  margin-bottom: 6px;
  display: block;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.fi {
  width: 100%;
  padding: 12px 14px;
  background: #fff;
  border: 2px solid #ccc;
  font-size: 14px;
  color: #000;
  transition: border .2s;
  font-weight: 500;
}

.fi:focus {
  border-color: #000;
  outline: none;
  box-shadow: 2px 2px 0 0 #ccc;
}

.fi::placeholder { color: #9ca3af; font-weight: 400; }

.fr {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.btn-p {
  width: 100%;
  padding: 14px;
  background: #000;
  color: #fff;
  border: 2px solid #000;
  font-size: 14px;
  font-weight: 800;
  text-transform: uppercase;
  letter-spacing: 1px;
  transition: all .2s;
  cursor: pointer;
  box-shadow: 4px 4px 0 0 #ccc;
  margin-top: 8px;
}

.btn-p:hover { 
  transform: translate(-2px, -2px);
  box-shadow: 6px 6px 0 0 #ccc;
}

.btn-p:active {
  transform: translate(2px, 2px);
  box-shadow: 0 0 0 0 #ccc;
}

.btn-p:disabled { opacity: .7; cursor: wait; }

.msg {
  padding: 12px 14px;
  font-size: 13px;
  font-weight: 600;
  margin-bottom: 16px;
  display: block;
  border: 2px solid #000;
  border-left-width: 6px;
}

.msg.err {
  background: #fff;
  border-color: #000;
}

.msg.ok {
  background: #f9fafb;
}

.border-border {
  border-color: var(--border);
}
</style>
