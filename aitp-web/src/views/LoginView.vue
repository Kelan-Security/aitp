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
/* Inject Enterprise Variables strictly into this view */
.auth-view {
  --bg:#f8fafc; --surf:#ffffff; --surf2:#f1f5f9; --surf3:#e2e8f0;
  --primary:#0f172a; --blue:#2563eb; --blue-l:#eff6ff; --blue-m:#dbeafe;
  --green:#059669; --green-l:#ecfdf5; --red:#dc2626; --red-l:#fef2f2;
  --amber:#d97706; --amber-l:#fffbeb; --slate:#475569; --slate-l:#94a3b8;
  --border:#e2e8f0; --border2:#cbd5e1; --text:#0f172a; --text2:#475569; --text3:#94a3b8;
}

.bg-bg { background-color: var(--bg); }
.text-text3 { color: var(--text3); }

/* Custom Overrides from user CSS */
.auth-grid {
  position: absolute;
  inset: 0;
  background-image: linear-gradient(var(--border) 1px, transparent 1px), linear-gradient(90deg, var(--border) 1px, transparent 1px);
  background-size: 40px 40px;
  opacity: 0.35;
}

.auth-card {
  background: var(--surf);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 36px;
  width: 400px; /* Force consistent width like the snippet */
  box-shadow: 0 4px 6px -1px rgba(0,0,0,.04), 0 20px 40px -8px rgba(0,0,0,.07);
  animation: cardIn .35s ease;
}

@keyframes cardIn {
  from { opacity: 0; transform: translateY(16px) scale(.97); }
  to { opacity: 1; transform: none; }
}

.auth-mark {
  width: 38px;
  height: 38px;
  background: var(--primary);
  border-radius: 9px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-family: 'Syne', sans-serif;
  font-weight: 800;
  font-size: 13px;
  color: #fff;
  letter-spacing: .5px;
  margin-bottom: 14px;
}

.auth-title {
  font-family: 'Syne', sans-serif;
  font-weight: 800;
  font-size: 21px;
  color: var(--text);
  margin-bottom: 3px;
}

.auth-sub {
  font-size: 12px;
  color: var(--text3);
  margin-bottom: 22px;
}

.tabs {
  display: flex;
  gap: 3px;
  background: var(--surf2);
  border-radius: 8px;
  padding: 3px;
  margin-bottom: 20px;
}

.tab {
  flex: 1;
  padding: 7px;
  border-radius: 6px;
  font-size: 13px;
  font-weight: 500;
  background: transparent;
  color: var(--text2);
  transition: all .15s;
}

.tab.on {
  background: var(--surf);
  color: var(--primary);
  font-weight: 600;
  box-shadow: 0 1px 3px rgba(0,0,0,.08);
}

.fg { margin-bottom: 13px; }
.fl {
  font-size: 11px;
  font-weight: 600;
  color: var(--text);
  margin-bottom: 5px;
  display: block;
}

.fi {
  width: 100%;
  padding: 9px 11px;
  background: var(--surf);
  border: 1.5px solid var(--border);
  border-radius: 7px;
  font-size: 13px;
  color: var(--text);
  transition: border .15s;
}

.fi:focus {
  border-color: var(--blue);
  box-shadow: 0 0 0 3px rgba(37,99,235,.1);
  outline: none;
}

.fi::placeholder { color: var(--text3); }

.fr {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
}

.btn-p {
  width: 100%;
  padding: 10px;
  border-radius: 7px;
  background: var(--primary);
  color: #fff;
  font-size: 13px;
  font-weight: 600;
  transition: all .15s;
  border: none;
  cursor: pointer;
}

.btn-p:hover { background: #1e293b; }
.btn-p:disabled { opacity: .6; cursor: wait; }

.msg {
  padding: 8px 11px;
  border-radius: 6px;
  font-size: 12px;
  margin-bottom: 10px;
  display: block;
}

.msg.err {
  background: var(--red-l);
  border: 1px solid #fecaca;
  color: var(--red);
}

.msg.ok {
  background: var(--green-l);
  border: 1px solid #bbf7d0;
  color: var(--green);
}

.border-border {
  border-color: var(--border);
}
</style>
