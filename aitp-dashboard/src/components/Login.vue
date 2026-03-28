<script setup>
import { ref } from 'vue'

const emit = defineEmits(['login'])
const inputToken = ref('')
const errorMsg = ref('')

const doLogin = () => {
  if (!inputToken.value.trim()) {
    errorMsg.value = 'Token is required'
    return
  }
  
  // Basic format check (JWT usually has 2 dots)
  if (inputToken.value.split('.').length !== 3) {
    errorMsg.value = 'Invalid JWT format'
    return
  }

  errorMsg.value = ''
  emit('login', inputToken.value.trim())
}
</script>

<template>
  <div class="login-wrapper">
    <div class="card login-card">
      <div class="logo-box">
        <span class="mono" style="font-size: 1.5rem; font-weight: 600;">AITP<span class="text-ai">.</span>SOC</span>
        <p class="text-muted" style="margin-top: 8px; font-size: 0.9rem;">Intelligence Core Admin Portal</p>
      </div>

      <div class="input-group">
        <label for="token">Access Token (JWT)</label>
        <textarea 
          id="token" 
          v-model="inputToken" 
          placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
          rows="4"
        ></textarea>
        <div v-if="errorMsg" class="error-text text-error">{{ errorMsg }}</div>
      </div>

      <button class="btn login-btn" @click="doLogin">Authenticate</button>
      
      <p class="hint text-muted">
        Use <code>./start.sh token</code> or check core logs to generate a valid operator token.
      </p>
    </div>
  </div>
</template>

<style scoped>
.login-wrapper {
  flex: 1;
  display: flex;
  justify-content: center;
  align-items: center;
  padding: 24px;
}

.login-card {
  width: 100%;
  max-width: 440px;
  padding: 40px;
}

.logo-box {
  margin-bottom: 32px;
  text-align: center;
}

.input-group {
  margin-bottom: 24px;
}

.input-group label {
  display: block;
  font-size: 0.85rem;
  font-weight: 500;
  margin-bottom: 8px;
  color: var(--text-secondary);
}

textarea {
  width: 100%;
  background-color: var(--bg-base);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px;
  resize: vertical;
  outline: none;
  transition: border-color 0.2s;
  font-family: var(--font-mono);
  font-size: 0.85rem;
  color: var(--text-primary);
}

textarea:focus {
  border-color: var(--accent-primary);
}

.error-text {
  font-size: 0.8rem;
  margin-top: 8px;
}

.login-btn {
  width: 100%;
  padding: 12px;
  font-size: 1rem;
}

.hint {
  font-size: 0.8rem;
  text-align: center;
  margin-top: 24px;
}
.hint code {
  background: var(--bg-base);
  padding: 2px 6px;
  border-radius: 4px;
  color: var(--text-secondary);
}
</style>
