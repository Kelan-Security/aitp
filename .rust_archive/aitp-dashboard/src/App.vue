<script setup>
import { ref, onMounted } from 'vue'
import Login from './components/Login.vue'
import Dashboard from './components/Dashboard.vue'

const token = ref(null)

onMounted(() => {
  const savedToken = localStorage.getItem('aitp_token')
  if (savedToken) {
    token.value = savedToken
  }
})

const handleLogin = (newToken) => {
  localStorage.setItem('aitp_token', newToken)
  token.value = newToken
}

const handleLogout = () => {
  localStorage.removeItem('aitp_token')
  token.value = null
}
</script>

<template>
  <div class="app-layout">
    <Login v-if="!token" @login="handleLogin" />
    <Dashboard v-else :token="token" @logout="handleLogout" />
  </div>
</template>

<style scoped>
.app-layout {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}
</style>
