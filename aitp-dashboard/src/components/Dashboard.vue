<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import Terminal from './Terminal.vue'

const props = defineProps({
  token: { type: String, required: true }
})
const emit = defineEmits(['logout'])

const ws = ref(null)
const connected = ref(false)
const stats = ref({
  active_sessions: 0,
  blocked_today: 0,
  entities_online: 0,
  threats_detected_today: 0
})

const logs = ref([])
const alerts = ref([])

onMounted(() => {
  connectWs()
})

onUnmounted(() => {
  if (ws.value) ws.value.close()
})

const connectWs = () => {
  const url = `ws://localhost:3000/ws?token=${encodeURIComponent(props.token)}`
  ws.value = new WebSocket(url)

  ws.value.onopen = () => {
    connected.value = true
    // Initial welcome ping
  }

  ws.value.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data)
      if (data.Stats) {
        stats.value = data.Stats
      } else if (data.Log) {
        logs.value.push(data.Log)
        if (logs.value.length > 200) logs.value.shift()
      } else if (data.Alert) {
        alerts.value.unshift(data.Alert)
        if (alerts.value.length > 10) alerts.value.pop()
        
        // Also log alerts
        logs.value.push({
          level: 'AI_DECISION',
          message: `[${data.Alert.severity}] ${data.Alert.description} -> Action: ${data.Alert.recommended_action}`,
          ts: data.Alert.ts
        })
      }
    } catch(err) {
      console.error(err)
    }
  }

  ws.value.onclose = () => {
    connected.value = false
    // Attempt reconnect after 5s
    setTimeout(connectWs, 5000)
  }
}

const clearLogs = () => {
  logs.value = []
}

const formatNumber = (num) => {
  return new Intl.NumberFormat().format(num || 0)
}
</script>

<template>
  <div class="dashboard-layout">
    <!-- Navbar -->
    <header class="navbar">
      <div class="brand">
        <span class="mono" style="font-size: 1.2rem; font-weight: 600;">AITP<span class="text-ai">.</span>SOC</span>
        <span v-if="connected" class="tag tag-success" style="margin-left: 16px;">LIVE</span>
        <span v-else class="tag tag-error" style="margin-left: 16px;">OFFLINE</span>
      </div>
      <div>
        <button class="btn btn-danger" @click="emit('logout')">Logout</button>
      </div>
    </header>

    <main class="content-grid">
      <!-- Stats Row -->
      <div class="stats-row">
        <div class="stat-card card">
          <div class="stat-label mono text-muted">ACTIVE SESSIONS</div>
          <div class="stat-value text-success">{{ formatNumber(stats.active_sessions) }}</div>
        </div>
        <div class="stat-card card">
          <div class="stat-label mono text-muted">BLOCKED FLOWS</div>
          <div class="stat-value text-error">{{ formatNumber(stats.blocked_today) }}</div>
        </div>
        <div class="stat-card card">
          <div class="stat-label mono text-muted">ENTITIES ONLINE</div>
          <div class="stat-value">{{ formatNumber(stats.entities_online) }}</div>
        </div>
        <div class="stat-card card">
          <div class="stat-label mono text-muted">THREATS DETECTED</div>
          <div class="stat-value text-warn">{{ formatNumber(stats.threats_detected_today) }}</div>
        </div>
      </div>

      <!-- Main Split -->
      <div class="main-split">
        <div class="terminal-section">
          <h3 class="section-title">Network Monitor</h3>
          <Terminal :logs="logs" @clear="clearLogs" />
        </div>

        <div class="ai-section">
          <h3 class="section-title">Ollama AI Reasoning</h3>
          <div class="ai-card card" v-for="alert in alerts" :key="alert.ts">
            <div class="ai-header">
              <span class="tag tag-ai">AI VERDICT</span>
              <span class="mono text-muted" style="font-size: 0.75rem;">{{ alert.entity_id || 'Unknown' }}</span>
            </div>
            <p class="ai-desc">{{ alert.description }}</p>
            <div class="ai-action mono text-warn">> {{ alert.recommended_action }}</div>
          </div>
          
          <div v-if="alerts.length === 0" class="empty-state text-muted">
            Waiting for AI evaluation events...
          </div>
        </div>
      </div>
    </main>
  </div>
</template>

<style scoped>
.dashboard-layout {
  height: 100vh;
  display: flex;
  flex-direction: column;
}

.navbar {
  height: 60px;
  background-color: var(--bg-card);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 24px;
}

.brand {
  display: flex;
  align-items: center;
}

.content-grid {
  flex: 1;
  padding: 24px;
  overflow-y: auto;
}

.stats-row {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 24px;
  margin-bottom: 24px;
}

.stat-card {
  padding: 20px;
}

.stat-label {
  font-size: 0.75rem;
  letter-spacing: 0.5px;
  margin-bottom: 8px;
}

.stat-value {
  font-size: 2rem;
  font-weight: 700;
  font-family: var(--font-mono);
}

.main-split {
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: 24px;
}

.section-title {
  font-size: 1rem;
  font-weight: 500;
  margin-bottom: 16px;
  color: var(--text-secondary);
}

.ai-card {
  margin-bottom: 16px;
  background-color: rgba(139, 92, 246, 0.05); /* Slight purple tint */
  border-color: rgba(139, 92, 246, 0.2);
}

.ai-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.ai-desc {
  font-size: 0.9rem;
  margin-bottom: 12px;
}

.ai-action {
  font-size: 0.8rem;
  background-color: rgba(0,0,0,0.2);
  padding: 8px;
  border-radius: 4px;
}

.empty-state {
  text-align: center;
  padding: 40px 20px;
  border: 1px dashed var(--border);
  border-radius: 8px;
  font-size: 0.9rem;
}
</style>
