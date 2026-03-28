<script setup>
import { ref, onMounted, onUnmounted } from 'vue'

const props = defineProps({
  logs: { type: Array, required: true }
})

const emit = defineEmits(['clear'])

const terminalRef = ref(null)

const scrollToBottom = () => {
  if (terminalRef.value) {
    terminalRef.value.scrollTop = terminalRef.value.scrollHeight
  }
}

// Watch logs array length and scroll
import { watch } from 'vue'
watch(() => props.logs.length, () => {
  setTimeout(scrollToBottom, 50)
})

const levelClass = (level) => {
  const l = level.toUpperCase()
  if (l === 'INFO') return 'text-success'
  if (l === 'WARN') return 'text-warn'
  if (l === 'ERROR') return 'text-error'
  if (l === 'AI_DECISION' || l === 'ANOMALY') return 'text-ai'
  return 'text-muted'
}

const formatTime = (ts) => {
  const d = new Date(ts * 1000)
  return d.toTimeString().split(' ')[0]
}
</script>

<template>
  <div class="terminal-card card">
    <div class="term-header">
      <span class="mono" style="font-size: 0.8rem; color: var(--text-secondary);">root@kelan-core: ~/logs</span>
      <button class="btn btn-clear" @click="emit('clear')">Clear Logs</button>
    </div>
    <div class="term-body mono" ref="terminalRef">
      <div v-for="(log, i) in logs" :key="i" class="log-line">
        <span class="ts">[{{ formatTime(log.ts) }}]</span>
        <span class="lvl" :class="levelClass(log.level)">[{{ log.level }}]</span>
        <span class="msg">{{ log.message }}</span>
      </div>
      <div class="log-line prompt">
        <span class="ts">></span> <span class="blink">_</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.terminal-card {
  display: flex;
  flex-direction: column;
  height: 500px;
  padding: 0;
  overflow: hidden;
  background-color: #0f1015;
  border-color: #1f222b;
}

.term-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 16px;
  background-color: rgba(255,255,255,0.03);
  border-bottom: 1px solid var(--border);
}

.btn-clear {
  background: transparent;
  color: var(--text-muted);
  font-size: 0.75rem;
  padding: 4px 8px;
  border: 1px solid var(--border);
}

.btn-clear:hover {
  color: var(--text-primary);
  border-color: var(--text-secondary);
}

.term-body {
  flex: 1;
  padding: 16px;
  overflow-y: auto;
  font-size: 0.85rem;
  line-height: 1.6;
}

.log-line {
  margin-bottom: 4px;
  word-break: break-all;
}

.ts {
  color: #4b5266;
  margin-right: 8px;
}

.lvl {
  display: inline-block;
  min-width: 60px;
  margin-right: 8px;
  font-weight: 600;
}

.msg {
  color: #c9d1d9;
}

.prompt {
  margin-top: 12px;
  color: var(--success);
}

.blink {
  animation: blink 1s step-end infinite;
}

@keyframes blink {
  50% { opacity: 0; }
}
</style>
