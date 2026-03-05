<script setup>
import { computed } from 'vue'

const props = defineProps({
  title: String,
  value: [Number, String],
  detail: String,
  color: {
    type: String,
    default: 'cyan'
  }
})

const colorClass = computed(() => {
  const classes = {
    cyan: 'text-accent-cyan border-accent-cyan/20 bg-accent-cyan/5',
    emerald: 'text-accent-emerald border-accent-emerald/20 bg-accent-emerald/5',
    red: 'text-accent-red border-accent-red/20 bg-accent-red/5',
    amber: 'text-accent-amber border-accent-amber/20 bg-accent-amber/5'
  }
  return classes[props.color] || classes.cyan
})
</script>

<template>
  <div class="cyber-panel flex flex-col justify-between border-l-2" :class="colorClass">
    <div class="space-y-1">
      <h4 class="font-mono text-[10px] uppercase tracking-widest opacity-60">{{ title }}</h4>
      <div class="text-3xl font-mono font-bold">{{ value }}</div>
    </div>
    <div class="pt-4 mt-4 border-t border-white/5 font-mono text-[9px] uppercase tracking-tighter opacity-40">
      {{ detail }}
    </div>
  </div>
</template>
