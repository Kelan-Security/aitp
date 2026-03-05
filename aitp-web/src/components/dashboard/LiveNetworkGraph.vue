<script setup>
import { onMounted, onUnmounted, ref, watch } from 'vue'
import * as THREE from 'three'
import { useAitpStore } from '../../stores/aitp'

const store = useAitpStore()
const canvasRef = ref(null)

let scene, camera, renderer, nodesGroup, edgesGroup
let animationId

onMounted(() => {
  initThree()
  animate()
  window.addEventListener('resize', onWindowResize)
})

onUnmounted(() => {
  window.removeEventListener('resize', onWindowResize)
  cancelAnimationFrame(animationId)
  if (renderer) renderer.dispose()
})

// Watch for store session changes to update the graph
watch(() => store.sessions, () => {
  updateGraph()
}, { deep: true })

function initThree() {
  scene = new THREE.Scene()
  camera = new THREE.PerspectiveCamera(75, canvasRef.value.clientWidth / canvasRef.value.clientHeight, 0.1, 1000)
  camera.position.z = 100

  renderer = new THREE.WebGLRenderer({ canvas: canvasRef.value, alpha: true, antialias: true })
  renderer.setSize(canvasRef.value.clientWidth, canvasRef.value.clientHeight)
  renderer.setPixelRatio(window.devicePixelRatio)

  nodesGroup = new THREE.Group()
  edgesGroup = new THREE.Group()
  scene.add(nodesGroup)
  scene.add(edgesGroup)

  // Initial nodes (Placeholders)
  for (let i = 0; i < 20; i++) {
    addNode({
      id: `node-${i}`,
      score: Math.random() * 255
    })
  }
}

function addNode(data) {
  const geometry = new THREE.SphereGeometry(1, 16, 16)
  const material = new THREE.MeshBasicMaterial({ 
    color: data.score > 128 ? 0x00ff88 : (data.score > 64 ? 0xffaa00 : 0xff2244),
    transparent: true,
    opacity: 0.8
  })
  const mesh = new THREE.Mesh(geometry, material)
  
  mesh.position.set(
    (Math.random() - 0.5) * 100,
    (Math.random() - 0.5) * 100,
    (Math.random() - 0.5) * 100
  )
  
  nodesGroup.add(mesh)
}

function updateGraph() {
  // Logic to clear and rebuild edges based on active sessions
  // For now, randomly connect some nodes
  edgesGroup.clear()
  const positions = nodesGroup.children.map(n => n.position)
  
  const lineMaterial = new THREE.LineBasicMaterial({ color: 0x00f5ff, transparent: true, opacity: 0.2 })
  
  for (let i = 0; i < 15; i++) {
     const p1 = positions[Math.floor(Math.random() * positions.length)]
     const p2 = positions[Math.floor(Math.random() * positions.length)]
     
     const geometry = new THREE.BufferGeometry().setFromPoints([p1, p2])
     const line = new THREE.Line(geometry, lineMaterial)
     edgesGroup.add(line)
  }
}

function animate() {
  animationId = requestAnimationFrame(animate)
  
  nodesGroup.rotation.y += 0.002
  edgesGroup.rotation.y += 0.002
  
  renderer.render(scene, camera)
}

function onWindowResize() {
  if (!canvasRef.value) return
  camera.aspect = canvasRef.value.clientWidth / canvasRef.value.clientHeight
  camera.updateProjectionMatrix()
  renderer.setSize(canvasRef.value.clientWidth, canvasRef.value.clientHeight)
}
</script>

<template>
  <canvas ref="canvasRef" class="w-full h-full"></canvas>
</template>
