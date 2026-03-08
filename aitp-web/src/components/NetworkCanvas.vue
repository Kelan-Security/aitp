<script setup>
import { onMounted, onUnmounted, ref } from 'vue'
import * as THREE from 'three'

const canvasRef = ref(null)
let renderer, scene, camera, particles, lines

onMounted(() => {
  initThree()
  animate()
  window.addEventListener('resize', onWindowResize)
})

onUnmounted(() => {
  window.removeEventListener('resize', onWindowResize)
  if (renderer) renderer.dispose()
})

function initThree() {
  scene = new THREE.Scene()
  camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000)
  camera.position.z = 50

  renderer = new THREE.WebGLRenderer({ canvas: canvasRef.value, alpha: true, antialias: true })
  renderer.setSize(window.innerWidth, window.innerHeight)
  renderer.setPixelRatio(window.devicePixelRatio)

  // Particles
  const particleCount = 100
  const geometry = new THREE.BufferGeometry()
  const positions = new Float32Array(particleCount * 3)
  const velocities = []

  for (let i = 0; i < particleCount; i++) {
    positions[i * 3] = (Math.random() - 0.5) * 100
    positions[i * 3 + 1] = (Math.random() - 0.5) * 100
    positions[i * 3 + 2] = (Math.random() - 0.5) * 100
    velocities.push({
      x: (Math.random() - 0.5) * 0.05,
      y: (Math.random() - 0.5) * 0.05,
      z: (Math.random() - 0.5) * 0.05
    })
  }

  geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3))
  
  const material = new THREE.PointsMaterial({
    color: 0x000000,
    size: 2.0,
    transparent: true,
    opacity: 0.15,
    blending: THREE.NormalBlending
  })

  particles = new THREE.Points(geometry, material)
  scene.add(particles)

  // Lines (Connections)
  const lineGeometry = new THREE.BufferGeometry()
  const lineMaterial = new THREE.LineBasicMaterial({
    color: 0x000000,
    transparent: true,
    opacity: 0.08,
    blending: THREE.NormalBlending
  })

  lines = new THREE.LineSegments(lineGeometry, lineMaterial)
  scene.add(lines)

  particles.userData.velocities = velocities
}

function animate() {
  requestAnimationFrame(animate)

  const positions = particles.geometry.attributes.position.array
  const velocities = particles.userData.velocities

  const linePositions = []
  const maxDistance = 20

  for (let i = 0; i < positions.length / 3; i++) {
    positions[i * 3] += velocities[i].x
    positions[i * 3 + 1] += velocities[i].y
    positions[i * 3 + 2] += velocities[i].z

    // Boundary check
    if (Math.abs(positions[i * 3]) > 50) velocities[i].x *= -1
    if (Math.abs(positions[i * 3 + 1]) > 50) velocities[i].y *= -1
    if (Math.abs(positions[i * 3 + 2]) > 50) velocities[i].z *= -1

    // Draw lines between close particles
    for (let j = i + 1; j < positions.length / 3; j++) {
      const dx = positions[i * 3] - positions[j * 3]
      const dy = positions[i * 3 + 1] - positions[j * 3 + 1]
      const dz = positions[i * 3 + 2] - positions[j * 3 + 2]
      const dist = Math.sqrt(dx * dx + dy * dy + dz * dz)

      if (dist < maxDistance) {
        linePositions.push(positions[i * 3], positions[i * 3 + 1], positions[i * 3 + 2])
        linePositions.push(positions[j * 3], positions[j * 3 + 1], positions[j * 3 + 2])
      }
    }
  }

  particles.geometry.attributes.position.needsUpdate = true
  
  lines.geometry.setAttribute('position', new THREE.Float32BufferAttribute(linePositions, 3))
  lines.geometry.attributes.position.needsUpdate = true

  scene.rotation.y += 0.001
  renderer.render(scene, camera)
}

function onWindowResize() {
  camera.aspect = window.innerWidth / window.innerHeight
  camera.updateProjectionMatrix()
  renderer.setSize(window.innerWidth, window.innerHeight)
}
</script>

<template>
  <canvas ref="canvasRef" class="fixed inset-0 z-0 pointer-events-none opacity-40"></canvas>
</template>
