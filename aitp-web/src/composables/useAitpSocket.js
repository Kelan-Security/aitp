import { ref, onMounted, onUnmounted } from 'vue'
import { io } from 'socket.io-client'
import { useAitpStore } from '../stores/aitp'

export function useAitpSocket() {
    const store = useAitpStore()
    const socket = ref(null)

    onMounted(() => {
        socket.value = io(import.meta.env.VITE_AITP_WS_URL || 'http://localhost:8080', {
            transports: ['websocket'],
            autoConnect: true
        })

        socket.value.on('connect', () => {
            console.log('Connected to AITP Terminal')
        })

        socket.value.on('session.established', (data) => {
            store.addSession(data)
        })

        socket.value.on('session.revoked', (data) => {
            store.revokeSession(data.session_id)
        })

        socket.value.on('metrics.update', (data) => {
            store.updateMetrics(data)
        })

        socket.value.on('attack.detected', (data) => {
            store.addAttackEvent(data)
        })
    })

    onUnmounted(() => {
        if (socket.value) socket.value.disconnect()
    })

    return { socket }
}
