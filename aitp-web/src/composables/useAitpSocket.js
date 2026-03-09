import { ref, onMounted, onUnmounted } from 'vue'
import { useAitpStore } from '../stores/aitp'

export function useAitpSocket() {
    const store = useAitpStore()
    const socket = ref(null)

    onMounted(() => {
        const token = localStorage.getItem('aitp_token')
        if (!token) return

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
        const wsUrl = `${protocol}//${window.location.host}/ws?token=${token}`

        socket.value = new WebSocket(wsUrl)

        socket.value.onopen = () => {
            console.log('Connected to AITP Intelligence Core')
        }

        socket.value.onmessage = (event) => {
            const msg = JSON.parse(event.data)

            if (msg.type === 'stats') {
                store.updateMetrics({
                    activeSessions: msg.active_sessions,
                    trustScoreAvg: msg.avg_trust,
                    threatsBlocked: msg.blocked_today,
                    geminiCalls: msg.ai_calls,
                    entitiesOnline: msg.entities_online
                })
            } else if (msg.type === 'session_new') {
                store.addSession({
                    id: msg.session_id,
                    source: msg.source_entity,
                    intent: msg.intent,
                    trust_score: msg.trust_score,
                    verdict: 'Allow',
                    status: 'ACTIVE'
                })
            } else if (msg.type === 'alert' || msg.type === 'threat_incident' || msg.type === 'anomaly_detected') {
                store.addAttackEvent(msg)
            }
        }

        socket.value.onclose = () => {
            console.log('AITP connection closed')
        }
    })

    onUnmounted(() => {
        if (socket.value) socket.value.close()
    })

    return { socket }
}
