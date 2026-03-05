import { defineStore } from 'pinia'

export const useAitpStore = defineStore('aitp', {
    state: () => ({
        sessions: [],
        attackEvents: [],
        metrics: {
            activeSessions: 0,
            trustScoreAvg: 0,
            threatsBlocked: 0,
            geminiCalls: 0,
            latencyMs: 0
        },
        nodeStatus: {
            alpha: 'OFFLINE',
            beta: 'OFFLINE'
        }
    }),
    actions: {
        addSession(session) {
            this.sessions.unshift(session)
            if (this.sessions.length > 100) this.sessions.pop()
        },
        revokeSession(sessionId) {
            const idx = this.sessions.findIndex(s => s.id === sessionId)
            if (idx !== -1) {
                this.sessions[idx].status = 'REVOKED'
                setTimeout(() => {
                    this.sessions = this.sessions.filter(s => s.id !== sessionId)
                }, 2000)
            }
        },
        addAttackEvent(event) {
            this.attackEvents.unshift(event)
            if (this.attackEvents.length > 50) this.attackEvents.pop()
        },
        updateMetrics(newMetrics) {
            this.metrics = { ...this.metrics, ...newMetrics }
        }
    }
})
