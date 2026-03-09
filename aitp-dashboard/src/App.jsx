import { useState, useEffect, useRef } from 'react'

const BASE = '/api'

export default function App() {
  const [token, setToken] = useState(localStorage.getItem('aitp_token') || '')
  const [loggedIn, setLoggedIn] = useState(false)
  const [stats, setStats] = useState(null)
  const [events, setEvents] = useState([])
  const [entities, setEntities] = useState([])
  const [sessions, setSessions] = useState([])
  const [threats, setThreats] = useState([])
  const [email, setEmail] = useState('admin@acme.com')
  const [pass, setPass] = useState('supersecret123')
  const wsRef = useRef(null)
  const feedRef = useRef(null)

  // ── Auth ──────────────────────────────────────────────────────
  const login = async () => {
    try {
      const r = await fetch(`${BASE}/auth/signin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password: pass })
      })
      const d = await r.json()
      if (d.token) {
        setToken(d.token)
        localStorage.setItem('aitp_token', d.token)
        setLoggedIn(true)
      } else {
        alert('Login failed: ' + JSON.stringify(d))
      }
    } catch (e) {
      alert('Login error: ' + e.message)
    }
  }

  // ── API helper ────────────────────────────────────────────────
  const api = (path) => fetch(`${BASE}${path}`, {
    headers: { 'Authorization': `Bearer ${token}` }
  }).then(r => r.json())

  // ── Load data ─────────────────────────────────────────────────
  const refresh = async () => {
    try {
      const [s, e, sess, t] = await Promise.all([
        api('/stats'), api('/entities'), api('/sessions?limit=20'), api('/threats')
      ])
      setStats(s)
      setEntities(Array.isArray(e) ? e : [])
      setSessions(Array.isArray(sess) ? sess : [])
      setThreats(Array.isArray(t) ? t : [])
    } catch (err) {
      console.error('Refresh error:', err)
    }
  }

  // ── WebSocket ─────────────────────────────────────────────────
  useEffect(() => {
    if (!loggedIn || !token) return
    refresh()

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsUrl = `${protocol}//${window.location.host}/ws?token=${token}`

    const ws = new WebSocket(wsUrl)
    wsRef.current = ws

    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data)
      const color = {
        session_new: '#5DBB7E',
        session_killed: '#E87B7B',
        alert: '#E87B7B',
        anomaly_detected: '#D4A06A',
        threat_incident: '#E87B7B',
        entity_quarantined: '#E87B7B',
        stats: null,
        log: '#A8B5C8'
      }[msg.type]

      if (color) {
        setEvents(prev => [{
          id: Date.now() + Math.random(),
          type: msg.type,
          text: formatEvent(msg),
          color,
          ts: new Date().toLocaleTimeString()
        }, ...prev].slice(0, 200))
      }
      if (msg.type === 'stats') setStats(msg)
    }

    ws.onclose = () => {
      console.log('WS closed, retrying in 3s...')
      setTimeout(() => {
        if (loggedIn) setLoggedIn(true) // trigger re-render/re-effect
      }, 3000)
    }

    return () => ws.close()
  }, [loggedIn, token])

  const formatEvent = (msg) => {
    switch (msg.type) {
      case 'session_new': return `[ALLOW] ${msg.source_entity || 'entity'} → intent:${msg.intent} score:${msg.trust_score}`
      case 'session_killed': return `[KILL] ${(msg.session_id || '').slice(0, 8)} — ${msg.reason}`
      case 'alert': return `[ALERT:${msg.severity}] ${msg.description}`
      case 'anomaly_detected': return `[ANOMALY:${msg.severity}] ${msg.entity_id?.slice(0, 8)} — ${msg.anomaly_type}`
      case 'threat_incident': return `[THREAT] ${msg.attack_type} — ${msg.summary}`
      case 'entity_quarantined': return `[QUARANTINE] ${msg.entity_id?.slice(0, 8)} — ${msg.reason}`
      case 'log': return `[LOG] ${msg.message}`
      default: return JSON.stringify(msg).slice(0, 80)
    }
  }

  // ── Render ────────────────────────────────────────────────────
  if (!loggedIn) return (
    <div style={{
      background: '#0F1219', minHeight: '100vh', display: 'flex',
      alignItems: 'center', justifyContent: 'center', fontFamily: 'monospace'
    }}>
      <div style={{
        background: '#1C2330', padding: '2rem', borderRadius: '8px',
        border: '1px solid #2A3340', width: '360px'
      }}>
        <div style={{
          color: '#5DBB7E', fontSize: '1.2rem', marginBottom: '1.5rem',
          fontWeight: 'bold'
        }}>AITP Intelligence Core</div>
        <input value={email} onChange={e => setEmail(e.target.value)}
          placeholder="email" style={inputStyle} />
        <input value={pass} onChange={e => setPass(e.target.value)}
          type="password" placeholder="password" style={inputStyle} />
        <button onClick={login} style={btnStyle}>Sign In</button>
        <div style={{ color: '#4A5568', fontSize: '0.75rem', marginTop: '1rem', textAlign: 'center' }}>
          default: admin@acme.com / supersecret123
        </div>
      </div>
    </div>
  )

  return (
    <div style={{
      background: '#0F1219', minHeight: '100vh', color: '#A8B5C8',
      fontFamily: 'monospace', fontSize: '0.82rem'
    }}>
      {/* Header */}
      <div style={{
        background: '#1C2330', borderBottom: '1px solid #2A3340',
        padding: '0.75rem 1.5rem', display: 'flex', alignItems: 'center', gap: '1rem'
      }}>
        <span style={{ color: '#5DBB7E', fontWeight: 'bold' }}>AITP</span>
        <span style={{ color: '#4A5568' }}>Intelligence Core v0.3</span>
        <button onClick={refresh} style={{
          ...btnStyle, padding: '0.3rem 0.75rem',
          fontSize: '0.72rem', marginLeft: 'auto', width: 'auto'
        }}>Refresh</button>
        <button onClick={() => {
          setLoggedIn(false); setToken('');
          localStorage.removeItem('aitp_token')
        }}
          style={{
            ...btnStyle, background: '#3A2020', padding: '0.3rem 0.75rem',
            fontSize: '0.72rem', width: 'auto'
          }}>Logout</button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', padding: '1rem' }}>

        {/* Stats */}
        <div style={cardStyle}>
          <div style={cardHeader}>LIVE STATS</div>
          {stats && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.75rem' }}>
              {[
                ['Active Sessions', stats.active_sessions],
                ['Entities Online', stats.entities_online],
                ['Blocked Today', stats.blocked_today],
                ['AI Evaluations', stats.ai_calls],
                ['Avg Trust', stats.avg_trust ? stats.avg_trust.toFixed(0) : '—'],
                ['Threats Today', stats.threats_detected_today],
              ].map(([label, val]) => (
                <div key={label} style={{
                  textAlign: 'center', padding: '0.5rem',
                  background: '#0F1219', borderRadius: '4px'
                }}>
                  <div style={{ color: '#7BB5E8', fontSize: '1.1rem', fontWeight: 'bold' }}>{val ?? '—'}</div>
                  <div style={{ color: '#4A5568', fontSize: '0.68rem' }}>{label}</div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Entities */}
        <div style={cardStyle}>
          <div style={cardHeader}>ENTITIES ({entities.length})</div>
          <div style={{ overflowY: 'auto', maxHeight: '160px' }}>
            {entities.map(e => (
              <div key={e.id} style={{
                display: 'flex', gap: '0.5rem', padding: '0.3rem 0',
                borderBottom: '1px solid #2A3340', alignItems: 'center'
              }}>
                <span style={{ color: e.quarantined ? '#E87B7B' : '#5DBB7E', fontSize: '0.7rem' }}>
                  {e.quarantined ? '⊘' : '●'}
                </span>
                <span style={{ flex: 1, color: '#A8B5C8' }}>{e.name}</span>
                <span style={{ color: '#4A5568', fontSize: '0.7rem' }}>{e.entity_type}</span>
                <span style={{ color: '#D4A06A', fontSize: '0.7rem' }}>
                  {e.trust_score_avg ? e.trust_score_avg.toFixed(0) : '—'}
                </span>
              </div>
            ))}
            {entities.length === 0 && <div style={{ color: '#4A5568' }}>No entities registered</div>}
          </div>
        </div>

        {/* Live Event Feed */}
        <div style={{ ...cardStyle, gridColumn: '1 / -1' }}>
          <div style={cardHeader}>LIVE SECURITY FEED (WebSocket)</div>
          <div ref={feedRef} style={{
            overflowY: 'auto', maxHeight: '300px',
            fontFamily: 'monospace', fontSize: '0.78rem'
          }}>
            {events.length === 0 && (
              <div style={{ color: '#4A5568' }}>Waiting for events...
                (run attack simulations to see activity)</div>
            )}
            {events.map(ev => (
              <div key={ev.id} style={{
                padding: '0.2rem 0', borderBottom: '1px solid #1C2330',
                display: 'flex', gap: '0.75rem'
              }}>
                <span style={{ color: '#4A5568', minWidth: '60px' }}>{ev.ts}</span>
                <span style={{ color: ev.color }}>{ev.text}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Sessions */}
        <div style={cardStyle}>
          <div style={cardHeader}>RECENT SESSIONS ({sessions.length})</div>
          <div style={{ overflowY: 'auto', maxHeight: '200px' }}>
            {sessions.map(s => (
              <div key={s.id} style={{
                padding: '0.3rem 0', borderBottom: '1px solid #2A3340',
                display: 'flex', gap: '0.5rem', alignItems: 'center', fontSize: '0.75rem'
              }}>
                <span style={{
                  color:
                    s.verdict === 'Allow' ? '#5DBB7E' : s.verdict === 'Monitor' ? '#D4A06A' : '#E87B7B',
                  minWidth: '55px'
                }}>{s.verdict}</span>
                <span style={{ color: '#7BB5E8', minWidth: '55px' }}>{s.intent}</span>
                <span style={{ color: '#D4A06A', minWidth: '30px' }}>{s.trust_score}</span>
                <span style={{ color: '#4A5568', fontSize: '0.68rem' }}>{s.status}</span>
              </div>
            ))}
            {sessions.length === 0 && <div style={{ color: '#4A5568' }}>No sessions yet</div>}
          </div>
        </div>

        {/* Threats */}
        <div style={cardStyle}>
          <div style={cardHeader}>THREAT INCIDENTS ({threats.length})</div>
          <div style={{ overflowY: 'auto', maxHeight: '200px' }}>
            {threats.map(t => (
              <div key={t.id} style={{ padding: '0.4rem 0', borderBottom: '1px solid #2A3340' }}>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                  <span style={{
                    color: '#E87B7B', fontSize: '0.7rem',
                    background: 'rgba(232,123,123,0.1)', padding: '0.1rem 0.4rem',
                    borderRadius: '3px'
                  }}>{t.severity}</span>
                  <span style={{ color: '#A8B5C8' }}>{t.attack_type}</span>
                </div>
                <div style={{ color: '#4A5568', fontSize: '0.72rem', marginTop: '0.2rem' }}>
                  {t.summary?.slice(0, 80)}
                </div>
              </div>
            ))}
            {threats.length === 0 && <div style={{ color: '#4A5568' }}>No threats detected yet</div>}
          </div>
        </div>

      </div>
    </div>
  )
}

const inputStyle = {
  display: 'block', width: '100%', marginBottom: '0.75rem',
  padding: '0.6rem', background: '#0F1219', border: '1px solid #2A3340',
  borderRadius: '4px', color: '#A8B5C8', fontFamily: 'monospace',
  boxSizing: 'border-box'
}
const btnStyle = {
  background: '#1B3560', color: 'white', border: 'none',
  padding: '0.65rem 1.25rem', borderRadius: '4px', cursor: 'pointer',
  fontFamily: 'monospace', width: '100%'
}
const cardStyle = {
  background: '#1C2330', border: '1px solid #2A3340', borderRadius: '6px', padding: '1rem'
}
const cardHeader = {
  color: '#7BB5E8', fontSize: '0.7rem', letterSpacing: '0.1em',
  textTransform: 'uppercase', marginBottom: '0.75rem', fontWeight: 'bold'
}
