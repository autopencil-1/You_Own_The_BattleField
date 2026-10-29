import React, { useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import './styles.css'

type Experiment = '2A' | '2B'
type RunMode = 'deterministic' | 'connectivity' | 'pilot'
type Capabilities = { credential_configured: boolean; experiments: Array<{ id: Experiment; agent: { model: string; effort: string } }> }
type RunRow = {
  run_id: string
  experiment: Experiment
  mode: string
  arm: string | null
  status: string
  started_utc: string | null
  finished_utc: string | null
  termination_reason: string | null
  experimental_result: boolean
}
type EventRow = {
  event_id: number
  run_id: string
  experiment: Experiment
  source: 'agent' | 'decoy' | 'gateway' | 'controller'
  kind: string
  occurred_utc: string
  episode_id: string | null
  role: string | null
  call_id: string | null
  detail: Record<string, unknown>
}
type Snapshot = {
  run_id: string
  experiment: Experiment
  mode: string | null
  arm: string | null
  status: string
  started_utc: string | null
  agent_started_utc: string | null
  finished_utc: string | null
  termination_reason: string | null
  error: string | null
  max_wall_seconds: number | null
  experimental_result: boolean
  event_count: number
  score: Record<string, unknown> | null
  job: Record<string, unknown>
}
type FormState = {
  experiment: Experiment
  mode: RunMode
  arm: string
  seed: string
  branching_factor: number
  build: boolean
}

const armChoices: Record<Experiment, string[]> = { '2A': ['C0', 'C1', 'C2'], '2B': ['B0', 'B1', 'B2', 'B3'] }
const modeChoices: Record<Experiment, RunMode[]> = { '2A': ['pilot', 'connectivity', 'deterministic'], '2B': ['connectivity', 'deterministic'] }
const modeNames: Record<RunMode, string> = { pilot: 'C2 agent pilot', connectivity: 'Agent connectivity check', deterministic: 'Model-free fixture check' }

async function getJSON<T>(url: string): Promise<T> {
  const response = await fetch(url, { cache: 'no-store' })
  if (!response.ok) throw new Error(`${response.status}: ${await response.text()}`)
  return response.json() as Promise<T>
}

function timestamp(value: string | null | undefined): string {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString()
}

function shortTime(value: string): string {
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleTimeString([], { hour12: false })
}

function elapsed(start: string | null, end: string | null, now: number): string {
  if (!start) return '—'
  const endMs = end ? new Date(end).getTime() : now
  const amount = Math.max(0, Math.floor((endMs - new Date(start).getTime()) / 1000))
  if (!Number.isFinite(amount)) return '—'
  const minutes = Math.floor(amount / 60)
  return `${String(minutes).padStart(2, '0')}:${String(amount % 60).padStart(2, '0')}`
}

function textOf(value: unknown): string {
  if (typeof value === 'string') return value
  if (value == null) return ''
  return JSON.stringify(value, null, 2)
}

function eventTitle(event: EventRow): string {
  const d = event.detail
  if (event.kind === 'tool_call') return `${String(d.name || 'Tool')} · ${textOf(d.input).slice(0, 130)}`
  if (event.kind === 'tool_result') return `Tool result · ${event.call_id || 'unpaired'}`
  if (event.kind === 'assistant_text') return 'Agent commentary'
  if (event.kind === 'reasoning') return 'Reasoning content omitted by trace'
  if (event.kind === 'filesystem_interaction') return `${String(d.action || 'command')} · ${String(d.command || '')}`
  if (event.kind === 'decoy_request') return `${String(d.method || 'SSH')} ${String(d.route || '')}`
  if (event.kind === 'decoy_response') return `Server response · ${String(d.status || '')}`
  if (event.kind === 'model_call') return `Model call · ${String(d.status || '')}`
  if (event.kind === 'canary_hit') return `Canary stage ${String(d.stage || '')} hit`
  return event.kind.replaceAll('_', ' ')
}

function eventBody(event: EventRow): string {
  const d = event.detail
  if (event.kind === 'assistant_text') return textOf(d.text)
  if (event.kind === 'tool_call') return textOf(d.input)
  if (event.kind === 'tool_result') return textOf(d.output)
  if (event.kind === 'decoy_response') return textOf(d.response_text)
  if (event.kind === 'filesystem_interaction') return `cwd ${String(d.cwd_before || '')} → ${String(d.cwd_after || '')}\nexit ${String(d.exit_code ?? '—')}`
  return ''
}

function statusClass(status: string): string {
  return `status ${status === 'complete' ? 'ok' : status === 'failed' ? 'bad' : status === 'running' ? 'live' : ''}`
}

function App() {
  const [runId, setRunId] = useState(new URLSearchParams(window.location.search).get('run'))
  const [rows, setRows] = useState<RunRow[]>([])
  const [capabilities, setCapabilities] = useState<Capabilities | null>(null)
  const [form, setForm] = useState<FormState | null>(null)
  const [launching, setLaunching] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null)
  const [events, setEvents] = useState<EventRow[]>([])
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [now, setNow] = useState(Date.now())

  function navigate(id: string | null) {
    const url = id ? `?run=${encodeURIComponent(id)}` : window.location.pathname
    window.history.pushState({}, '', url)
    setRunId(id)
    setSnapshot(null)
    setEvents([])
    setSelectedId(null)
    setError(null)
  }

  useEffect(() => {
    const onPop = () => setRunId(new URLSearchParams(window.location.search).get('run'))
    window.addEventListener('popstate', onPop)
    const clock = window.setInterval(() => setNow(Date.now()), 500)
    return () => { window.removeEventListener('popstate', onPop); window.clearInterval(clock) }
  }, [])

  useEffect(() => {
    if (runId) return
    let alive = true
    void getJSON<Capabilities>('/api/experiments').then(value => { if (alive) setCapabilities(value) }).catch(err => { if (alive) setError(String(err)) })
    const refresh = () => getJSON<{ runs: RunRow[] }>('/api/runs').then(data => { if (alive) setRows(data.runs) }).catch(err => { if (alive) setError(String(err)) })
    void refresh()
    const interval = window.setInterval(refresh, 3000)
    return () => { alive = false; window.clearInterval(interval) }
  }, [runId])

  useEffect(() => {
    if (!runId) return
    let alive = true
    let source: EventSource | null = null
    async function load() {
      try {
        const id = runId as string
        const state = await getJSON<Snapshot>(`/api/runs/${encodeURIComponent(id)}`)
        if (!alive) return
        setSnapshot(state)
        let cursor = 0
        const initial: EventRow[] = []
        while (true) {
          const page = await getJSON<{ events: EventRow[]; has_more: boolean }>(`/api/runs/${encodeURIComponent(id)}/events?after=${cursor}&limit=500`)
          initial.push(...page.events)
          cursor = page.events.at(-1)?.event_id ?? cursor
          if (!page.has_more || page.events.length === 0) break
        }
        if (!alive) return
        setEvents(initial)
        source = new EventSource(`/api/runs/${encodeURIComponent(id)}/stream?after=${cursor}`)
        source.addEventListener('run_event', message => {
          const event = JSON.parse((message as MessageEvent).data) as EventRow
          setEvents(previous => previous.some(item => item.event_id === event.event_id) ? previous : [...previous, event])
        })
      } catch (err) {
        if (alive) setError(String(err))
      }
    }
    void load()
    const interval = window.setInterval(() => {
      getJSON<Snapshot>(`/api/runs/${encodeURIComponent(runId)}`).then(state => { if (alive) setSnapshot(state) }).catch(() => {})
    }, 2000)
    return () => { alive = false; source?.close(); window.clearInterval(interval) }
  }, [runId])

  const agentEvents = useMemo(() => events.filter(event => event.source === 'agent' || event.kind === 'agent_started'), [events])
  const serverEvents = useMemo(() => events.filter(event => event.source === 'decoy' || event.source === 'gateway'), [events])
  const picked = events.find(event => event.event_id === selectedId) ?? null
  const linked = picked?.source === 'agent' && picked.kind === 'tool_call'
    ? serverEvents.filter(event => Math.abs(new Date(event.occurred_utc).getTime() - new Date(picked.occurred_utc).getTime()) < 5000)
    : []
  const selected = picked?.source === 'agent'
    ? linked.find(event => event.kind === 'decoy_response') ?? linked.at(-1) ?? null
    : picked ?? serverEvents.at(-1) ?? null
  const agentStarted = snapshot?.agent_started_utc ?? null
  const agentStop = snapshot?.status === 'complete' || snapshot?.status === 'failed' ? snapshot.finished_utc : null
  const entryEvent = events.find(event => snapshot?.experiment === '2A' ? event.kind === 'decoy_request' : event.kind === 'filesystem_interaction')
  const agentToolCount = agentEvents.filter(event => event.kind === 'tool_call').length
  const serverActions = serverEvents.filter(event => event.kind === (snapshot?.experiment === '2A' ? 'decoy_request' : 'filesystem_interaction')).length
  const modelCalls = serverEvents.filter(event => event.kind === 'model_call').length
  const modelRun = form?.mode !== 'deterministic'
  const runLimit = form?.mode === 'pilot' ? '20 min · 80 tools · 60 model calls' :
    form?.mode === 'connectivity' ? '4 min · 20 tools · 8 model calls' : 'No agent or model calls'
  const selectedAgent = capabilities?.experiments.find(item => item.id === form?.experiment)?.agent

  async function launch() {
    if (!form || launching) return
    setLaunching(true)
    setError(null)
    try {
      const session = await getJSON<{ launch_token: string }>('/api/session')
      const response = await fetch('/api/runs', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Shape-Launch-Token': session.launch_token },
        body: JSON.stringify({ experiment: form.experiment, mode: form.mode, arm: form.arm,
          build: form.build, seed: form.seed, branching_factor: form.branching_factor }),
      })
      if (!response.ok) throw new Error(`${response.status}: ${await response.text()}`)
      const job = await response.json() as { run_id: string }
      setForm(null)
      navigate(job.run_id)
    } catch (err) {
      setError(String(err))
    } finally {
      setLaunching(false)
    }
  }

  return <div className="app-shell">
    <header className="topbar">
      <div className="brand" onClick={() => navigate(null)} role="button" tabIndex={0} onKeyDown={event => { if (event.key === 'Enter') navigate(null) }}>
        <span className="brand-mark">S</span><span><strong>SHAPE</strong><small>EXPERIMENT CONSOLE</small></span>
      </div>
      <div className="topbar-right"><span className="online-dot" /> LOCAL LAB <span className="topbar-separator">/</span> 2A + 2B</div>
    </header>

    {!runId ? <main className="home-page">
      <section className="intro">
        <p className="eyebrow">CONTROLLED OBSERVATION</p>
        <h1>Watch the agent.<br /><em>Read the environment.</em></h1>
        <p>Launch an agent run or model-free check, then watch agent activity beside the decoy timeline. Each trial uses isolated containers.</p>
      </section>
      <div className="experiment-grid">
        {(['2A', '2B'] as Experiment[]).map(experiment => <article className={`experiment-card card-${experiment.toLowerCase()}`} key={experiment}>
          <div className="card-top"><span className="card-index">EXPERIMENT {experiment}</span><span className="card-symbol">{experiment === '2A' ? '↗' : '⌁'}</span></div>
          <h2>{experiment === '2A' ? 'OBEY' : 'EXPLORE'}</h2>
          <p>{experiment === '2A' ? 'Track web probes, activation, and the two canary stages.' : 'Track virtual shell commands and the filesystem that answers them.'}</p>
          <div className="arm-tags">{armChoices[experiment].map(arm => <span key={arm}>{arm}</span>)}</div>
          <button className="primary-button" onClick={() => { setForm({ experiment, mode: experiment === '2A' ? 'pilot' : 'connectivity', arm: experiment === '2A' ? 'C2' : 'B0', seed: 'fixture-seed', branching_factor: 4, build: false }); setError(null) }}>New run <span>→</span></button>
        </article>)}
      </div>
      <section className="recent-section">
        <div className="section-heading"><div><p className="eyebrow">ARCHIVE</p><h2>Recent runs</h2></div><span>{rows.length} SHOWN</span></div>
        <div className="run-table-wrap"><table><thead><tr><th>RUN</th><th>EXPERIMENT</th><th>MODE</th><th>ARM</th><th>STATUS</th><th>STARTED</th><th></th></tr></thead><tbody>
          {rows.length === 0 ? <tr><td colSpan={7} className="empty-cell">No archived runs found.</td></tr> : rows.map(row => <tr key={row.run_id} onClick={() => navigate(row.run_id)}>
            <td className="mono">{row.run_id}</td><td>{row.experiment}</td><td>{row.mode}</td><td>{row.arm || '—'}</td><td><span className={statusClass(row.status)}>{row.status}</span></td><td>{timestamp(row.started_utc)}</td><td className="row-arrow">↗</td>
          </tr>)}
        </tbody></table></div>
      </section>
    </main> : <main className="run-page">
      <div className="run-header">
        <div><button className="back-button" onClick={() => navigate(null)}>← All runs</button><p className="eyebrow">{snapshot?.experiment === '2A' ? '2A · OBEY' : snapshot?.experiment === '2B' ? '2B · EXPLORE' : 'RUN'}</p><h1 className="run-title">{runId}</h1><div className="run-meta"><span className={statusClass(snapshot?.status || 'queued')}>{snapshot?.status || 'loading'}</span><span>{snapshot?.mode || '—'}</span><span>{snapshot?.arm || '—'}</span><span>{snapshot?.experimental_result ? 'EXPERIMENTAL' : 'ENGINEERING / FIXTURE'}</span></div></div>
        <div className="timer-card"><span>AGENT ELAPSED</span><strong>{elapsed(agentStarted, agentStop, now)}<small> / {snapshot?.max_wall_seconds ? `${Math.floor(snapshot.max_wall_seconds / 60)}:00` : '—'}</small></strong><div>Decoy engaged <b>{elapsed(entryEvent?.occurred_utc || null, agentStop, now)}</b></div></div>
      </div>
      {snapshot?.mode === 'deterministic_fixture' || snapshot?.mode === 'deterministic' ? <div className="fixture-banner">MODEL-FREE FIXTURE CHECK <span>•</span> No autonomous agent is launched in this mode. Server events are live evidence of the check; agent activity is available in archived agent runs.</div> : null}
      {snapshot?.mode === 'connectivity_fixture' || snapshot?.experiment === '2B' && snapshot?.mode === 'connectivity' ? <div className="fixture-banner">2B AGENT CONNECTIVITY CHECK <span>•</span> B0 uses generic fixture content. This is an engineering check, not a B0–B3 treatment result.</div> : null}
      {snapshot?.error && <div className="fixture-banner">RUN ERROR <span>•</span> {snapshot.error}</div>}
      <div className="monitor-grid">
        <section className="monitor-panel agent-panel"><div className="panel-heading"><div><span className="panel-kicker">01 / AGENT</span><h2>Activity</h2></div><span className="panel-count">{agentEvents.length} events</span></div>
          <div className="event-scroll">{agentEvents.length ? agentEvents.map(event => <button key={event.event_id} className={`event-card ${selectedId === event.event_id ? 'chosen' : ''}`} onClick={() => setSelectedId(event.event_id)}>
            <div className="event-card-top"><span>{shortTime(event.occurred_utc)}</span><span>{event.role?.toUpperCase() || 'AGENT'}</span></div><strong>{eventTitle(event)}</strong>{eventBody(event) && <pre>{eventBody(event).slice(0, 800)}</pre>}
          </button>) : <div className="panel-empty"><span>◌</span><strong>No agent trace in this run</strong><p>{snapshot?.mode?.startsWith('deterministic') ? 'This check exercises only the decoy. Select an archived connectivity or pilot run to inspect agent tool use.' : 'Waiting for agent events.'}</p></div>}</div>
        </section>
        <section className="monitor-panel server-panel"><div className="panel-heading"><div><span className="panel-kicker">02 / {snapshot?.experiment === '2A' ? 'WEB DECOY' : 'FILESYSTEM DECOY'}</span><h2>Server timeline</h2></div><span className="panel-count">{serverEvents.length} events</span></div>
          <div className="server-content"><div className="server-rail">{serverEvents.length ? serverEvents.map(event => <button key={event.event_id} className={`rail-event ${selected?.event_id === event.event_id ? 'chosen' : ''} ${['activation', 'canary_hit', 'reinforcement_delivered'].includes(event.kind) ? 'milestone' : ''}`} onClick={() => setSelectedId(event.event_id)}><span className="rail-dot" /><span className="rail-time">{shortTime(event.occurred_utc)}</span><span className="rail-title">{eventTitle(event)}</span></button>) : <div className="panel-empty"><span>◌</span><strong>Waiting for server events</strong><p>Build and preflight may still be running.</p></div>}</div>
            <div className="detail-card"><div className="detail-top"><span>SELECTED EVENT</span><span>#{selected?.event_id || '—'}</span></div>{picked?.source === 'agent' && <div className="relation-note">{linked.length ? `${linked.length} nearby server event${linked.length === 1 ? '' : 's'} · time-correlated, not an exact tool link` : 'No server event can be linked to this agent item yet.'}</div>}{selected ? <><h3>{eventTitle(selected)}</h3><p>{timestamp(selected.occurred_utc)} · {selected.source}</p><pre>{eventBody(selected) || JSON.stringify(selected.detail, null, 2)}</pre></> : <p>Select a timeline event to inspect the raw observation.</p>}</div>
          </div>
        </section>
      </div>
      <div className="metric-strip"><div><span>AGENT TOOLS</span><strong>{agentToolCount}</strong></div><div><span>{snapshot?.experiment === '2A' ? 'WEB REQUESTS' : 'FS ACTIONS'}</span><strong>{serverActions}</strong></div><div><span>MODEL CALLS</span><strong>{modelCalls}</strong></div><div><span>TERMINATION</span><strong>{snapshot?.termination_reason || '—'}</strong></div></div>
    </main>}

    {error && <div className="error-toast" role="alert">{error}<button onClick={() => setError(null)}>×</button></div>}
    {form && <div className="modal-backdrop" onMouseDown={event => { if (event.target === event.currentTarget) setForm(null) }}><section className="config-modal" role="dialog" aria-modal="true" aria-label="Configure run"><div className="modal-top"><span>NEW {form.experiment} RUN</span><button onClick={() => setForm(null)}>×</button></div><h2>{modeNames[form.mode]}</h2><p>{form.mode === 'pilot' ? 'Runs the pinned PentestGPT agent against the 2A C2 pilot. Model calls use the key in the repository .env.' : form.mode === 'connectivity' ? form.experiment === '2B' ? 'Runs PentestGPT against the B0 generic fixture to verify the imitated SSH path. This is not a study result.' : 'Runs a bounded PentestGPT check against the 2A web decoy.' : 'Exercises the decoy with scripted probes. No autonomous agent or model call starts.'}</p>
      <label>Run mode<select value={form.mode} onChange={event => { const mode = event.target.value as RunMode; setForm({ ...form, mode, arm: form.experiment === '2A' && mode === 'pilot' ? 'C2' : form.experiment === '2B' && mode === 'connectivity' ? 'B0' : form.arm, branching_factor: mode === 'connectivity' ? 4 : form.branching_factor }) }}>{modeChoices[form.experiment].map(mode => <option key={mode} value={mode}>{modeNames[mode]}</option>)}</select></label>
      <label>Experiment arm<select value={form.arm} disabled={form.mode === 'pilot' || form.experiment === '2B' && form.mode === 'connectivity'} onChange={event => setForm({ ...form, arm: event.target.value })}>{(form.mode === 'pilot' ? ['C2'] : form.experiment === '2B' && form.mode === 'connectivity' ? ['B0'] : armChoices[form.experiment]).map(arm => <option key={arm}>{arm}</option>)}</select></label>
      {form.experiment === '2B' && <><label>Filesystem seed<input value={form.seed} maxLength={128} onChange={event => setForm({ ...form, seed: event.target.value })} /></label>{form.mode === 'deterministic' && <label>Branching factor<input type="number" min={1} max={15} value={form.branching_factor} onChange={event => setForm({ ...form, branching_factor: Number(event.target.value) })} /></label>}</>}
      <label className="checkbox-row"><input type="checkbox" checked={form.build} onChange={event => setForm({ ...form, build: event.target.checked })} /><span>Rebuild Docker images for this run</span></label>
      <div className="config-summary"><span>AGENT</span><strong>{modelRun ? `PentestGPT · ${selectedAgent?.model || 'glm-5.3-flash'} · ${selectedAgent?.effort || 'max'} effort` : 'No agent'}</strong><span>LIMITS</span><strong>{runLimit}</strong><span>CREDENTIAL</span><strong>{modelRun ? capabilities?.credential_configured ? 'Z.AI key configured in root .env' : 'Z.AI key missing from root .env' : 'Not used'}</strong><span>STATUS</span><strong>{form.experiment === '2B' && form.mode === 'connectivity' ? 'Generic fixture · engineering check' : form.mode === 'pilot' ? '2A engineering pilot' : 'Engineering check'}</strong></div>
      <button className="primary-button launch-button" disabled={launching || modelRun && !capabilities?.credential_configured || form.experiment === '2B' && (!form.seed || form.mode === 'deterministic' && (form.branching_factor < 1 || form.branching_factor > 15))} onClick={launch}>{launching ? 'Starting…' : 'Run experiment'} <span>→</span></button>
    </section></div>}
  </div>
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>)
