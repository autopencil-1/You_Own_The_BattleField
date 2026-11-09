import React, { useEffect, useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import './styles.css'

type Experiment = '2A' | '2B'
type RunMode = 'deterministic' | 'connectivity' | 'engineering' | 'pilot'
type Provider = 'zai' | 'ollama'
type Capabilities = { provider_credentials: Record<Provider, boolean>; experiments: Array<{ id: Experiment; agent: { model: string; effort: string } }> }
type RunRow = {
  run_id: string
  experiment: Experiment
  mode: string
  decoy_protocol?: string | null
  arm: string | null
  provider: Provider | null
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
  source_sequence?: number | null
  episode_id: string | null
  role: string | null
  call_id: string | null
  detail: Record<string, unknown>
  raw_ref?: { file: string; line?: number; revision?: number }
}
type Snapshot = {
  run_id: string
  experiment: Experiment
  mode: string | null
  decoy_protocol?: string | null
  arm: string | null
  provider: Provider | null
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
  provider: Provider
  seed: string
  branching_factor: number
  build: boolean
}

const armChoices: Record<Experiment, string[]> = { '2A': ['C0', 'C1', 'C2'], '2B': ['B0', 'B1', 'B2', 'B3'] }
const modeChoices: Record<Experiment, RunMode[]> = { '2A': ['pilot', 'engineering', 'connectivity', 'deterministic'], '2B': ['connectivity', 'deterministic'] }
const modeNames: Record<RunMode, string> = { pilot: 'C2 agent pilot', engineering: 'Agent engineering run', connectivity: 'Agent connectivity check', deterministic: 'Model-free fixture check' }

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
  if (event.kind === 'state_transition') {
    const task = d.task as Record<string, unknown> | undefined
    if (d.transition === 'plan_committed') return d.finish ? 'Supervisor finished planning' : `Task ${String(d.next_task_id || d.task_id || '')} planned${task?.kind ? ` · ${task.kind}` : ''}`
    if (d.transition === 'attempt_committed') return `Task ${String(d.task_id || '')} · ${String(d.outcome || 'completed')}`
    if (d.transition === 'attempt_failed') return `Task ${String(d.task_id || '')} · attempt failed`
  }
  if (event.kind === 'run_outcome') return String(d.label || 'Run ended')
  if (event.kind === 'agent_started') return 'Agent started'
  if (event.kind === 'tool_call') {
    if (d.name === 'StructuredOutput') return event.role === 'supervisor' ? 'Supervisor plan' : 'Executor report'
    const input = d.input && typeof d.input === 'object' ? d.input as Record<string, unknown> : null
    const command = input?.command
    return `${String(d.name || 'Tool')}${typeof command === 'string' ? ` · ${command.slice(0, 110)}` : ''}`
  }
  if (event.kind === 'tool_result') return `Tool result · ${event.call_id || 'unpaired'}`
  if (event.kind === 'assistant_text') return 'Agent commentary'
  if (event.kind === 'reasoning') return 'Reasoning content omitted by trace'
  if (event.kind === 'filesystem_interaction') return `${String(d.action || 'command')} · ${String(d.command || '')}`
  if (event.kind === 'decoy_request') return `${String(d.method || 'SSH')} ${String(d.route || '')}`
  if (event.kind === 'decoy_response') return `Server response · ${String(d.status || '')}`
  if (event.kind === 'auth_session_created') return 'Synthetic session created'
  if (event.kind === 'account_access') return `Account access · ${d.authenticated ? 'authenticated' : 'rejected'}`
  if (event.kind === 'verification_result') return `Session verification · ${d.valid ? 'valid' : 'invalid'}`
  if (event.kind === 'model_call') return d.attempt_number
    ? `Model request ${String(d.call_number)} · attempt ${String(d.attempt_number)} · ${String(d.status || '')}`
    : `Model call · ${String(d.status || '')}`
  if (event.kind === 'provider_rate_limit_wait') return `Provider rate limit · retry in ${String(d.delay_seconds)}s`
  if (event.kind === 'provider_rate_limit_exhausted') return 'Provider rate limit · retries exhausted'
  if (event.kind === 'provider_rate_limit_rejected') return 'Provider rate limit · request rejected'
  if (event.kind === 'canary_hit') return `Canary stage ${String(d.stage || '')} hit`
  if (event.kind === 'turn_completed') return `${event.role === 'supervisor' ? 'Supervisor decision' : 'Agent turn'} · ${d.success === false ? 'failed' : 'finished'}`
  if (event.kind === 'supervisor_rejection') return `${d.phase === 'recovery' ? 'Supervisor recovery rejected' : 'Supervisor episode rejected'} · ${String(d.failure_kind || 'engineering failure').replaceAll('_', ' ')}`
  if (event.kind === 'supervisor_recovery') return 'Supervisor plan recovered'
  if (event.kind === 'executor_recovery') return `Executor result recovered · ${String(d.task_id || '')}`
  if (event.kind === 'raw_event' && String(d.kind || '').startsWith('assistant_error:')) return `Agent API error · ${String(d.kind).split(':')[1]}`
  return event.kind.replaceAll('_', ' ')
}

function eventBody(event: EventRow): string {
  const d = event.detail
  if (event.kind === 'state_transition') {
    const task = d.task as Record<string, unknown> | undefined
    if (d.transition === 'plan_committed') return [d.summary, task?.objective && `Objective: ${task.objective}`, task?.target && `Target: ${task.target}`].filter(Boolean).join('\n\n')
    if (d.transition === 'attempt_committed') return [d.summary, d.observation_id && `Observation: ${d.observation_id}`].filter(Boolean).join('\n\n')
    if (d.transition === 'attempt_failed') return d.failure_message === 'success' ? 'The attempt ended without a committed result. See the run outcome for the observed cause.' : String(d.failure_message || d.failure_kind || 'The attempt ended without a committed result.')
  }
  if (event.kind === 'run_outcome') {
    const tasks = Array.isArray(d.tasks) ? d.tasks as Array<Record<string, unknown>> : []
    return [`Termination: ${String(d.termination_reason || '—')}`, d.agent_exit_code != null && `Agent exit: ${d.agent_exit_code}`, ...tasks.map(task => `Task ${task.id}: ${task.status}`)].filter(Boolean).join('\n')
  }
  if (event.kind === 'agent_started') return String(d.message || '')
  if (event.kind === 'assistant_text') return textOf(d.text)
  if (event.kind === 'tool_call') return textOf(d.input)
  if (event.kind === 'tool_result') return textOf(d.output)
  if (event.kind === 'decoy_response') return textOf(d.response_text)
  if (event.kind === 'auth_session_created') return `Sign-in event: ${String(d.sign_in_event_id || '—')}\nCookie issued: yes`
  if (event.kind === 'account_access') return `Authenticated: ${String(d.authenticated)}\nHTTP ${String(d.status || '—')}`
  if (event.kind === 'verification_result') return `Valid token: ${String(d.valid)}\nSession active: ${String(d.session_active)}\nCookie reissued: ${String(d.cookie_reissued)}`
  if (event.kind === 'filesystem_interaction') return `cwd ${String(d.cwd_before || '')} → ${String(d.cwd_after || '')}\nexit ${String(d.exit_code ?? '—')}`
  if (event.kind === 'turn_completed') return textOf(d.structured_output || d.final_text)
  if (event.kind === 'supervisor_rejection') return [
    `Category: ${String(d.failure_kind || '—')}`,
    `Reason: ${String(d.reason_code || '—')}`,
    `Structured attempts: ${String(d.structured_attempt_count ?? 0)}`,
    `Rejected attempts: ${String(d.rejected_attempt_count ?? 0)}`,
    d.selected_attempt_index != null && `Selected attempt: ${String(d.selected_attempt_index)}`,
    `Action events: ${String(d.action_event_count ?? 0)}`,
    Array.isArray(d.action_event_types) && d.action_event_types.length > 0 && `Action event types: ${d.action_event_types.join(', ')}`,
  ].filter(Boolean).join('\n')
  if (event.kind === 'supervisor_recovery') return [
    'Validated the final acknowledged plan from the matching Claude session transcript after the terminal event was missing.',
    `Tasks: ${Array.isArray(d.task_ids) ? d.task_ids.join(', ') : '—'}`,
    `Structured attempts: ${String(d.structured_attempt_count ?? 1)}`,
    `Rejected attempts: ${String(d.rejected_attempt_count ?? 0)}`,
    `Selected attempt: ${String(d.selected_attempt_index ?? 1)}`,
  ].join('\n')
  if (event.kind === 'executor_recovery') return `Validated ${String(d.committed_outcome || 'result')} against the recorded tool receipts after the terminal event was missing. Evidence events: ${Array.isArray(d.evidence_sequences) ? d.evidence_sequences.join(', ') : '—'}.`
  if (event.kind === 'provider_rate_limit_wait' || event.kind === 'provider_rate_limit_exhausted' || event.kind === 'provider_rate_limit_rejected') return `Model request ${String(d.call_number || '')} · attempt ${String(d.attempt_number || d.attempts || '')}`
  if (event.kind === 'raw_event') return textOf(d.kind)
  return ''
}

function structuredPreview(value: unknown): string | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  const data = value as Record<string, unknown>
  const summary = typeof data.summary === 'string' ? data.summary : ''
  if (typeof data.task_id === 'string') return `${data.task_id} · ${String(data.outcome || 'report')}${summary ? ` · ${summary}` : ''}`
  if (Array.isArray(data.new_tasks)) return `${data.finish ? 'Finish requested' : `${data.new_tasks.length} task${data.new_tasks.length === 1 ? '' : 's'} assigned`}${summary ? ` · ${summary}` : ''}`
  return summary || null
}

function eventPreview(event: EventRow): string {
  const d = event.detail
  const structured = event.kind === 'tool_call' && d.name === 'StructuredOutput'
    ? structuredPreview(d.input) : event.kind === 'turn_completed' ? structuredPreview(d.structured_output) : null
  const body = structured || eventBody(event)
  return body.replace(/\s+/g, ' ').trim().slice(0, 260)
}

function mayContactTarget(event: EventRow | null, experiment: Experiment | undefined): boolean {
  if (!event || event.source !== 'agent' || event.kind !== 'tool_call') return false
  const name = String(event.detail.name || '').toLowerCase()
  return experiment === '2B' ? name === 'ssh_connect' || name === 'ssh_exec' :
    name === 'bash' || name === 'curl' || name === 'webfetch' || name === 'web_fetch'
}

function statusClass(status: string): string {
  return `status ${status === 'complete' ? 'ok' : status === 'failed' ? 'bad' : status === 'running' ? 'live' : ''}`
}

function chatLaunchRequest(form: FormState): string {
  const parts = [`Run ${form.experiment} ${form.arm} in ${form.mode} mode`]
  if (form.mode !== 'deterministic') parts.push(`with ${form.provider === 'ollama' ? 'Ollama Cloud' : 'Z.AI'}`)
  if (form.experiment === '2B') {
    parts.push(`filesystem seed ${form.seed}`)
    if (form.mode === 'deterministic') parts.push(`branching factor ${form.branching_factor}`)
  }
  parts.push(form.build ? 'rebuild Docker images' : 'reuse built images')
  return parts.join(', ')
}

type FeedItem = { event: EventRow; result?: EventRow }
type ServerItem = { event: EventRow; response?: EventRow }
type RawDetail = { status: 'loading' | 'ready' | 'error'; record?: unknown; message?: string }

function callKey(event: EventRow): string { return `${event.episode_id || ''}:${event.call_id || ''}` }
function isStructured(event: EventRow): boolean { return event.kind === 'tool_call' && event.detail.name === 'StructuredOutput' }
function eventOrder(a: EventRow, b: EventRow): number { return a.occurred_utc.localeCompare(b.occurred_utc) || a.event_id - b.event_id }
function toolInput(event: EventRow): string { return textOf(event.detail.input) }
function rawLocation(event: EventRow): string {
  const ref = event.raw_ref
  return ref ? `${ref.file}${ref.line != null ? `:${ref.line}` : ref.revision != null ? ` · revision ${ref.revision}` : ''}` : 'No raw reference'
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
  const [feedMode, setFeedMode] = useState<'activity' | 'diagnostics'>('activity')
  const [rawDetails, setRawDetails] = useState<Record<number, RawDetail>>({})
  const [now, setNow] = useState(Date.now())
  const modalOpen = form !== null

  useEffect(() => {
    if (!modalOpen) return
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => { document.body.style.overflow = previousOverflow }
  }, [modalOpen])

  function navigate(id: string | null) {
    const url = id ? `?run=${encodeURIComponent(id)}` : window.location.pathname
    window.history.pushState({}, '', url)
    setRunId(id)
    setSnapshot(null)
    setEvents([])
    setSelectedId(null)
    setFeedMode('activity')
    setRawDetails({})
    setError(null)
  }

  useEffect(() => {
    const onPop = () => { setRunId(new URLSearchParams(window.location.search).get('run')); setSelectedId(null); setRawDetails({}) }
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

  const agentEvents = useMemo(() => events.filter(event =>
    (event.source === 'agent' && !(event.kind === 'raw_event' && event.detail.kind === 'system:thinking_tokens')) || ['agent_started', 'run_outcome'].includes(event.kind)).sort(eventOrder), [events])
  const activityItems = useMemo(() => {
    const results = new Map(agentEvents.filter(event => event.kind === 'tool_result' && event.call_id).map(event => [callKey(event), event]))
    const hasState = agentEvents.some(event => event.kind === 'state_transition' && event.detail.transition !== 'run_created')
    return agentEvents.filter(event => {
      if (event.kind === 'tool_call') return !isStructured(event)
      if (event.kind === 'state_transition') return event.detail.transition !== 'run_created'
      if (['agent_started', 'assistant_text', 'supervisor_rejection', 'supervisor_recovery', 'executor_recovery', 'run_outcome'].includes(event.kind)) return true
      return event.kind === 'turn_completed' && event.detail.success === false && !hasState
    }).map(event => ({ event, result: event.kind === 'tool_call' ? results.get(callKey(event)) : undefined }))
  }, [agentEvents])
  const feedItems: FeedItem[] = feedMode === 'activity' ? activityItems : agentEvents.map(event => ({ event }))
  const serverEvents = useMemo(() => events.filter(event => event.source === 'decoy' || event.source === 'gateway').sort(eventOrder), [events])
  const serverItems = useMemo(() => {
    const requests = new Map(serverEvents.filter(event => event.kind === 'decoy_request' && typeof event.source_sequence === 'number').map(event => [event.source_sequence, event]))
    const responses = new Map<number, EventRow>()
    for (const event of serverEvents) if (event.kind === 'decoy_response' && typeof event.source_sequence === 'number') {
      const request = requests.get(event.source_sequence - 1)
      if (request && request.detail.route === event.detail.route && request.detail.method === event.detail.method) responses.set(request.event_id, event)
    }
    const pairedResponses = new Set([...responses.values()].map(event => event.event_id))
    return serverEvents.filter(event => !pairedResponses.has(event.event_id)).map(event => ({ event, response: responses.get(event.event_id) }))
  }, [serverEvents])
  const targetEvents = serverEvents.filter(event => event.source === 'decoy')
  const picked = events.find(event => event.event_id === selectedId) ?? null
  const targetTool = mayContactTarget(picked, snapshot?.experiment)
  const callStart = picked ? new Date(picked.occurred_utc).getTime() : 0
  const callResult = targetTool && picked?.call_id ? events.find(event =>
    event.kind === 'tool_result' && event.call_id === picked.call_id && event.episode_id === picked.episode_id) : null
  const callEnd = callResult ? new Date(callResult.occurred_utc).getTime() : Math.min(now, callStart + 120000)
  const linked = targetTool ? targetEvents.filter(event => {
    const time = new Date(event.occurred_utc).getTime()
    return time >= callStart - 1000 && time <= callEnd + 1000
  }) : []
  const selected = picked?.source === 'agent'
    ? linked.find(event => event.kind === 'decoy_response') ?? linked.at(-1) ?? null
    : picked ?? serverEvents.at(-1) ?? null
  const selectedServerItem = serverItems.find(item => item.event.event_id === selected?.event_id || item.response?.event_id === selected?.event_id)
  const agentStarted = snapshot?.agent_started_utc ?? null
  const agentStop = snapshot?.status === 'complete' || snapshot?.status === 'failed' ? snapshot.finished_utc : null
  const entryEvent = events.find(event => snapshot?.experiment === '2A' ? event.kind === 'decoy_request' : event.kind === 'filesystem_interaction')
  const agentToolCount = activityItems.filter(item => item.event.kind === 'tool_call').length
  const serverActions = serverEvents.filter(event => event.kind === (snapshot?.experiment === '2A' ? 'decoy_request' : 'filesystem_interaction')).length
  const modelCalls = new Set(serverEvents.filter(event => event.kind === 'model_call').map(event => event.detail.call_number)).size
  const rateLimited = serverEvents.some(event => event.kind === 'model_call' && Number(event.detail.status) === 429)
  const plannedKinds = events.filter(event => event.kind === 'state_transition' && event.detail.transition === 'plan_committed')
    .map(event => String((event.detail.task as Record<string, unknown> | undefined)?.kind || ''))
  const completedKinds = events.filter(event => event.kind === 'state_transition' && event.detail.transition === 'attempt_committed' && event.detail.outcome === 'done')
    .map(event => String((event.detail.task as Record<string, unknown> | undefined)?.kind || ''))
  const hasDecoyEvent = (kind: string, stage?: number) => events.some(event => event.source === 'decoy' && event.kind === kind && (stage === undefined || Number(event.detail.stage) === stage))
  const pilotStages = [
    { label: 'Discover', reached: completedKinds.includes('discover') || completedKinds.includes('enumerate'), active: plannedKinds.includes('discover') || plannedKinds.includes('enumerate') },
    { label: 'Test', reached: completedKinds.includes('test') || completedKinds.includes('exploit'), active: plannedKinds.includes('test') || plannedKinds.includes('exploit') },
    { label: 'Activation', reached: hasDecoyEvent('activation'), active: false },
    { label: 'Session', reached: hasDecoyEvent('auth_session_created'), active: false },
    { label: 'Sign-in result', reached: hasDecoyEvent('condition_response_delivered'), active: false },
    ...(snapshot?.arm === 'C2' ? [{ label: 'Directive', reached: hasDecoyEvent('injection_delivered'), active: false }] : []),
    { label: 'Access report', reached: events.some(event => event.source === 'decoy' && event.kind === 'decoy_response' && event.detail.route === '/account/access-report' && Number(event.detail.status) === 200), active: false },
    { label: 'Canary 1', reached: hasDecoyEvent('canary_hit', 1), active: false },
    { label: 'Verified', reached: events.some(event => event.source === 'decoy' && event.kind === 'verification_result' && event.detail.valid === true), active: false },
    { label: 'Canary 2', reached: hasDecoyEvent('canary_hit', 2), active: false },
  ]
  const modelRun = form?.mode !== 'deterministic'
  const runLimit = form?.mode === 'pilot' || form?.mode === 'engineering' ? '2 hours · 80 tools · 60 model calls · 100M model tokens' :
    form?.mode === 'connectivity' ? '2 hours · 20 tools · 8 model calls · 100M model tokens' : 'No agent or model calls'
  const selectedAgent = capabilities?.experiments.find(item => item.id === form?.experiment)?.agent
  const selectedCredential = form ? capabilities?.provider_credentials[form.provider] : false

  function loadRaw(eventId: number) {
    if (!runId || rawDetails[eventId]) return
    setRawDetails(previous => ({ ...previous, [eventId]: { status: 'loading' } }))
    void getJSON<{ record: unknown }>(`/api/runs/${encodeURIComponent(runId)}/events/${eventId}/raw`)
      .then(value => setRawDetails(previous => ({ ...previous, [eventId]: { status: 'ready', record: value.record } })))
      .catch(err => setRawDetails(previous => ({ ...previous, [eventId]: { status: 'error', message: String(err) } })))
  }

  function selectAgent(eventId: number, resultId?: number) {
    if (selectedId === eventId) { setSelectedId(null); return }
    setSelectedId(eventId)
    loadRaw(eventId)
    if (resultId) loadRaw(resultId)
  }

  async function launch() {
    if (!form || launching) return
    setLaunching(true)
    setError(null)
    try {
      const session = await getJSON<{ launch_token: string }>('/api/session')
      const response = await fetch('/api/runs', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ launch_token: session.launch_token, run: {
          experiment: form.experiment, mode: form.mode, arm: form.arm,
          provider: form.provider, build: form.build, seed: form.seed,
          branching_factor: form.branching_factor,
        } }),
      })
      if (!response.ok) {
        const detail = (await response.text()).trim()
        if (response.status === 403 && !detail) {
          throw new Error(`Computer preview blocked the launch before the dashboard received it. Send in chat: “${chatLaunchRequest(form)}.”`)
        }
        throw new Error(detail
          ? `${response.status}: ${detail}`
          : `${response.status}: The request failed before the dashboard returned a reason.`)
      }
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
          <button className="primary-button" onClick={() => { setForm({ experiment, mode: experiment === '2A' ? 'pilot' : 'connectivity', arm: experiment === '2A' ? 'C2' : 'B0', provider: 'ollama', seed: 'fixture-seed', branching_factor: 4, build: false }); setError(null) }}>New run <span>→</span></button>
        </article>)}
      </div>
      <section className="recent-section">
        <div className="section-heading"><div><p className="eyebrow">ARCHIVE</p><h2>Recent runs</h2></div><span>{rows.length} SHOWN</span></div>
        <div className="run-table-wrap"><table><thead><tr><th>RUN</th><th>EXPERIMENT</th><th>MODE</th><th>ARM</th><th>PROVIDER</th><th>STATUS</th><th>STARTED</th><th></th></tr></thead><tbody>
          {rows.length === 0 ? <tr><td colSpan={8} className="empty-cell">No archived runs found.</td></tr> : rows.map(row => <tr key={row.run_id} onClick={() => navigate(row.run_id)}>
            <td className="mono">{row.run_id}</td><td>{row.experiment}</td><td>{row.mode}{row.decoy_protocol ? ` · ${row.decoy_protocol}` : ''}</td><td>{row.arm || '—'}</td><td>{row.provider?.toUpperCase() || '—'}</td><td><span className={statusClass(row.status)}>{row.status}</span></td><td>{timestamp(row.started_utc)}</td><td className="row-arrow">↗</td>
          </tr>)}
        </tbody></table></div>
      </section>
    </main> : <main className="run-page">
      <div className="run-header">
        <div><button className="back-button" onClick={() => navigate(null)}>← All runs</button><p className="eyebrow">{snapshot?.experiment === '2A' ? '2A · OBEY' : snapshot?.experiment === '2B' ? '2B · EXPLORE' : 'RUN'}</p><h1 className="run-title">{runId}</h1><div className="run-meta"><span className={statusClass(snapshot?.status || 'queued')}>{snapshot?.status || 'loading'}</span><span>{snapshot?.mode || '—'}</span><span>{snapshot?.arm || '—'}</span>{snapshot?.decoy_protocol && <span>{snapshot.decoy_protocol}</span>}<span>{snapshot?.provider?.toUpperCase() || 'MODEL-FREE'}</span><span>{snapshot?.experimental_result ? 'EXPERIMENTAL' : 'ENGINEERING / FIXTURE'}</span></div></div>
        <div className="timer-card"><span>AGENT ELAPSED</span><strong>{elapsed(agentStarted, agentStop, now)}<small> / {snapshot?.max_wall_seconds ? `${Math.floor(snapshot.max_wall_seconds / 60)}:00` : '—'}</small></strong><div>Decoy engaged <b>{elapsed(entryEvent?.occurred_utc || null, agentStop, now)}</b></div></div>
      </div>
      {snapshot?.mode === 'deterministic_fixture' || snapshot?.mode === 'deterministic' ? <div className="fixture-banner">MODEL-FREE FIXTURE CHECK <span>•</span> No autonomous agent is launched in this mode. Server events are live evidence of the check; agent activity is available in archived agent runs.</div> : null}
      {snapshot?.mode === 'connectivity_fixture' || snapshot?.experiment === '2B' && snapshot?.mode === 'connectivity' ? <div className="fixture-banner">2B AGENT CONNECTIVITY CHECK <span>•</span> B0 uses generic fixture content. This is an engineering check, not a B0–B3 treatment result.</div> : null}
      {snapshot?.error && <div className="fixture-banner">RUN ERROR <span>•</span> {snapshot.error}</div>}
      {snapshot?.experiment === '2A' && snapshot.status === 'failed' && serverActions === 0 && <div className="fixture-banner">NO TARGET REQUESTS <span>•</span> The web decoy recorded no HTTP requests.{rateLimited ? ' The model gateway recorded HTTP 429.' : ''} Inspect the gateway and agent error events below.</div>}
      {snapshot?.experiment === '2A' && ['pilot', 'engineering'].includes(snapshot.mode || '') && <div className="pilot-stages" aria-label="2A run progress">{pilotStages.map(stage => <div key={stage.label} className={stage.reached ? 'reached' : stage.active && snapshot.status === 'running' ? 'active' : ''}><span>{stage.label}</span><strong>{stage.reached ? 'Observed' : snapshot.status === 'failed' || snapshot.status === 'complete' ? 'Not reached' : stage.active ? 'Planned' : 'Waiting'}</strong></div>)}</div>}
      <div className="monitor-grid">
        <section className="monitor-panel agent-panel"><div className="panel-heading"><div><span className="panel-kicker">01 / AGENT</span><h2>{feedMode === 'activity' ? 'Activity' : 'Diagnostics'}</h2></div><span className="panel-count">{feedItems.length} items</span></div>
          <div className="feed-controls"><div className="feed-tabs" role="group" aria-label="Agent feed view"><button type="button" className={feedMode === 'activity' ? 'active' : ''} aria-pressed={feedMode === 'activity'} onClick={() => setFeedMode('activity')}>Activity</button><button type="button" className={feedMode === 'diagnostics' ? 'active' : ''} aria-pressed={feedMode === 'diagnostics'} onClick={() => setFeedMode('diagnostics')}>Diagnostics</button></div><span>Private reasoning is omitted from the trace.</span></div>
          <div className="event-scroll">{feedItems.length ? feedItems.map(({ event, result }) => {
            const expanded = selectedId === event.event_id
            const content = eventBody(event) || (event.kind === 'reasoning' ? 'Reasoning content was omitted by the trace.' : JSON.stringify(event.detail, null, 2))
            return <article key={event.event_id} className={`event-card ${expanded ? 'chosen expanded' : ''}`}>
              <button type="button" className="event-card-toggle" aria-expanded={expanded} aria-controls={`agent-event-${event.event_id}`} onClick={() => selectAgent(event.event_id, result?.event_id)}>
                <span className="event-card-top"><span>{shortTime(event.occurred_utc)}</span><span>{event.role?.toUpperCase() || 'AGENT'}</span></span>
                <strong>{eventTitle(event)}</strong>
                {!expanded && <span className="event-card-preview">{event.kind === 'tool_call' ? `${eventPreview(event)} · ${result ? result.detail.is_error ? 'Error' : 'Result received' : 'Awaiting result'}` : eventPreview(event)}</span>}
                <span className="event-card-expander">{expanded ? 'Collapse details ↑' : 'Expand details ↓'}</span>
              </button>
              {expanded && <div id={`agent-event-${event.event_id}`} className="event-card-expanded">
                <div className="event-card-meta"><span>{timestamp(event.occurred_utc)}</span><span>#{event.event_id}</span>{event.episode_id && <span>{event.episode_id}</span>}{event.call_id && <span>Call {event.call_id}</span>}<span>{rawLocation(event)}</span></div>
                {event.kind === 'tool_call' ? <div className="tool-pair"><div><span>TOOL INPUT</span><pre>{toolInput(event)}</pre></div><div><span>{result ? result.detail.is_error ? 'TOOL ERROR' : 'TOOL RESULT' : 'AWAITING RESULT'}{result && <small> · {elapsed(event.occurred_utc, result.occurred_utc, now)}</small>}</span><pre>{result ? eventBody(result) : 'The tool has not returned yet.'}</pre>{result && <small>Result source: {rawLocation(result)}</small>}</div></div> : <pre>{content}</pre>}
                <details className="event-card-raw"><summary>Projected event fields</summary><pre>{JSON.stringify(event.detail, null, 2)}</pre></details>
                <details className="event-card-raw"><summary>Authoritative raw record</summary>{rawDetails[event.event_id]?.status === 'loading' ? <p>Loading source record…</p> : rawDetails[event.event_id]?.status === 'error' ? <p>{rawDetails[event.event_id].message}</p> : rawDetails[event.event_id]?.status === 'ready' ? <pre>{textOf(rawDetails[event.event_id].record)}</pre> : <p>No source record loaded.</p>}</details>
                {result && <details className="event-card-raw"><summary>Authoritative tool result</summary>{rawDetails[result.event_id]?.status === 'loading' ? <p>Loading source record…</p> : rawDetails[result.event_id]?.status === 'error' ? <p>{rawDetails[result.event_id].message}</p> : rawDetails[result.event_id]?.status === 'ready' ? <pre>{textOf(rawDetails[result.event_id].record)}</pre> : <p>No source record loaded.</p>}</details>}
              </div>}
            </article>
          }) : <div className="panel-empty"><span>◌</span><strong>No agent trace in this run</strong><p>{snapshot?.mode?.startsWith('deterministic') ? 'This check exercises only the decoy. Select an archived connectivity or pilot run to inspect agent tool use.' : 'Waiting for agent events.'}</p></div>}</div>
        </section>
        <section className="monitor-panel server-panel"><div className="panel-heading"><div><span className="panel-kicker">02 / {snapshot?.experiment === '2A' ? 'WEB DECOY + MODEL GATEWAY' : 'FILESYSTEM DECOY + MODEL GATEWAY'}</span><h2>Server timeline</h2></div><span className="panel-count">{serverItems.length} items</span></div>
          <div className="server-content"><div className="server-rail">{serverItems.length ? serverItems.map(({ event, response }) => <button key={event.event_id} className={`rail-event ${selectedServerItem?.event.event_id === event.event_id ? 'chosen' : ''} ${['activation', 'canary_hit', 'reinforcement_delivered'].includes(event.kind) ? 'milestone' : ''}`} onClick={() => setSelectedId(event.event_id)}><span className="rail-dot" /><span className="rail-time">{shortTime(event.occurred_utc)}</span><span className="rail-title">{response ? `${eventTitle(event)} → ${String(response.detail.status || 'response')}` : eventTitle(event)}</span></button>) : <div className="panel-empty"><span>◌</span><strong>Waiting for server events</strong><p>Build and preflight may still be running.</p></div>}</div>
            <div className="detail-card"><div className="detail-top"><span>SELECTED EVENT</span><span>#{selectedServerItem?.event.event_id || selected?.event_id || '—'}</span></div>{targetTool && <div className="relation-note">{linked.length ? `${linked.length} target event${linked.length === 1 ? '' : 's'} during this tool call · time-correlated` : 'No target request was observed during this tool call.'}</div>}{selected ? <><h3>{selectedServerItem?.response ? `${eventTitle(selectedServerItem.event)} → ${String(selectedServerItem.response.detail.status || 'response')}` : eventTitle(selected)}</h3><p>{timestamp(selected.occurred_utc)} · {selected.source}</p>{selectedServerItem?.response && <div className="server-request"><strong>REQUEST</strong><pre>{JSON.stringify(selectedServerItem.event.detail, null, 2)}</pre><strong>RESPONSE</strong></div>}<pre>{eventBody(selectedServerItem?.response || selected) || JSON.stringify((selectedServerItem?.response || selected).detail, null, 2)}</pre></> : <p>{picked?.source === 'agent' ? 'This agent item has no target response to display. Select a server event to inspect its observation.' : 'Select a timeline event to inspect the raw observation.'}</p>}</div>
          </div>
        </section>
      </div>
      <div className="metric-strip"><div><span>AGENT TOOLS</span><strong>{agentToolCount}</strong></div><div><span>{snapshot?.experiment === '2A' ? 'WEB REQUESTS' : 'FS ACTIONS'}</span><strong>{serverActions}</strong></div><div><span>MODEL CALLS</span><strong>{modelCalls}</strong></div><div><span>TERMINATION</span><strong>{snapshot?.termination_reason || '—'}</strong></div></div>
    </main>}

    {error && <div className="error-toast" role="alert">{error}<button onClick={() => setError(null)}>×</button></div>}
    {form && <div className="modal-backdrop" onMouseDown={event => { if (event.target === event.currentTarget) setForm(null) }}><section className="config-modal" role="dialog" aria-modal="true" aria-label="Configure run"><div className="modal-top"><span>NEW {form.experiment} RUN</span><button type="button" aria-label="Close run settings" onClick={() => setForm(null)}>×</button></div><div className="modal-scroll"><h2>{modeNames[form.mode]}</h2><p>{form.mode === 'pilot' ? 'Runs the full PentestGPT Supervisor → Executor loop against the 2A C2 session-v2 decoy. The agent maps the login flow, tests an evidence-backed hypothesis, and continues until its goal or trial cap. The agent never receives the arm, trigger, or canary details. Provider 429 responses are retried after 30, 60, and 90 seconds within the two-hour wall cap.' : form.mode === 'engineering' ? 'Runs the full PentestGPT loop against the selected 2A arm for live observation. This exploratory run does not enter the controlled-study pilot gate.' : form.mode === 'connectivity' ? form.experiment === '2B' ? 'Runs PentestGPT against the B0 generic fixture to verify the imitated SSH path. This is not a study result.' : 'Runs a bounded PentestGPT check against the 2A web decoy.' : 'Exercises the decoy with scripted probes. No autonomous agent or model call starts.'}</p>
      <label>Run mode<select value={form.mode} onChange={event => { const mode = event.target.value as RunMode; setForm({ ...form, mode, arm: form.experiment === '2A' && mode === 'pilot' ? 'C2' : form.experiment === '2B' && mode === 'connectivity' ? 'B0' : form.arm, branching_factor: mode === 'connectivity' ? 4 : form.branching_factor }) }}>{modeChoices[form.experiment].map(mode => <option key={mode} value={mode}>{modeNames[mode]}</option>)}</select></label>
      {modelRun && <label>Model provider<select value={form.provider} onChange={event => setForm({ ...form, provider: event.target.value as Provider })}><option value="ollama">Ollama Cloud</option><option value="zai">Z.AI</option></select></label>}
      {form.experiment === '2A' && form.mode === 'pilot' && <p className="provider-note">Both Ollama Cloud and Z.AI pilots have shown incomplete agent streams. A failed run with this error is an engineering failure, not a defense result.</p>}
      <label>Experiment arm<select value={form.arm} disabled={form.mode === 'pilot' || form.experiment === '2B' && form.mode === 'connectivity'} onChange={event => setForm({ ...form, arm: event.target.value })}>{(form.mode === 'pilot' ? ['C2'] : form.experiment === '2B' && form.mode === 'connectivity' ? ['B0'] : armChoices[form.experiment]).map(arm => <option key={arm}>{arm}</option>)}</select></label>
      {form.experiment === '2B' && <><label>Filesystem seed<input value={form.seed} maxLength={128} onChange={event => setForm({ ...form, seed: event.target.value })} /></label>{form.mode === 'deterministic' && <label>Branching factor<input type="number" min={1} max={15} value={form.branching_factor} onChange={event => setForm({ ...form, branching_factor: Number(event.target.value) })} /></label>}</>}
      <label className="checkbox-row"><input type="checkbox" checked={form.build} onChange={event => setForm({ ...form, build: event.target.checked })} /><span>Rebuild Docker images for this run</span></label>
      <div className="config-summary"><span>AGENT</span><strong>{modelRun ? `PentestGPT · ${selectedAgent?.model || 'glm-5.3'} · ${selectedAgent?.effort || 'max'} effort` : 'No agent'}</strong><span>LIMITS</span><strong>{runLimit}</strong><span>CREDENTIAL</span><strong>{modelRun ? `${form.provider === 'ollama' ? 'Ollama Cloud' : 'Z.AI'} key ${selectedCredential ? 'configured' : 'missing'} in root .env` : 'Not used'}</strong><span>STATUS</span><strong>{form.experiment === '2B' && form.mode === 'connectivity' ? 'Generic fixture · engineering check' : form.mode === 'pilot' ? '2A C2 engineering pilot' : form.mode === 'engineering' ? 'Exploratory · excluded from study gate' : 'Engineering check'}</strong></div></div>
      <div className="modal-actions"><button type="button" className="primary-button launch-button" disabled={launching || modelRun && !selectedCredential || form.experiment === '2B' && (!form.seed || form.mode === 'deterministic' && (form.branching_factor < 1 || form.branching_factor > 15))} onClick={launch}>{launching ? 'Starting…' : 'Run experiment'} <span>→</span></button></div>
    </section></div>}
  </div>
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>)
