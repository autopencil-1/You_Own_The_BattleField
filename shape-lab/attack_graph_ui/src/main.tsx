import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import cytoscape, { type Core, type ElementDefinition } from 'cytoscape'
import './styles.css'

type Evidence = 'crawl_observed' | 'analyst_asserted' | 'analyst_inferred' | 'user_confirmed' | 'bundle_inferred' | 'unknown' | 'candidate'
type ViewMode = 'surface' | 'analyst'
type GraphNode = {
  id: string
  kind: string
  name?: string
  evidence_state: Evidence
  visibility: 'external' | 'internal'
  count?: number
  [key: string]: unknown
}
type GraphEdge = {
  from: string
  to: string
  kind: string
  evidence_state: Evidence
  path_pattern?: string
  [key: string]: unknown
}
type RouteGroup = { id: string; label: string; tier: 'web' | 'api'; count: number }
type Endpoint = {
  id: number
  url: string
  group: string
  status: number
  content_type: string
  tested: boolean
  crawled: boolean
  fold_reason: string | null
  service_id: string
}
type Finding = {
  id: number
  url: string
  group: string
  type: string
  name: string
  severity: string
  verified: boolean
  verify_method: string
}
type Service = {
  ip: string
  service_id: string
  port: string
  product_label: string
  root_status: number
  root_location: string | null
  endpoint_rows: number
}
type ApiRouteCatalogItem = {
  area: string
  routes: string[]
  purpose: string
  auth_note: string
  detail?: string
}
type Principal = { id: string; name: string; role_token: string | null; code_marker?: string; scope: string; evidence_state: Evidence }
type OwnershipRule = { id: string; resource: string; owners: string[]; condition: string; public_read: string; evidence_state: Evidence }
type AccessRule = { id: string; area: string; tier: string; patterns: string[]; observed: string; required_principals: string[]; required_session: boolean; condition: string; enforcement_point: string; evidence_state: Evidence }
type NetworkExposure = { to: string; protocol: string; service: string; port: number }
type EvidenceDoc = { id: string; kind: string; evidence_state: Evidence; text: string; score: number }
type ThreatContext = { model: string; corpus_size: number; documents: EvidenceDoc[]; initial_capabilities: string[]; model_configured: boolean; generation_enabled: boolean }
type CandidateAction = { id: string; name: string; category?: string; kind?: 'known' | 'hypothesis'; entry_point?: string; verification_question?: string; asset_id: string; preconditions: string[]; effects: string[]; evidence_ids: string[]; missing_evidence: string[]; rationale: string; status: string }
type CandidatePath = { action_ids: string[]; end_asset_id: string; status: string; missing_evidence: string[]; gained_capabilities: string[]; hypothesis_ids?: string[] }
type ThreatResult = { id: string; created_at: string; model: string; provider: string; example?: boolean; revalidated_from?: string; planner_version?: number; goal: string; corpus_size: number; retrieved_evidence: EvidenceDoc[]; initial_capabilities: string[]; hypotheses?: CandidateAction[]; hypothesis_stages?: { entry: number; downstream: number; downstream_status: string }; actions: CandidateAction[]; paths: CandidatePath[]; blocked_actions: { action_id: string; unmet_preconditions: string[] }[]; rejected_actions: string[]; gaps: string[]; filteredLegacyPaths?: number }
type Snapshot = {
  scope: string
  path_policy: { target_scope: string; defense_priority: string; attack_steps_required: boolean }
  scan_id: string
  collected_at_kst: string
  metrics: {
    discovered_urls: number
    folded_endpoints: number
    crawl_links: number
    findings: number
    tested_endpoints: number
    crawled_endpoints: number
  }
  nodes: GraphNode[]
  edges: GraphEdge[]
  services: Service[]
  groups: RouteGroup[]
  endpoints: Endpoint[]
  findings: Finding[]
  api_route_catalog: ApiRouteCatalogItem[]
  network_policy: { id: string; source_scope: string; effect: string; note: string; evidence_state: Evidence }
  network_exposures: NetworkExposure[]
  principals: Principal[]
  ownership_rules: OwnershipRule[]
  access_rules: AccessRule[]
  third_party_references: string[]
}

const evidenceNames: Record<Evidence, string> = {
  crawl_observed: 'Crawl observed',
  analyst_asserted: 'Analyst supplied',
  analyst_inferred: 'Analyst inferred',
  user_confirmed: 'User confirmed',
  bundle_inferred: 'Bundle inferred',
  candidate: 'Candidate',
  unknown: 'Unresolved',
}

function sourceClass(evidence: Evidence): 'asm' | 'cmdb' {
  return evidence === 'crawl_observed' ? 'asm' : 'cmdb'
}

function causalPath(path: CandidatePath, actions: CandidateAction[], initial: string[]): boolean {
  const byId = new Map(actions.map(action => [action.id, action]))
  const facts = new Set(initial)
  let previousEffects: Set<string> | null = null
  for (const id of path.action_ids) {
    const action = byId.get(id)
    if (!action || !action.preconditions.every(capability => facts.has(capability))) return false
    if (previousEffects && !action.preconditions.some(capability => previousEffects?.has(capability))) return false
    if (!action.effects.some(capability => !facts.has(capability))) return false
    action.effects.forEach(capability => facts.add(capability))
    previousEffects = new Set(action.effects)
  }
  return path.action_ids.length > 0 && byId.get(path.action_ids.at(-1)!)?.asset_id === path.end_asset_id
}

function displayResult(result: ThreatResult): ThreatResult {
  if ((result.planner_version || 0) >= 3) return result
  const paths = result.paths.filter(path => causalPath(path, result.actions, result.initial_capabilities || []))
  return { ...result, paths, filteredLegacyPaths: result.paths.length - paths.length }
}

const positions: Record<string, { x: number; y: number }> = {
  'network:internet': { x: 75, y: 65 },
  'origin:bugcamp.io:443': { x: 75, y: 335 },
  'ip:43.200.49.16': { x: 225, y: 245 },
  'ip:3.37.226.238': { x: 225, y: 425 },
  'alb:bugcamp-main': { x: 370, y: 335 },
  'tg:bugcamp-web': { x: 525, y: 170 },
  'tg:bugcamp-api': { x: 525, y: 480 },
  'app:bugcamp-nuxt': { x: 685, y: 170 },
  'app:bugcamp-api': { x: 685, y: 480 },
  'surface:web': { x: 850, y: 110 },
  'surface:api': { x: 850, y: 330 },
  'host:static.bugcamp.io': { x: 1015, y: 180 },
  'store-role:relational-db': { x: 850, y: 470 },
  'store-role:session': { x: 1015, y: 425 },
  'store-role:ticket-files': { x: 850, y: 610 },
  'store-role:public-uploads': { x: 1015, y: 570 },
}

const surfacePositions: Record<string, { x: number; y: number }> = {
  'origin:bugcamp.io:443': { x: 100, y: 270 },
  'ip:43.200.49.16': { x: 340, y: 100 },
  'ip:3.37.226.238': { x: 340, y: 440 },
  'surface:web': { x: 620, y: 155 },
  'surface:api': { x: 620, y: 345 },
  'host:static.bugcamp.io': { x: 620, y: 510 },
}

function graphFor(snapshot: Snapshot, view: ViewMode): { nodes: GraphNode[]; edges: GraphEdge[] } {
  if (view === 'surface') {
    const allowed = new Set([
      'origin:bugcamp.io:443', 'ip:43.200.49.16', 'ip:3.37.226.238',
      'surface:web', 'surface:api', 'host:static.bugcamp.io',
    ])
    return {
      nodes: snapshot.nodes.filter(node => allowed.has(node.id)),
      edges: [
        ...snapshot.edges.filter(edge => edge.kind === 'OBSERVED_ON'),
        { from: 'origin:bugcamp.io:443', to: 'surface:web', kind: 'HAS_OBSERVED_ROUTES', evidence_state: 'crawl_observed' },
        { from: 'origin:bugcamp.io:443', to: 'surface:api', kind: 'HAS_OBSERVED_ROUTES', evidence_state: 'crawl_observed' },
        { from: 'surface:web', to: 'host:static.bugcamp.io', kind: 'REFERENCES_HOST', evidence_state: snapshot.nodes.find(node => node.id === 'host:static.bugcamp.io')?.evidence_state || 'bundle_inferred' },
      ],
    }
  }
  return { nodes: snapshot.nodes, edges: snapshot.edges }
}

function labelFor(node: GraphNode): string {
  if (node.id === 'surface:web') return `Web routes\n${node.count} endpoints`
  if (node.id === 'surface:api') return `API routes\n${node.count} endpoints`
  if (node.id === 'alb:bugcamp-main') return 'AWS ALB'
  if (node.id === 'host:static.bugcamp.io') return 'static.bugcamp.io\nunscanned'
  if (node.id === 'network:internet') return 'Any IP\nnetwork source'
  if (node.kind === 'LogicalStoreRole') return `${node.name}\n${node.technology || 'identity unknown'}`
  if (node.kind === 'IPAddress') return String(node.address)
  return node.name || node.id
}

function toElements(nodes: GraphNode[], edges: GraphEdge[], view: ViewMode): ElementDefinition[] {
  const layout = view === 'surface' ? surfacePositions : positions
  return [
    ...nodes.map(node => ({
      data: { id: node.id, label: labelFor(node), sourceClass: sourceClass(node.evidence_state), kind: node.kind },
      position: layout[node.id] || { x: 500, y: 280 },
    })),
    ...edges.map((edge, index) => ({
      data: { id: `edge:${index}`, source: edge.from, target: edge.to, kind: edge.kind,
        sourceClass: sourceClass(edge.evidence_state), label: edge.kind === 'ROUTES_TO' ? edge.path_pattern : edge.kind === 'CAN_REACH' ? `${edge.service}:${edge.port}` : '' },
    })),
  ]
}

function routeElements(path: CandidatePath | null, actions: CandidateAction[]): ElementDefinition[] {
  if (!path) return []
  const byId = new Map(actions.map(action => [action.id, action]))
  const routeActions = path.action_ids.map(id => byId.get(id)).filter((action): action is CandidateAction => Boolean(action))
  return [
    ...routeActions.map((action, index) => ({
      data: { id: `route:${index}`, kind: 'CandidateAction', actionId: action.id, routeKind: action.kind || 'hypothesis',
        label: `${action.kind === 'known' ? 'KNOWN ROUTE' : 'HYPOTHESIS'} ${index + 1}\n${action.name}` },
      position: { x: 180 + index * 210, y: 790 },
    })),
    ...routeActions.map((action, index) => ({
      data: { id: `route-target:${index}`, source: `route:${index}`, target: action.asset_id,
        kind: 'ROUTE_TARGET', label: '' },
    })),
    ...routeActions.slice(1).map((_, index) => ({
      data: { id: `route-sequence:${index}`, source: `route:${index}`, target: `route:${index + 1}`,
        kind: 'ROUTE_SEQUENCE', label: '' },
    })),
  ]
}

function GraphCanvas({ snapshot, view, selected, onSelect, routePath, routeActions, selectedRouteActionId, onSelectRouteAction }: {
  snapshot: Snapshot
  view: ViewMode
  selected: string
  onSelect: (id: string) => void
  routePath: CandidatePath | null
  routeActions: CandidateAction[]
  selectedRouteActionId: string | null
  onSelectRouteAction: (id: string) => void
}) {
  const container = useRef<HTMLDivElement>(null)
  const graph = useRef<Core | null>(null)
  const data = useMemo(() => graphFor(snapshot, view), [snapshot, view])

  useEffect(() => {
    if (!container.current) return
    const cy = cytoscape({
      container: container.current,
      elements: [...toElements(data.nodes, data.edges, view), ...(view === 'analyst' ? routeElements(routePath, routeActions) : [])],
      layout: { name: 'preset' },
      minZoom: 0.35,
      maxZoom: 2.2,
      wheelSensitivity: 0.18,
      boxSelectionEnabled: false,
      autoungrabify: true,
      style: [
        { selector: 'node', style: {
          'shape': 'round-rectangle', 'width': 126, 'height': 58,
          'background-color': '#162638', 'border-color': '#47718a', 'border-width': 1.5,
          'label': 'data(label)', 'color': '#edf4f8', 'font-size': 12, 'font-family': 'Inter, system-ui, sans-serif',
          'text-wrap': 'wrap', 'text-max-width': '112px', 'text-valign': 'center', 'text-halign': 'center',
          'text-margin-y': 0,
        } },
        { selector: 'node[sourceClass = "asm"]', style: { 'background-color': '#123b38', 'border-color': '#49bca6' } },
        { selector: 'node[sourceClass = "cmdb"]', style: { 'background-color': '#20334f', 'border-color': '#79a9ea' } },
        { selector: 'node[kind = "WebOrigin"]', style: { 'width': 150, 'height': 68, 'font-weight': 600 } },
        { selector: 'node[kind = "RouteSurface"]', style: { 'width': 144, 'height': 66 } },
        { selector: 'node[kind = "LogicalStoreRole"]', style: { 'width': 142, 'height': 66 } },
        { selector: 'node[kind = "CandidateAction"]', style: {
          'shape': 'rectangle', 'width': 174, 'height': 76,
          'background-opacity': 0, 'border-color': '#f06b70', 'border-width': 2.5,
          'color': '#ffd6d7', 'font-size': 11, 'font-weight': 600,
          'text-max-width': '160px',
        } },
        { selector: 'node[routeKind = "known"]', style: { 'border-color': '#76b8d7', 'color': '#d4efff' } },
        { selector: 'node.is-route-selected', style: { 'border-color': '#ffb0b2', 'border-width': 4 } },
        { selector: 'node.is-selected', style: { 'border-width': 3, 'border-color': '#f6f2c9' } },
        { selector: 'edge', style: {
          'width': 1.8, 'line-color': '#5e7484', 'target-arrow-color': '#5e7484',
          'target-arrow-shape': 'triangle', 'curve-style': 'bezier', 'arrow-scale': 0.7,
          'label': 'data(label)', 'color': '#a9bbc8', 'font-size': 10,
          'text-background-color': '#0e1b28', 'text-background-opacity': 0.95,
          'text-background-padding': '3px',
        } },
        { selector: 'edge[sourceClass = "asm"]', style: { 'line-color': '#4d9b90', 'target-arrow-color': '#4d9b90' } },
        { selector: 'edge[sourceClass = "cmdb"]', style: { 'line-color': '#6886b4', 'target-arrow-color': '#6886b4' } },
        { selector: 'edge[kind = "CAN_REACH"]', style: { 'line-style': 'dashed', 'width': 1.2, 'opacity': 0.55 } },
        { selector: 'edge[kind = "ROUTE_TARGET"]', style: {
          'line-style': 'dashed', 'width': 2, 'line-color': '#e5656b', 'target-arrow-color': '#e5656b',
          'opacity': 0.9, 'curve-style': 'bezier',
        } },
        { selector: 'edge[kind = "ROUTE_SEQUENCE"]', style: {
          'width': 2.5, 'line-color': '#f06b70', 'target-arrow-color': '#f06b70',
          'target-arrow-shape': 'triangle', 'curve-style': 'straight',
        } },
      ],
    })
    graph.current = cy
    cy.on('tap', 'node', event => {
      if (event.target.data('kind') === 'CandidateAction') onSelectRouteAction(event.target.data('actionId'))
      else onSelect(event.target.id())
    })
    cy.fit(undefined, 32)
    const observer = new ResizeObserver(() => { cy.resize(); cy.fit(undefined, 32) })
    observer.observe(container.current)
    return () => { observer.disconnect(); cy.destroy(); graph.current = null }
  }, [data, onSelect, onSelectRouteAction, routePath, routeActions, view])

  useEffect(() => {
    const cy = graph.current
    if (!cy) return
    cy.nodes().removeClass('is-selected')
    cy.nodes().removeClass('is-route-selected')
    cy.getElementById(selected).addClass('is-selected')
    const routeIndex = routePath?.action_ids.indexOf(selectedRouteActionId || '') ?? -1
    if (routeIndex >= 0) cy.getElementById(`route:${routeIndex}`).addClass('is-route-selected')
  }, [selected, selectedRouteActionId, routePath, view])

  const selectedAction = routeActions.find(action => action.id === selectedRouteActionId)

  return <>
    <div className="graph-toolbar">
      <span className="graph-hint">Select an asset or a red route step to inspect it.</span>
      <button type="button" className="button-quiet" onClick={() => graph.current?.fit(undefined, 32)}>Fit graph</button>
    </div>
    <div className={`graph-canvas ${view === 'analyst' && routePath ? 'with-route' : ''}`} ref={container} role="img" aria-label={`${view === 'surface' ? 'External surface' : 'Analyst topology'} graph of bugcamp.io`} />
    {view === 'analyst' && routePath && <div className="graph-route-detail">
      <div className="route-detail-heading"><span className="route-outline-key" /> <strong>Selected route step</strong><span>{selectedAction?.kind === 'known' ? 'Known routing or access' : 'Unverified weakness'}</span></div>
      {selectedAction ? <><h3>{selectedAction.name}</h3><p>{selectedAction.rationale || 'No description supplied by the model.'}</p>
        <dl><div><dt>Asset</dt><dd>{snapshot.nodes.find(node => node.id === selectedAction.asset_id)?.name || selectedAction.asset_id}</dd></div>
          {selectedAction.entry_point && <div><dt>Entry</dt><dd>{selectedAction.entry_point}</dd></div>}
          <div><dt>Requires</dt><dd>{selectedAction.preconditions.join(' + ')}</dd></div>
          <div><dt>Gains</dt><dd>{selectedAction.effects.join(', ')}</dd></div>
          <div><dt>Evidence</dt><dd>{selectedAction.evidence_ids.join(', ')}</dd></div></dl>
        {selectedAction.verification_question && <p><b>Check:</b> {selectedAction.verification_question}</p>}
        {selectedAction.missing_evidence.length > 0 && <p className="route-detail-gap"><b>Still needed:</b> {selectedAction.missing_evidence.join(' · ')}</p>}
      </> : <p>Select a red outline box to read its description and evidence gaps.</p>}
    </div>}
  </>
}

function Metric({ value, label }: { value: string; label: string }) {
  return <div className="metric"><strong>{value}</strong><span>{label}</span></div>
}

function ThreatModelStudio({ snapshot, result, onResult, activePathIndex, onPathSelect }: {
  snapshot: Snapshot
  result: ThreatResult | null
  onResult: (result: ThreatResult) => void
  activePathIndex: number | null
  onPathSelect: (index: number) => void
}) {
  const [goal, setGoal] = useState('Find plausible routes from any public IP to assets in this Bugcamp snapshot')
  const [target, setTarget] = useState('')
  const [context, setContext] = useState<ThreatContext | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [generationEnabled, setGenerationEnabled] = useState(false)

  useEffect(() => {
    fetch(`${import.meta.env.BASE_URL}api/threat-model/latest`, { cache: 'no-store' })
      .then(response => response.ok ? response.json() : null)
      .then(data => { if (data?.id) onResult(data as ThreatResult) })
      .catch(() => {})
    fetch(`${import.meta.env.BASE_URL}api/threat-model/status`, { cache: 'no-store' })
      .then(response => response.ok ? response.json() : null)
      .then(data => setGenerationEnabled(Boolean(data?.generation_enabled)))
      .catch(() => {})
  }, [onResult])

  async function run(mode: 'context' | 'generate') {
    setBusy(true)
    setError('')
    try {
      const response = await fetch(`${import.meta.env.BASE_URL}api/threat-model/${mode}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ goal, target_asset_id: target || null }),
      })
      const data = await response.json()
      if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`)
      if (mode === 'context') { setContext(data as ThreatContext); setGenerationEnabled(Boolean(data.generation_enabled)) }
      else { onResult(data as ThreatResult); setContext(null) }
    } catch (cause) { setError(String(cause)) }
    finally { setBusy(false) }
  }

  async function previewExample() {
    setBusy(true)
    setError('')
    try {
      const response = await fetch(`${import.meta.env.BASE_URL}api/threat-model/example`, { cache: 'no-store' })
      const data = await response.json()
      if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`)
      onResult(data as ThreatResult)
      setContext(null)
    } catch (cause) { setError(String(cause)) }
    finally { setBusy(false) }
  }

  return <section className="threat-studio" aria-label="LLM threat model">
    <div className="threat-head"><div><p className="eyebrow">EVIDENCE → HYPOTHESES → ROUTES</p><h2>Threat model generator</h2>
      <p>GLM-5.3 proposes testable weakness hypotheses. A local planner combines them with known routing and checks each prerequisite.</p></div>
      <span className="model-badge">GLM-5.3 on Ollama Cloud</span></div>
    <div className="threat-controls">
      <label>Modeling goal<input value={goal} maxLength={500} onChange={event => setGoal(event.target.value)} /></label>
      <label>Destination asset<select value={target} onChange={event => setTarget(event.target.value)}>
        <option value="">All assets</option>{snapshot.nodes.filter(node => node.id !== 'network:internet').map(node =>
          <option key={node.id} value={node.id}>{node.name || node.id}</option>)}
      </select></label>
      <div className="threat-buttons"><button type="button" disabled={busy || goal.length < 8} onClick={() => run('context')}>Inspect retrieval</button>
        <button type="button" disabled={busy} onClick={previewExample}>Preview local example</button>
        <button type="button" className="primary" disabled={busy || goal.length < 8 || !generationEnabled} onClick={() => run('generate')}>{busy ? 'Working…' : 'Generate hypotheses and routes'}</button></div>
    </div>
    {!generationEnabled && <p className="threat-pending">Live generation is disabled until the Ollama credential and evidence-export gate are configured. Retrieval and local validation remain available.</p>}
    {generationEnabled && <p className="threat-pending">Generating sends the selected crawl and CMDB evidence records to Ollama Cloud.</p>}
    {error && <p className="threat-error" role="alert">{error}</p>}
    {context && <div className="threat-context"><h3>Retrieved context</h3>
      <p>{context.documents.length} of {context.corpus_size} evidence records selected · {context.initial_capabilities.length} starting capabilities · generation {context.generation_enabled ? 'enabled' : 'disabled'}</p>
      <div className="evidence-chips">{context.documents.map(doc => <span key={doc.id} title={doc.text}>{doc.id} <small>{evidenceNames[doc.evidence_state]}</small></span>)}</div>
      <details><summary>Starting capabilities</summary><ul>{context.initial_capabilities.map(capability => <li key={capability}>{capability}</li>)}</ul></details>
    </div>}
    {result && <div className="threat-result"><div className="threat-result-head"><h3>Vulnerability hypotheses</h3><span>{result.hypotheses?.length || 0} hypotheses · {result.paths.length} routes · {result.model}{result.example ? '' : ' on Ollama Cloud'}</span></div>
      {!result.example && (result.planner_version || 0) < 3 && <p className="threat-example">This saved run uses the older action-first planner. Select “Preview local example” to inspect the new hypothesis-first graph.</p>}
      {result.example && <p className="threat-example">Offline illustration from the supplied architecture. These ten weaknesses and eighteen chains are test scenarios, not model output or verified findings. This preview is not saved.</p>}
      {result.revalidated_from && <p className="small-note">Locally revalidated from saved GLM run {result.revalidated_from}; no new model call.</p>}
      {result.hypothesis_stages && !result.example && <p className="small-note">Entry hypotheses: {result.hypothesis_stages.entry} · downstream hypotheses: {result.hypothesis_stages.downstream} · follow-up: {result.hypothesis_stages.downstream_status}</p>}
      <p className="threat-caveat">These are conditional threat-model routes. A valid chain of prerequisites does not verify a vulnerability or a permission.</p>
      {result.hypotheses && <div className="hypothesis-list">{result.hypotheses.map(hypothesis => <details key={hypothesis.id}>
        <summary><strong>{hypothesis.name}</strong><span>{hypothesis.category}</span><em>{hypothesis.asset_id}</em></summary>
        <p>{hypothesis.rationale}</p><p><b>Entry:</b> {hypothesis.entry_point || 'Unspecified'} · <b>Requires:</b> {hypothesis.preconditions.join(' + ')} · <b>Could gain:</b> {hypothesis.effects.join(', ')}</p>
        {hypothesis.verification_question && <p><b>Check:</b> {hypothesis.verification_question}</p>}
        <p><b>Missing evidence:</b> {hypothesis.missing_evidence.join(' · ')}</p>
      </details>)}</div>}
      <h3>Chained attack routes</h3>
      {Boolean(result.filteredLegacyPaths) && <p className="small-note">{result.filteredLegacyPaths} older noncausal path combinations are hidden from the asset graph.</p>}
      {result.paths.length === 0 && <p>No route satisfied the modeled prerequisites. Review the evidence gaps below.</p>}
      <div className="candidate-paths">{result.paths.map((path, index) => <details key={`${result.id}:${index}`} className={activePathIndex === index ? 'is-overlaid' : ''} open={activePathIndex === index}>
        <summary onClick={() => onPathSelect(index)}><strong>Route {index + 1}</strong><span>→ {snapshot.nodes.find(node => node.id === path.end_asset_id)?.name || path.end_asset_id}</span><em>{activePathIndex === index ? 'On graph' : path.status === 'conditional' ? 'Conditional' : 'Public access'}</em></summary>
        <div className="path-steps">{path.action_ids.map((id, position) => {
          const action = result.actions.find(item => item.id === id)
          return action && <div className="path-step" key={id}><b>{position + 1}. {action.name}</b><span>{action.kind === 'known' ? 'Known route' : 'Hypothesis'} · {action.asset_id}</span>
            <p>{action.rationale}</p><small>Requires {action.preconditions.join(' + ')} → gains {action.effects.join(', ')}</small>
            <small>Evidence: {action.evidence_ids.join(', ')}</small></div>
        })}</div>
        {path.missing_evidence.length > 0 && <div className="route-gaps"><b>To verify this route</b><ul>{path.missing_evidence.map(gap => <li key={gap}>{gap}</li>)}</ul></div>}
      </details>)}</div>
      {(result.blocked_actions.length > 0 || result.rejected_actions.length > 0 || result.gaps.length > 0) && <details className="model-gaps"><summary>Unreachable actions and evidence gaps</summary>
        <ul>{result.blocked_actions.map(item => <li key={item.action_id}>{item.action_id}: missing {item.unmet_preconditions.join(', ')}</li>)}
          {result.rejected_actions.map((item, index) => <li key={`reject:${index}`}>{item}</li>)}
          {result.gaps.map((item, index) => <li key={`gap:${index}`}>{item}</li>)}</ul></details>}
      <p className="small-note">{result.example ? 'Unsaved local preview' : `Saved run ${result.id}`} · {new Date(result.created_at).toLocaleString()}</p>
    </div>}
  </section>
}

function App() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null)
  const [loadError, setLoadError] = useState('')
  const [view, setView] = useState<ViewMode>('analyst')
  const [selected, setSelected] = useState('origin:bugcamp.io:443')
  const [groupId, setGroupId] = useState('ticket-pages')
  const [query, setQuery] = useState('')
  const [activeEndpoint, setActiveEndpoint] = useState<Endpoint | null>(null)
  const [threatResult, setThreatResult] = useState<ThreatResult | null>(null)
  const [activePathIndex, setActivePathIndex] = useState<number | null>(null)
  const [selectedRouteActionId, setSelectedRouteActionId] = useState<string | null>(null)

  useEffect(() => {
    fetch(`${import.meta.env.BASE_URL}api/graph/overview`, { cache: 'no-store' })
      .then(response => { if (!response.ok) throw new Error(`Snapshot request failed: ${response.status}`); return response.json() })
      .then(data => setSnapshot(data as Snapshot))
      .catch(error => setLoadError(String(error)))
  }, [])

  const onSelect = useCallback((id: string) => { setSelected(id); setActiveEndpoint(null) }, [])
  const onThreatResult = useCallback((next: ThreatResult) => {
    const checked = displayResult(next)
    setThreatResult(checked)
    setActivePathIndex(checked.paths.length ? 0 : null)
    setSelectedRouteActionId(checked.paths[0]?.action_ids[0] || null)
  }, [])
  const onPathSelect = useCallback((index: number) => {
    const path = threatResult?.paths[index]
    if (!path) return
    setActivePathIndex(index)
    setSelectedRouteActionId(path.action_ids[0] || null)
    setView('analyst')
  }, [threatResult])
  const onSelectRouteAction = useCallback((id: string) => setSelectedRouteActionId(id), [])
  const activePath = activePathIndex === null ? null : threatResult?.paths[activePathIndex] || null
  const activeActions = useMemo(() => activePath?.action_ids.map(id => threatResult?.actions.find(action => action.id === id))
    .filter((action): action is CandidateAction => Boolean(action)) || [], [activePath, threatResult])
  const data = useMemo(() => snapshot ? graphFor(snapshot, view) : null, [snapshot, view])
  const selectedNode = data?.nodes.find(node => node.id === selected) || null
  const service = snapshot?.services.find(row => `ip:${row.ip}` === selected)
  const routeTier = selected === 'surface:web' ? 'web' : selected === 'surface:api' ? 'api' : null
  const availableGroups = snapshot?.groups.filter(group => group.tier === routeTier) || []
  const currentGroup = availableGroups.find(group => group.id === groupId) || availableGroups[0]
  const endpointMatches = snapshot?.endpoints.filter(endpoint =>
    (!routeTier || snapshot.groups.some(group => group.id === endpoint.group && group.tier === routeTier))
    && (query ? endpoint.url.toLowerCase().includes(query.toLowerCase()) : endpoint.group === currentGroup?.id)
  ) || []
  const selectedFindings = snapshot?.findings.filter(finding =>
    routeTier ? snapshot.groups.some(group => group.id === finding.group && group.tier === routeTier) : false
  ) || []

  const switchView = (next: ViewMode) => {
    setView(next)
    setSelected('origin:bugcamp.io:443')
    setActiveEndpoint(null)
    setQuery('')
  }

  if (loadError) return <main className="load-state" role="alert">Could not load the graph snapshot. {loadError}</main>
  if (!snapshot) return <main className="load-state">Loading graph snapshot…</main>

  return <div className="app-shell">
    <header className="topbar">
      <div className="brand-mark" aria-hidden="true">B</div>
      <div className="brand-copy"><strong>BUGCAMP</strong><span>ATTACK SURFACE STUDIO</span></div>
      <div className="topbar-right"><span className="live-dot" /> Local benchmark workspace</div>
    </header>

    <main className="content">
      <div className="page-heading">
        <div><p className="eyebrow">GRAPH WORKSPACE / BUGCAMP.IO:443</p><h1>Asset graph</h1>
          <p className="subtitle">ASM crawl and CMDB topology · collected {snapshot.collected_at_kst} KST</p></div>
        <div className="heading-status"><span className="status-pip" /> Conditional route analysis <small>Target scope: {snapshot.path_policy.target_scope === 'all_assets' ? 'all assets' : snapshot.path_policy.target_scope} · evidence gaps retained</small></div>
      </div>

      <div className="metrics" aria-label="Crawl totals">
        <Metric value={snapshot.metrics.discovered_urls.toLocaleString()} label="discovered URLs" />
        <Metric value={snapshot.metrics.folded_endpoints.toLocaleString()} label="stored endpoints" />
        <Metric value={snapshot.metrics.crawl_links.toLocaleString()} label="discovery links" />
        <Metric value={String(snapshot.metrics.findings)} label="pattern findings" />
      </div>

      <div className="workspace-head">
        <div className="view-switch" role="group" aria-label="Graph view">
          <button type="button" className={view === 'analyst' ? 'active' : ''} aria-pressed={view === 'analyst'} onClick={() => switchView('analyst')}>Analyst topology</button>
          <button type="button" className={view === 'surface' ? 'active' : ''} aria-pressed={view === 'surface'} onClick={() => switchView('surface')}>External surface</button>
        </div>
        {threatResult?.paths.length ? <label className="route-select">Attack route
          <select value={activePathIndex ?? 0} onChange={event => onPathSelect(Number(event.target.value))}>
            {threatResult.paths.map((path, index) => <option key={`${threatResult.id}:${index}`} value={index}>Route {index + 1} · {path.hypothesis_ids?.length || 1} hypotheses · {snapshot.nodes.find(node => node.id === path.end_asset_id)?.name || path.end_asset_id}</option>)}
          </select></label> : null}
        <div className="legend" aria-label="Evidence legend">
          <span><i className="key asm" /> ASM · crawl observed</span>
          <span><i className="key cmdb" /> CMDB · other asset data</span>
          {view === 'analyst' && activePath && <span><i className="key route" /> Candidate route</span>}
        </div>
      </div>

      <div className="workspace-grid">
        <section className="graph-section" aria-label="Graph canvas">
          <GraphCanvas snapshot={snapshot} view={view} selected={selected} onSelect={onSelect}
            routePath={activePath} routeActions={activeActions} selectedRouteActionId={selectedRouteActionId}
            onSelectRouteAction={onSelectRouteAction} />
          <div className="canvas-foot"><span>{view === 'analyst' ? 'Red outlines are vulnerability hypotheses; blue outlines are known route or access steps. Dashed network links do not grant application access.' : 'The external surface shows crawl-facing assets; candidate routes appear in analyst topology.'}</span><span>Scroll to zoom · drag to pan</span></div>
        </section>

        <aside className="inspector" aria-label="Graph inspector">
          <div className="inspector-head"><span>INSPECTOR</span><label className="node-select-label">Select node
            <select value={selected} onChange={event => onSelect(event.target.value)}>
              {data?.nodes.map(node => <option key={node.id} value={node.id}>{labelFor(node).replace('\n', ' · ')}</option>)}
            </select>
          </label></div>
          {selectedNode && <div className="node-summary">
            <span className={`evidence-pill ${sourceClass(selectedNode.evidence_state)}`}>{sourceClass(selectedNode.evidence_state).toUpperCase()}</span>
            <h2>{selectedNode.name || (selectedNode.kind === 'IPAddress' ? String(selectedNode.address) : selectedNode.id)}</h2>
            <p>{descriptionFor(selectedNode, service)}</p>
            <dl className="facts">
              <div><dt>Source</dt><dd>{sourceClass(selectedNode.evidence_state) === 'asm' ? 'ASM crawl' : 'CMDB'}</dd></div>
              <div><dt>Type</dt><dd>{selectedNode.kind.replaceAll(/([a-z])([A-Z])/g, '$1 $2')}</dd></div>
              <div><dt>Visibility</dt><dd>{selectedNode.visibility === 'external' ? 'External surface' : 'Internal analyst view'}</dd></div>
              {selectedNode.asset_id != null && <div><dt>Synthetic ID</dt><dd>{String(selectedNode.asset_id)}</dd></div>}
              {selectedNode.published_port != null && <div><dt>Published port</dt><dd>HTTPS :{String(selectedNode.published_port)}</dd></div>}
              {selectedNode.externally_reachable_via != null && <div><dt>Public route</dt><dd>Via bugcamp.io:443 ALB</dd></div>}
              {service && <><div><dt>Root response</dt><dd>{service.root_status} → {service.root_location}</dd></div>
                <div><dt>Endpoint rows</dt><dd>{service.endpoint_rows} linked to this service</dd></div></>}
              {selectedNode.kind === 'TargetGroup' && <><div><dt>Target type</dt><dd>{selectedNode.target_type ? String(selectedNode.target_type) : `Pending · ${(selectedNode.target_type_candidates as string[]).join(' / ')}`}</dd></div>
                <div><dt>Protocol / port</dt><dd>{String(selectedNode.protocol || 'Unknown')} :{selectedNode.port != null ? String(selectedNode.port) : `pending (${(selectedNode.port_candidates as number[]).join(' / ')})`}</dd></div>
                <div><dt>Health check</dt><dd>{String(selectedNode.health_check_path || 'Unknown')}</dd></div></>}
              {selectedNode.kind === 'ApplicationLoadBalancer' && <div><dt>Listener</dt><dd>HTTPS :443 · CMDB</dd></div>}
              {selectedNode.kind === 'RouteSurface' && <div><dt>Endpoints</dt><dd>{selectedNode.count}</dd></div>}
              {selectedNode.kind === 'LogicalStoreRole' && <><div><dt>Connection</dt><dd>Express API → store role · CMDB</dd></div>
                <div><dt>Synthetic ID</dt><dd>{String(selectedNode.asset_identity || 'Pending resource ID')}</dd></div>
                <div><dt>Technology</dt><dd>{selectedNode.technology ? String(selectedNode.technology) : `Pending · ${(selectedNode.technology_candidates as string[]).join(' / ')}`}</dd></div>
                {selectedNode.deployment != null && <div><dt>Deployment</dt><dd>{String(selectedNode.deployment)}</dd></div>}
                {(selectedNode.deployment_candidates as string[]).length > 0 && <div><dt>Deployment</dt><dd>Pending · {(selectedNode.deployment_candidates as string[]).join(' / ')}</dd></div>}
                {selectedNode.database_instance_ref != null && <div><dt>Database instance</dt><dd>Same RDS MySQL instance</dd></div>}
                <div><dt>Port</dt><dd>{selectedNode.port != null ? String(selectedNode.port) : (selectedNode.port_candidates as number[]).join(' / ') || 'Local or unknown'}</dd></div></>}
              {selected === 'host:static.bugcamp.io' && <><div><dt>Served by</dt><dd>{String(selectedNode.backing_service)}</dd></div><div><dt>Origin</dt><dd>{String(selectedNode.origin_service)}</dd></div></>}
            </dl>
          </div>}

          {selected === 'app:bugcamp-nuxt' && <div className="inspector-block"><h3>Bundle-derived technology</h3>
            <ul className="technology-list">{Object.entries(selectedNode?.library_versions_from_bundle as Record<string, string>).map(([name, version]) =>
              <li key={name}><span>{name}</span><strong>{version}</strong></li>)}</ul>
            <p className="small-note">The analyst reports that ticket API JSON is embedded in server-rendered pages.</p>
            <h3 className="subheading">Referenced integrations</h3>
            <p className="small-note">{snapshot.third_party_references.join(' · ')}</p>
          </div>}

          {selected === 'app:bugcamp-api' && <div className="inspector-block"><h3>Asserted outbound store connections</h3>
            <ul className="dependency-list">{snapshot.nodes.filter(node => node.kind === 'LogicalStoreRole').map(node =>
              <li key={node.id}><strong>{node.name}</strong><span>{String(node.status)}</span></li>)}</ul>
            <h3 className="subheading">Middleware</h3>
            <p className="small-note">{(selectedNode?.middleware as string[]).join(' · ')}</p>
          </div>}

          {routeTier && <div className="inspector-block route-explorer">
            <h3>Route families</h3>
            <div className="group-list">{availableGroups.map(group => <button key={group.id} type="button"
              className={currentGroup?.id === group.id ? 'is-current' : ''}
              onClick={() => { setGroupId(group.id); setQuery(''); setActiveEndpoint(null) }}>
              <span>{group.label}</span><strong>{group.count}</strong></button>)}</div>
            <label className="search-label">Find an endpoint
              <input value={query} onChange={event => { setQuery(event.target.value); setActiveEndpoint(null) }} placeholder="Search URL path" /></label>
            <div className="endpoint-count">{query ? `${endpointMatches.length} match${endpointMatches.length === 1 ? '' : 'es'}` : `${currentGroup?.label || ''} · ${endpointMatches.length} endpoints`}</div>
            <div className="endpoint-list">{endpointMatches.slice(0, 12).map(endpoint =>
              <button key={endpoint.id} type="button" className={activeEndpoint?.id === endpoint.id ? 'is-current' : ''}
                onClick={() => setActiveEndpoint(endpoint)}>
                <span className="url-text">{new URL(endpoint.url).pathname}{new URL(endpoint.url).search}</span>
                <span className={`http-status ${endpoint.status >= 400 ? 'error' : ''}`}>{endpoint.status}</span>
              </button>)}</div>
            {endpointMatches.length > 12 && <p className="small-note">Showing first 12. Search to narrow the list.</p>}
            {activeEndpoint && <div className="endpoint-detail"><strong>Endpoint observation</strong>
              <div className="url-full">{activeEndpoint.url}</div>
              <span>{activeEndpoint.tested ? 'Tested' : 'Not tested'} · {activeEndpoint.crawled ? 'Crawled' : 'Not crawled'} · {activeEndpoint.content_type || 'type unknown'}</span>
              {activeEndpoint.fold_reason && <span>Folded: {activeEndpoint.fold_reason}</span>}
            </div>}
            {selectedFindings.length > 0 && <div className="finding-summary"><strong>{selectedFindings.length} recorded finding{selectedFindings.length === 1 ? '' : 's'}</strong><span>Offline pattern matches; inspect evidence before treating as exploitable.</span></div>}
          </div>}

          {selected === 'surface:api' && <div className="inspector-block"><h3>Analyst route catalog</h3>
            <p className="small-note catalog-intro">These route templates came from bundle review and analyst observations. Most were not individually tested in this crawl.</p>
            <div className="catalog-list">{snapshot.api_route_catalog.map(area => <details key={area.area}>
              <summary><span>{area.area}</span><strong>{area.routes.length}</strong></summary>
              <p>{area.purpose}</p>
              <ul>{area.routes.map(route => <li key={route}>{route}</li>)}</ul>
              <p><b>Access:</b> {area.auth_note}</p>
              {area.detail && <p>{area.detail}</p>}
            </details>)}</div>
          </div>}

          <div className="inspector-block"><h3>Network policy</h3>
            <p className="small-note policy-intro">Any source IP can reach the modeled service ports. This user-supplied network rule does not grant a session or object permission.</p>
            <div className="catalog-list">{snapshot.network_exposures.map(exposure => <details key={exposure.to}>
              <summary><span>{snapshot.nodes.find(node => node.id === exposure.to)?.name || exposure.to}</span><strong>{exposure.service} :{exposure.port}</strong></summary>
              <p>{exposure.to}</p>
            </details>)}</div>
          </div>

          <div className="inspector-block"><h3>Principals and ownership</h3>
            <div className="catalog-list">{snapshot.principals.map(principal => <details key={principal.id}>
              <summary><span>{principal.name}</span><strong>{principal.role_token || 'no role token'}</strong></summary>
              <p>{principal.scope}</p>
              {principal.code_marker && <p><b>Code marker:</b> {principal.code_marker}</p>}
              <p><b>Evidence:</b> {evidenceNames[principal.evidence_state]}</p>
            </details>)}</div>
            <h3 className="subheading">Object ownership</h3>
            <div className="catalog-list">{snapshot.ownership_rules.map(rule => <details key={rule.id}>
              <summary><span>{rule.resource}</span><strong>{rule.owners.length} roles</strong></summary>
              <p><b>Owners:</b> {rule.owners.join(' · ')}</p>
              <p>{rule.condition}</p>
              <p><b>Public read:</b> {rule.public_read}</p>
              <p><b>Evidence:</b> {evidenceNames[rule.evidence_state]}</p>
            </details>)}</div>
          </div>

          <div className="inspector-block"><h3>Access rules</h3>
            <p className="small-note policy-intro">Observed responses and inferred enforcement are recorded separately. An unspecified route has unknown access, not an automatic allow.</p>
            <div className="catalog-list">{snapshot.access_rules.map(rule => <details key={rule.id}>
              <summary><span>{rule.area}</span><strong>{rule.required_principals.length ? rule.required_principals.join('/') : rule.required_session ? 'session' : 'public'}</strong></summary>
              <ul>{rule.patterns.map(pattern => <li key={pattern}>{pattern}</li>)}</ul>
              <p><b>Observed:</b> {rule.observed}</p>
              <p><b>Condition:</b> {rule.condition}</p>
              <p><b>Check:</b> {rule.enforcement_point} · {evidenceNames[rule.evidence_state]}</p>
            </details>)}</div>
          </div>

          <div className="inspector-block readiness"><h3>Needed for attack paths</h3>
            <ul><li>Exploit prerequisites and gained capabilities</li><li>Evidence that inferred authorization checks are enforced</li><li>Store permissions beyond network reachability</li></ul>
          </div>
        </aside>
      </div>
      <ThreatModelStudio snapshot={snapshot} result={threatResult} onResult={onThreatResult}
        activePathIndex={activePathIndex} onPathSelect={onPathSelect} />
      <footer>Source: PostgreSQL crawl dump and analyst-supplied provisional CMDB · scan {snapshot.scan_id}</footer>
    </main>
  </div>
}

function descriptionFor(node: GraphNode, service?: Service): string {
  if (service) return service.endpoint_rows ? 'This IP has the crawl-linked service record. The nginx label is a fingerprint, not an internal host identity.' : 'A service response was recorded on this IP. No endpoint rows were linked to its service ID.'
  switch (node.id) {
    case 'origin:bugcamp.io:443': return 'Public HTTPS origin and the entry point for the crawl. Internal hops are shown only in analyst topology.'
    case 'alb:bugcamp-main': return 'CMDB: one ALB serving both observed IPs. The sanitized listener sketch is not a configuration export.'
    case 'tg:bugcamp-web': return 'CMDB: default target group for Nuxt SSR, with IP targets on HTTP :80 and the / health check.'
    case 'tg:bugcamp-api': return 'CMDB: target group for /api/* routing, with IP targets on HTTP :3000 and the /api health check.'
    case 'app:bugcamp-nuxt': return 'CMDB: server-rendered web tier. Its public /api call forwards the client Cookie, and ticket JSON is embedded in rendered HTML.'
    case 'app:bugcamp-api': return 'CMDB: Express API tier with outbound database, session, ticket-file, and public-upload connections. The backend target ID is synthetic.'
    case 'network:internet': return 'CMDB: any IP can reach each modeled service port. Application access and object ownership remain separate checks.'
    case 'surface:web': return 'Stored web endpoint observations grouped by route family. This includes localized ticket and profile pages.'
    case 'surface:api': return 'Stored API endpoint observations, including attachment downloads. A 200 response does not establish access to private tickets.'
    case 'host:static.bugcamp.io': return 'CMDB: CloudFront serves this public asset host from S3. It was outside this same-origin crawl and has not been probed.'
    case 'store-role:relational-db': return 'CMDB: the API connects to RDS MySQL 8. The resource ID is synthetic.'
    case 'store-role:session': return 'CMDB: the API uses a MySQL session table in the same RDS instance.'
    case 'store-role:ticket-files': return 'CMDB: the API reads ticket attachments from EFS. Per-ticket access conditions remain unknown.'
    case 'store-role:public-uploads': return 'CMDB: the API writes public uploads to S3, and CloudFront serves the static host from that origin.'
    default: return 'Select a related node or route family to inspect its evidence.'
  }
}

createRoot(document.getElementById('root')!).render(<App />)
