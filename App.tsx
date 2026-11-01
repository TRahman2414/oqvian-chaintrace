import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertTriangle, ArrowDownRight, ArrowUpRight, Bell, BookOpenCheck, Check,
  ChevronDown, ChevronRight, CircleHelp, Clock3, Database, Download, FileSearch,
  Fingerprint, Gauge, GitBranch, KeyRound, LayoutDashboard, ListFilter, Mail,
  MoreHorizontal, Play, RefreshCw, Search, Server, Shield, ShieldAlert,
  ShieldCheck, SlidersHorizontal, Sparkles, TerminalSquare, UserRound, Wifi,
  X,
} from 'lucide-react'

type EventRecord = {
  id: string; source_event_id: string; event_type: string; event_timestamp: string; source_type: string
  actor_identity_id?: string | null; target_identity_id?: string | null; source_ip?: string | null
  destination?: string | null; outcome?: string | null; attributes: Record<string, unknown>; raw_evidence: Record<string, unknown>
}
type Incident = {
  id: string; primary_identity_id: string; title: string; description: string; severity: string; score: number
  confidence_label: string; status: string; event_ids: string[]; rule_ids: string[]
  explanations: { rule_id: string; text: string; score: number }[]; recommendations: string[]
  first_event_at: string; last_event_at: string; updated_at: string; events?: EventRecord[]; notes?: { id: string; author: string; note: string; created_at: string }[]
}
type Summary = {
  event_count: number; rule_match_count: number; active_incident_count: number; critical_incident_count: number
  identity_count: number; severity_distribution: Record<string, number>; recent_incidents: Incident[]; recent_events: EventRecord[]
}
type Scenario = { id: string; title: string; description: string; event_count: number }
type Page = 'Overview' | 'Event Stream' | 'Attack Chains' | 'Investigations' | 'Correlation Rules' | 'Demo Control'

const pages: { name: Page; icon: typeof LayoutDashboard }[] = [
  { name: 'Overview', icon: LayoutDashboard }, { name: 'Event Stream', icon: Activity },
  { name: 'Attack Chains', icon: GitBranch }, { name: 'Investigations', icon: FileSearch },
  { name: 'Correlation Rules', icon: BookOpenCheck }, { name: 'Demo Control', icon: Play },
]
const ruleInfo = [
  { id: 'R001', title: 'Authentication failure burst', icon: KeyRound, detail: '6+ failures against one identity within five minutes.', window: '5 min', points: '+15' },
  { id: 'R002', title: 'Unusual successful sign-in', icon: Fingerprint, detail: 'A login succeeds within ten minutes and the synthetic baseline explicitly marks its source unfamiliar.', window: '10 min', points: '+20' },
  { id: 'R003', title: 'Privilege change', icon: ShieldCheck, detail: 'A privilege grant targets the investigated identity within twenty minutes.', window: '20 min', points: '+25' },
  { id: 'R004', title: 'External forwarding', icon: Mail, detail: 'Forwarding points outside the approved domain list within thirty minutes.', window: '30 min', points: '+20' },
  { id: 'R005', title: 'Large download', icon: Download, detail: 'The same identity downloads 250 MB or more within thirty minutes.', window: '30 min', points: '+20' },
  { id: 'R006', title: 'Multi-stage chain', icon: GitBranch, detail: 'At least three distinct stages, including unusual authentication and one later high-risk action, within 45 minutes.', window: '45 min', points: 'Link' },
]

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { ...init, headers: { 'Content-Type': 'application/json', ...init?.headers } })
  if (!response.ok) {
    let reason = `Request failed (${response.status})`
    try { const body = await response.json(); reason = typeof body.detail === 'string' ? body.detail : reason } catch { /* keep default */ }
    throw new Error(reason)
  }
  return response.json() as Promise<T>
}
function time(value?: string) { if (!value) return '—'; return new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'UTC' }) }
function dateTime(value?: string) { if (!value) return '—'; return new Date(value).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', timeZone: 'UTC' }) }
function humanEvent(event: EventRecord) {
  const labels: Record<string, string> = { 'auth.login_failed': 'Authentication failed', 'auth.login_success': 'Successful sign-in', 'identity.role_granted': 'Privilege granted', 'mail.forwarding_rule_created': 'Forwarding rule created', 'files.bulk_download': 'Large file download' }
  return labels[event.event_type] || event.event_type.replaceAll('.', ' ')
}
function shortIdentity(value?: string | null) { return value?.replace('identity-', '').replaceAll('-', ' ') || 'Unknown identity' }

function App() {
  const [page, setPage] = useState<Page>('Overview')
  const [summary, setSummary] = useState<Summary | null>(null)
  const [events, setEvents] = useState<EventRecord[]>([])
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [scenarios, setScenarios] = useState<Scenario[]>([])
  const [status, setStatus] = useState<Record<string, unknown> | null>(null)
  const [scenarioId, setScenarioId] = useState('full-chain')
  const [cursor, setCursor] = useState(0)
  const [totalSteps, setTotalSteps] = useState(0)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [query, setQuery] = useState('')
  const [selectedIncident, setSelectedIncident] = useState<string | null>(null)
  const [selectedEvent, setSelectedEvent] = useState<EventRecord | null>(null)
  const [toast, setToast] = useState('')

  const refresh = useCallback(async () => {
    const [nextSummary, nextEvents, nextIncidents, nextScenarios, nextStatus] = await Promise.all([
      api<Summary>('/api/dashboard/summary'), api<{ items: EventRecord[] }>('/api/events?limit=200'),
      api<{ items: Incident[] }>('/api/incidents'), api<{ items: Scenario[]; active_scenario_id: string | null; cursor: number }>('/api/demo/scenarios'), api<Record<string, unknown>>('/api/system/status'),
    ])
    setSummary(nextSummary); setEvents(nextEvents.items); setIncidents(nextIncidents.items); setScenarios(nextScenarios.items); setStatus(nextStatus)
    setCursor(nextScenarios.cursor); setScenarioId(nextScenarios.active_scenario_id || 'full-chain')
    const scenario = nextScenarios.items.find(item => item.id === nextScenarios.active_scenario_id)
    setTotalSteps(scenario?.event_count || 0)
    if (!selectedIncident && nextIncidents.items.length) setSelectedIncident(nextIncidents.items[0].id)
  }, [selectedIncident])

  useEffect(() => { refresh().catch(err => setError(err.message)).finally(() => setLoading(false)) }, [refresh])
  useEffect(() => { if (!toast) return; const handle = window.setTimeout(() => setToast(''), 3000); return () => window.clearTimeout(handle) }, [toast])

  const selected = incidents.find(item => item.id === selectedIncident) || null
  const filteredEvents = useMemo(() => events.filter(item => `${item.event_type} ${item.actor_identity_id || ''} ${item.target_identity_id || ''} ${item.source_type}`.toLowerCase().includes(query.toLowerCase())), [events, query])
  const critical = summary?.critical_incident_count || 0

  const perform = async (action: () => Promise<unknown>, message?: string) => {
    setBusy(true); setError('')
    try { await action(); await refresh(); if (message) setToast(message) }
    catch (err) { setError(err instanceof Error ? err.message : 'Action failed') }
    finally { setBusy(false) }
  }
  const loadScenario = (id = scenarioId) => perform(async () => {
    const result = await api<{ total_events: number; scenario_id: string }>(`/api/demo/scenarios/${id}/load`, { method: 'POST' })
    setScenarioId(result.scenario_id); setCursor(0); setTotalSteps(result.total_events); setSelectedIncident(null)
  }, 'Synthetic scenario loaded')
  const stepScenario = () => perform(async () => {
    const result = await api<{ cursor: number; total_events: number; event: EventRecord | null; done: boolean }>(`/api/demo/scenarios/${scenarioId}/next`, { method: 'POST' })
    setCursor(result.cursor); setTotalSteps(result.total_events)
    if (result.event) setToast(`Ingested: ${humanEvent(result.event)}`)
    if (result.done) setToast('Scenario sequence complete')
  })
  const runScenario = () => perform(async () => {
    const result = await api<{ cursor: number; total_events: number; incidents: Incident[] }>(`/api/demo/scenarios/${scenarioId}/run`, { method: 'POST' })
    setCursor(result.cursor); setTotalSteps(result.total_events)
    if (result.incidents.length) { setSelectedIncident(result.incidents[0].id); setPage('Investigations') }
  }, 'Scenario playback complete')
  const resetDemo = () => perform(async () => {
    await api('/api/demo/reset', { method: 'POST' }); setSelectedIncident(null); setCursor(0); setTotalSteps(0)
  }, 'Demo state reset')
  const changeIncident = (id: string, patch: { status?: string; assigned_analyst?: string }) => perform(async () => {
    await api(`/api/incidents/${id}`, { method: 'PATCH', body: JSON.stringify(patch) })
  }, 'Investigation updated')

  const body = () => {
    if (loading) return <div className="loading-state"><span className="spinner" /> Loading local demonstration…</div>
    if (error && !summary) return <div className="error-state"><AlertTriangle size={22} /><strong>Local API unavailable</strong><span>{error}</span><small>Start the API and reload this page.</small></div>
    if (page === 'Overview') return <Overview summary={summary} incidents={incidents} events={events} status={status} onOpen={id => { setSelectedIncident(id); setPage('Investigations') }} onNavigate={setPage} onSelectEvent={setSelectedEvent} />
    if (page === 'Event Stream') return <EventStream events={filteredEvents} query={query} setQuery={setQuery} onSelect={setSelectedEvent} />
    if (page === 'Attack Chains') return <AttackChains incidents={incidents} onOpen={id => { setSelectedIncident(id); setPage('Investigations') }} onSelectEvent={setSelectedEvent} />
    if (page === 'Investigations') return <Investigations incidents={incidents} selected={selected} onSelect={setSelectedIncident} onStatus={changeIncident} onSelectEvent={setSelectedEvent} />
    if (page === 'Correlation Rules') return <Rules />
    return <DemoControl scenarios={scenarios} scenarioId={scenarioId} setScenarioId={setScenarioId} cursor={cursor} total={totalSteps} busy={busy} onLoad={loadScenario} onStep={stepScenario} onRun={runScenario} onReset={resetDemo} incidents={incidents} onOpen={id => { setSelectedIncident(id); setPage('Investigations') }} />
  }

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><GitBranch size={19} strokeWidth={2.2} /></div><div><strong>OQVIAN</strong><span>CHAINTRACE</span></div></div>
      <div className="workspace-label">SECURITY OPERATIONS <ChevronDown size={13} /></div>
      <div className="tenant-switch"><span className="tenant-dot">M</span><span><b>Meridian Digital</b><small>DEMO ENVIRONMENT</small></span><MoreHorizontal size={16} /></div>
      <nav className="nav-list" aria-label="Primary navigation">
        {pages.map(({ name, icon: Icon }) => <button key={name} onClick={() => setPage(name)} className={`nav-item ${page === name ? 'active' : ''}`} aria-current={page === name ? 'page' : undefined}><Icon size={17} strokeWidth={1.8} /><span>{name}</span>{name === 'Investigations' && critical > 0 && <em>{critical}</em>}</button>)}
      </nav>
      <div className="sidebar-bottom">
        <div className="sidebar-note"><span className="note-orb"><Shield size={15} /></span><div><b>Synthetic data only</b><small>Local demonstration mode</small></div><CircleHelp size={14} /></div>
        <button className="nav-item"><SlidersHorizontal size={17} /><span>Settings</span></button>
        <div className="profile-row"><span className="profile-avatar">DA</span><span><b>Demo analyst</b><small>Local operator</small></span><MoreHorizontal size={16} /></div>
      </div>
    </aside>

    <main className="main-area">
      <header className="topbar">
        <div className="crumb"><span>Workspace</span><ChevronRight size={13} /><b>{page}</b></div>
        <div className="topbar-right"><span className="local-badge"><span className="pulse-dot" /> LOCAL ONLY</span><span className="model-state"><Sparkles size={14} /> Model not connected</span><button className="icon-button" title="Notifications"><Bell size={17} /><i /></button><button className="top-avatar">DA</button></div>
      </header>
      {error && summary && <div className="inline-error"><AlertTriangle size={15} />{error}<button onClick={() => setError('')}><X size={14} /></button></div>}
      {body()}
    </main>
    {selectedEvent && <EventDrawer event={selectedEvent} onClose={() => setSelectedEvent(null)} />}
    {toast && <div className="toast"><Check size={16} />{toast}</div>}
    <div className="demo-ribbon"><span><span className="tiny-seal"><ShieldAlert size={11} /></span> DEMONSTRATION</span><span>Fictional telemetry · not connected to production</span></div>
  </div>
}

function PageHeading({ eyebrow, title, text, action }: { eyebrow: string; title: string; text: string; action?: React.ReactNode }) {
  return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{text}</p></div>{action}</div>
}
function Overview({ summary, incidents, events, status, onOpen, onNavigate, onSelectEvent }: { summary: Summary | null; incidents: Incident[]; events: EventRecord[]; status: Record<string, unknown> | null; onOpen: (id: string) => void; onNavigate: (page: Page) => void; onSelectEvent: (event: EventRecord) => void }) {
  const metrics = [
    { label: 'EVENTS OBSERVED', value: summary?.event_count || 0, detail: 'Normalized records', icon: Activity, trend: 'local feed' },
    { label: 'RULE MATCHES', value: summary?.rule_match_count || 0, detail: 'Deterministic signals', icon: GitBranch, trend: 'R001–R006' },
    { label: 'OPEN INVESTIGATIONS', value: summary?.active_incident_count || 0, detail: 'Evidence-linked cases', icon: FileSearch, trend: 'analyst review' },
    { label: 'CRITICAL PRIORITY', value: summary?.critical_incident_count || 0, detail: 'Demo heuristic only', icon: ShieldAlert, trend: 'not probability' },
  ]
  const chain = incidents[0]
  return <div className="page-content">
    <PageHeading eyebrow="COMMAND CENTER / 01" title="Signal overview" text="A clear view of what the event stream is saying—and why it matters." action={<span className="environment-pill"><span className="environment-icon"><Database size={15} /></span> Meridian · Demo tenant <ChevronDown size={14} /></span>} />
    <section className="metric-grid">{metrics.map(({ label, value, detail, icon: Icon, trend }, i) => <div className={`metric-card metric-${i}`} key={label}><div className="metric-top"><span>{label}</span><Icon size={16} /></div><div className="metric-value">{value.toLocaleString()}</div><div className="metric-foot"><span>{detail}</span><small>{trend}</small></div></div>)}</section>
    <div className="overview-grid">
      <section className="panel chain-panel">
        <div className="panel-heading"><div><div className="section-overline">INVESTIGATION SPOTLIGHT</div><h2>From noise to narrative</h2></div><button className="subtle-button" onClick={() => onNavigate('Attack Chains')}>View chains <ArrowUpRight size={14} /></button></div>
        {chain ? <>
          <div className="chain-overview-head"><div><span className={`severity-pill ${chain.severity.toLowerCase()}`}><span />{chain.severity}</span><span className="chain-tag">{chain.rule_ids.length - 1} STAGES LINKED</span></div><strong>{chain.score}<small>/100</small></strong></div>
          <h3 className="chain-title">{chain.title}</h3><p className="chain-caption">Potential sequence for <b>{shortIdentity(chain.primary_identity_id)}</b>. Review the linked source evidence before acting.</p>
          <EvidenceRail events={chain.events || events.filter(e => chain.event_ids.includes(e.id))} ruleIds={chain.rule_ids} onSelect={onSelectEvent} compact />
          <div className="chain-footer"><span><Fingerprint size={14} /> {shortIdentity(chain.primary_identity_id)}</span><span><Clock3 size={14} /> {dateTime(chain.first_event_at)}</span><button onClick={() => onOpen(chain.id)}>Open investigation <ChevronRight size={14} /></button></div>
        </> : <EmptyState icon={GitBranch} title="No linked chain yet" detail="Load a scenario and step through events to see a potential sequence form." action={<button className="primary-button" onClick={() => onNavigate('Demo Control')}>Open demo controller <Play size={14} /></button>} />}
      </section>
      <section className="panel activity-panel">
        <div className="panel-heading"><div><div className="section-overline">EVENT STREAM</div><h2>Latest activity</h2></div><button className="icon-link" onClick={() => onNavigate('Event Stream')}>All events <ArrowUpRight size={14} /></button></div>
        <div className="activity-list">{events.slice(0, 6).map((event, index) => <div className="activity-row" key={event.id}><span className={`activity-marker marker-${index % 4}`}><EventIcon type={event.event_type} size={14} /></span><div className="activity-copy"><b>{humanEvent(event)}</b><small>{shortIdentity(event.actor_identity_id || event.target_identity_id)} · {event.source_type}</small></div><time>{time(event.event_timestamp)}</time></div>)}{events.length === 0 && <EmptyState icon={Activity} title="No incoming records" detail="Use the demo controller to load synthetic events." />}</div>
        <div className="feed-footer"><span><span className="pulse-dot" /> Local feed</span><span>{events.length} total records</span></div>
      </section>
    </div>
    <div className="overview-bottom">
      <section className="panel incident-table"><div className="panel-heading"><div><div className="section-overline">NEEDS REVIEW</div><h2>Recent investigations</h2></div><button className="icon-link" onClick={() => onNavigate('Investigations')}>See all <ArrowUpRight size={14} /></button></div>
        {incidents.length ? <div className="table-scroll"><table><thead><tr><th>CASE</th><th>IDENTITY</th><th>PRIORITY</th><th>UPDATED</th><th>STATUS</th><th></th></tr></thead><tbody>{incidents.slice(0, 4).map(item => <tr key={item.id} onClick={() => onOpen(item.id)}><td><b>{item.title}</b><small>{item.rule_ids.length - 1} matched stages</small></td><td>{shortIdentity(item.primary_identity_id)}</td><td><span className={`severity-pill ${item.severity.toLowerCase()}`}><span />{item.severity}</span></td><td>{dateTime(item.updated_at)}</td><td><span className="status-chip">{item.status}</span></td><td><ChevronRight size={15} /></td></tr>)}</tbody></table></div> : <EmptyState icon={ShieldCheck} title="Clear queue" detail="No correlated incidents in the current demo." />}
      </section>
      <section className="panel health-panel"><div className="panel-heading"><div><div className="section-overline">SYSTEM POSTURE</div><h2>Local status</h2></div><span className="health-label"><span className="pulse-dot" /> Operational</span></div>
        <div className="health-list"><HealthRow icon={Server} label="API service" value={String(status?.api || '—')} good /><HealthRow icon={Database} label="Local database" value={String(status?.database || '—')} good /><HealthRow icon={Shield} label="Correlation core" value={String(status?.correlation || '—')} good /><HealthRow icon={Sparkles} label="Model connection" value="Not configured" /></div>
        <div className="local-note"><ShieldCheck size={15} /><span>Events stay in this local demonstration.</span></div>
      </section>
    </div>
  </div>
}

function HealthRow({ icon: Icon, label, value, good = false }: { icon: typeof Server; label: string; value: string; good?: boolean }) { return <div className="health-row"><span className="health-icon"><Icon size={15} /></span><span>{label}</span><b className={good ? 'good-text' : ''}>{value}</b></div> }
function EventIcon({ type, size = 16 }: { type: string; size?: number }) { const Icon = type.includes('auth') ? KeyRound : type.includes('role') ? ShieldCheck : type.includes('mail') ? Mail : type.includes('files') ? Download : Activity; return <Icon size={size} /> }
function EmptyState({ icon: Icon, title, detail, action }: { icon: typeof Activity; title: string; detail: string; action?: React.ReactNode }) { return <div className="empty-state"><span className="empty-icon"><Icon size={19} /></span><b>{title}</b><p>{detail}</p>{action}</div> }

function EvidenceRail({ events, ruleIds, onSelect, compact = false }: { events: EventRecord[]; ruleIds?: string[]; onSelect: (event: EventRecord) => void; compact?: boolean }) {
  const ordered = [...events].sort((a, b) => a.event_timestamp.localeCompare(b.event_timestamp))
  const stageRule: Record<string, string> = { 'auth.login_failed': 'R001', 'auth.login_success': 'R002', 'identity.role_granted': 'R003', 'mail.forwarding_rule_created': 'R004', 'files.bulk_download': 'R005' }
  const rows = compact
    ? [...new Set(ordered.map(event => stageRule[event.event_type]).filter(Boolean))].map(rule => {
        const group = ordered.filter(event => stageRule[event.event_type] === rule)
        return { event: group[0], count: group.length, rule }
      })
    : ordered.map(event => ({ event, count: 1, rule: stageRule[event.event_type] }))
  return <div className={`evidence-rail ${compact ? 'compact' : ''}`}>{rows.map(({ event, count, rule }, index) => {
    const linked = !ruleIds || (rule ? ruleIds.includes(rule) : false)
    return <button className={`rail-event ${linked ? 'linked' : ''}`} key={rule || event.id} onClick={() => onSelect(event)}>
      <span className="rail-dot"><EventIcon type={event.event_type} size={13} /></span>
      <span className="rail-copy"><b>{humanEvent(event)}</b><small>{compact && count > 1 ? `${count} source records` : shortIdentity(event.actor_identity_id || event.target_identity_id)}</small></span>
      <span className="rail-time">{time(event.event_timestamp)}</span>{rule && <span className="rail-rule">{rule}</span>}
      {index < rows.length - 1 && <span className="rail-line" />}
    </button>
  })}</div>
}

function EventStream({ events, query, setQuery, onSelect }: { events: EventRecord[]; query: string; setQuery: (v: string) => void; onSelect: (e: EventRecord) => void }) {
  const [type, setType] = useState('all')
  const filtered = type === 'all' ? events : events.filter(e => e.event_type === type)
  return <div className="page-content"><PageHeading eyebrow="TELEMETRY / 02" title="Event stream" text="Normalized records stay inspectable from source through correlation." action={<span className="count-pill"><span className="pulse-dot" /> {events.length} records</span>} />
    <section className="panel event-panel"><div className="filter-bar"><label className="search-box"><Search size={16} /><input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search identity, source, event…" /></label><label className="select-wrap"><ListFilter size={15} /><select value={type} onChange={e => setType(e.target.value)}><option value="all">All event types</option>{[...new Set(events.map(e => e.event_type))].map(t => <option key={t} value={t}>{humanEvent({ event_type: t } as EventRecord)}</option>)}</select><ChevronDown size={13} /></label><button className="subtle-button"><SlidersHorizontal size={15} /> Filters</button></div>
      {filtered.length ? <div className="table-scroll"><table className="events-table"><thead><tr><th>EVENT</th><th>IDENTITY</th><th>SOURCE</th><th>OCCURRED</th><th>OUTCOME</th><th></th></tr></thead><tbody>{filtered.map(event => <tr key={event.id} onClick={() => onSelect(event)}><td><span className="event-cell"><span className="event-cell-icon"><EventIcon type={event.event_type} size={15} /></span><b>{humanEvent(event)}</b></span><small className="event-id">{event.source_event_id}</small></td><td>{shortIdentity(event.target_identity_id || event.actor_identity_id)}{event.target_identity_id && event.actor_identity_id !== event.target_identity_id && <small>Actor: {shortIdentity(event.actor_identity_id)}</small>}</td><td><span className="source-label">{event.source_type}</span></td><td>{dateTime(event.event_timestamp)}</td><td><span className={`outcome ${event.outcome === 'failure' ? 'failed' : 'success'}`}><span />{event.outcome || 'observed'}</span></td><td><ChevronRight size={15} /></td></tr>)}</tbody></table></div> : <EmptyState icon={Search} title="No matching events" detail="Try another search term or clear filters." />}
    </section><div className="footnote"><ShieldCheck size={14} /> Source records are preserved as inert evidence. Event proximity alone does not establish a relationship.</div></div>
}

function AttackChains({ incidents, onOpen, onSelectEvent }: { incidents: Incident[]; onOpen: (id: string) => void; onSelectEvent: (event: EventRecord) => void }) {
  return <div className="page-content"><PageHeading eyebrow="CORRELATION / 03" title="Attack chains" text="Connected activity, linked by explicit rules and anchored to source events." action={<span className="count-pill">{incidents.length} linked chain{incidents.length === 1 ? '' : 's'}</span>} />
    {incidents.length ? <div className="chain-list">{incidents.map(item => <section className="panel attack-chain-card" key={item.id}><div className="chain-card-top"><div><span className={`severity-pill ${item.severity.toLowerCase()}`}><span />{item.severity}</span><span className="chain-tag">{item.rule_ids.length - 1} SIGNAL STAGES</span></div><span className="score-display">{item.score}<small> / 100</small></span></div><div className="chain-card-title"><div><h2>{item.title}</h2><p>Identity <b>{shortIdentity(item.primary_identity_id)}</b> · {dateTime(item.first_event_at)}</p></div><button className="subtle-button" onClick={() => onOpen(item.id)}>Investigate <ChevronRight size={14} /></button></div><EvidenceRail events={item.events || []} ruleIds={item.rule_ids} onSelect={onSelectEvent} /><div className="chain-card-bottom"><span><GitBranch size={14} /> {item.rule_ids.join(' · ')}</span><span><ShieldCheck size={14} /> {item.confidence_label} confidence · heuristic priority</span></div></section>)}</div> : <div className="panel empty-panel"><EmptyState icon={GitBranch} title="No attack chain yet" detail="Load and run one of the synthetic scenarios in Demo Control. The chain appears only when identity, timing, and rule evidence align." /></div>}
  </div>
}

function Investigations({ incidents, selected, onSelect, onStatus, onSelectEvent }: { incidents: Incident[]; selected: Incident | null; onSelect: (id: string) => void; onStatus: (id: string, patch: { status?: string; assigned_analyst?: string }) => void; onSelectEvent: (event: EventRecord) => void }) {
  return <div className="page-content investigation-page"><PageHeading eyebrow="CASEWORK / 04" title="Investigation workspace" text="Verify the evidence, assess the context, and record the analyst decision." action={<button className="subtle-button"><UserRound size={14} /> Assign analyst <ChevronDown size={14} /></button>} />
    <div className="investigation-layout"><aside className="panel case-list"><div className="case-list-head"><b>CASE QUEUE</b><span>{incidents.length}</span></div>{incidents.map(item => <button key={item.id} className={`case-item ${selected?.id === item.id ? 'selected' : ''}`} onClick={() => onSelect(item.id)}><span className={`case-severity ${item.severity.toLowerCase()}`} /><span><b>{item.title}</b><small>{shortIdentity(item.primary_identity_id)} · {dateTime(item.first_event_at)}</small></span><ChevronRight size={14} /></button>)}{!incidents.length && <p className="case-empty">No cases in this demo yet.</p>}</aside>
      {selected ? <section className="panel investigation-detail"><div className="detail-header"><div><div className="section-overline">CASE {selected.id.slice(0, 8).toUpperCase()}</div><h2>{selected.title}</h2><p>{selected.description}</p></div><div className="detail-actions"><span className={`severity-pill ${selected.severity.toLowerCase()}`}><span />{selected.severity}</span><select value={selected.status} onChange={e => onStatus(selected.id, { status: e.target.value })}><option>New</option><option>Acknowledged</option><option>Investigating</option><option>Escalated</option><option>Resolved</option><option>Reopened</option></select><button className="icon-button" title="More actions"><MoreHorizontal size={18} /></button></div></div>
        <div className="case-facts"><Fact label="INVESTIGATED IDENTITY" value={shortIdentity(selected.primary_identity_id)} icon={Fingerprint} /><Fact label="DEMO PRIORITY SCORE" value={`${selected.score} / 100 · ${selected.severity}`} icon={Gauge} /><Fact label="CONFIDENCE" value={`${selected.confidence_label} · rule-supported`} icon={ShieldCheck} /><Fact label="TIME WINDOW" value={`${time(selected.first_event_at)} — ${time(selected.last_event_at)} UTC`} icon={Clock3} /></div>
        <div className="detail-section"><div className="detail-section-head"><div><div className="section-overline">EVIDENCE RAIL</div><h3>Sequence of observed activity</h3></div><span>{selected.events?.length || selected.event_ids.length} source records</span></div><EvidenceRail events={selected.events || []} ruleIds={selected.rule_ids} onSelect={onSelectEvent} /></div>
          <div className="detail-columns"><div className="detail-section"><div className="detail-section-head"><div><div className="section-overline">WHY IT WAS PRIORITIZED</div><h3>Rule explanation</h3></div></div><div className="explanation-list">{selected.explanations.map(item => <div className="explanation-row" key={item.rule_id}><span className="explain-rule">{item.rule_id}</span><div><b>{ruleInfo.find(r => r.id === item.rule_id)?.title || 'Multi-stage chain'}</b><p>{item.text}</p></div><strong>+{item.score}</strong></div>)}<div className="score-total"><span>Demonstration heuristic</span><b>{selected.score}<small>/100</small></b></div><p className="caveat"><CircleHelp size={14} /> This score is not a probability of compromise.</p></div></div>
          <div className="detail-section next-steps"><div className="detail-section-head"><div><div className="section-overline">ANALYST GUIDANCE</div><h3>Suggested next checks</h3></div></div>{selected.recommendations.map((item, i) => <div className="recommendation" key={item}><span>{String(i + 1).padStart(2, '0')}</span>{item}</div>)}<div className="human-note"><ShieldCheck size={15} /> Human validation is required before any response.</div></div></div>
      </section> : <section className="panel no-case"><EmptyState icon={FileSearch} title="Choose an investigation" detail="Select a case from the queue, or create one by running the full-chain demo." /></section>}
    </div>
  </div>
}
function Fact({ label, value, icon: Icon }: { label: string; value: string; icon: typeof Gauge }) { return <div className="fact"><span><Icon size={14} /> {label}</span><b>{value}</b></div> }

function Rules() {
  return <div className="page-content"><PageHeading eyebrow="DETECTION LOGIC / 05" title="Correlation rules" text="Deterministic conditions explain how separate source events become linked evidence." action={<span className="count-pill"><ShieldCheck size={14} /> 6 active · local rules</span>} />
    <div className="rule-intro"><div className="rule-intro-icon"><GitBranch size={19} /></div><div><b>Explainable by design</b><p>These rules group only supported behavior for the same organization and investigated identity. The engine does not infer a relationship from time proximity alone.</p></div><span>UTC WINDOWS</span></div>
    <div className="rules-grid">{ruleInfo.map(({ id, title, icon: Icon, detail, window, points }) => <article className={`panel rule-card ${id === 'R006' ? 'rule-card-featured' : ''}`} key={id}><div className="rule-card-top"><span className="rule-id">{id}</span><span className="rule-points">{points === 'Link' ? 'CHAIN' : `${points} PTS`}</span></div><span className="rule-icon"><Icon size={18} /></span><h2>{title}</h2><p>{detail}</p><div className="rule-card-foot"><span><Clock3 size={13} /> {window} window</span><span><span className="pulse-dot" /> ENABLED</span></div></article>)}</div>
    <div className="score-note"><AlertTriangle size={16} /><span><b>Score is a demo heuristic.</b> Severity bands are illustrative. They are not trained, calibrated, or validated as compromise probabilities.</span></div>
  </div>
}

function DemoControl({ scenarios, scenarioId, setScenarioId, cursor, total, busy, onLoad, onStep, onRun, onReset, incidents, onOpen }: { scenarios: Scenario[]; scenarioId: string; setScenarioId: (id: string) => void; cursor: number; total: number; busy: boolean; onLoad: (id?: string) => void; onStep: () => void; onRun: () => void; onReset: () => void; incidents: Incident[]; onOpen: (id: string) => void }) {
  const current = scenarios.find(item => item.id === scenarioId)
  const labels = ['Failure burst', 'Unusual sign-in', 'Privilege change', 'External forwarding', 'Large download']
  const full = scenarioId === 'full-chain'
  const partial = scenarioId === 'partial-chain'
  const progress = total ? Math.min(100, cursor / total * 100) : 0
  return <div className="page-content"><PageHeading eyebrow="PRESENTER MODE / 06" title="Demo control" text="Stage the story at your pace. Every action calls the local API and persists synthetic evidence." action={<span className="demo-mode-chip"><Play size={13} /> CONTROLLED REPLAY</span>} />
    <div className="demo-layout"><section className="panel demo-controller"><div className="demo-card-head"><div className="controller-mark"><TerminalSquare size={20} /></div><div><div className="section-overline">SCENARIO RUNNER</div><h2>Choose the signal sequence</h2></div><span className="local-mode-chip"><span className="pulse-dot" /> LOCAL</span></div>
      <div className="scenario-options">{scenarios.map((scenario, i) => <button key={scenario.id} onClick={() => setScenarioId(scenario.id)} className={`scenario-option ${scenarioId === scenario.id ? 'selected' : ''}`}><span className={`scenario-index sc-${i}`}>0{i + 1}</span><span><b>{scenario.title}</b><small>{scenario.description}</small></span>{scenarioId === scenario.id && <span className="selected-check"><Check size={14} /></span>}</button>)}</div>
      <div className="runner-progress"><div className="progress-head"><span>EVENT REPLAY</span><b>{String(cursor).padStart(2, '0')} <small>/ {String(total || current?.event_count || 0).padStart(2, '0')} records</small></b></div><div className="progress-track"><span style={{ width: `${progress}%` }} /></div><div className="progress-labels"><span>Ready</span><span>{cursor === total && total > 0 ? 'Sequence complete' : 'Waiting for operator'}</span></div></div>
      <div className="runner-actions"><button className="primary-button" onClick={() => onLoad(scenarioId)} disabled={busy}><RefreshCw size={14} /> Load scenario</button><button className="secondary-button" onClick={onStep} disabled={busy || !total || cursor >= total}><ChevronRight size={15} /> Step next event</button><button className="secondary-button run-button" onClick={onRun} disabled={busy || !total || cursor >= total}><Play size={14} /> Run all</button><button className="text-button" onClick={onReset} disabled={busy}><RefreshCw size={14} /> Reset</button></div>
      <div className="scenario-expectation"><div className="section-overline">WHAT TO EXPECT</div><div className="expectation-rail">{labels.map((label, i) => { const shown = full || (partial && i !== 2) || scenarioId === 'benign-comparison'; return <span className={`${shown ? 'expected' : 'omitted'}`} key={label}><i>{shown ? <Check size={11} /> : <X size={11} />}</i>{label}</span> })}</div>{partial && <p className="omission-note">Privilege change is deliberately omitted from this sequence.</p>}{scenarioId === 'benign-comparison' && <p className="omission-note">Activity is split across identities; no full chain should form.</p>}</div>
    </section>
      <aside className="demo-side"><section className="panel live-readout"><div className="section-overline">LIVE READOUT</div><h3>Correlation state</h3><div className="readout-stat"><span>Current events</span><b>{cursor}<small> / {total || current?.event_count || 0}</small></b></div><div className="readout-stat"><span>Open cases</span><b>{incidents.length}</b></div><div className="readout-stat"><span>Detection engine</span><b className="good-text">Ready</b></div>{incidents.length > 0 && <div className="readout-case"><span className={`severity-pill ${incidents[0].severity.toLowerCase()}`}><span />{incidents[0].severity}</span><b>{incidents[0].title}</b><button onClick={() => onOpen(incidents[0].id)}>Review evidence <ChevronRight size={13} /></button></div>}</section>
        <section className="panel safety-callout"><span className="safety-icon"><ShieldCheck size={17} /></span><div><b>Safe by design</b><p>Fictional event records only. No external systems, live accounts, or response actions are involved.</p></div></section>
      </aside></div>
  </div>
}

function EventDrawer({ event, onClose }: { event: EventRecord; onClose: () => void }) {
  return <div className="drawer-backdrop" onClick={onClose}><aside className="event-drawer" onClick={e => e.stopPropagation()}><div className="drawer-head"><div><div className="section-overline">SOURCE EVIDENCE</div><h2>{humanEvent(event)}</h2></div><button className="icon-button" onClick={onClose}><X size={17} /></button></div><div className="drawer-timestamp"><Clock3 size={14} /> {dateTime(event.event_timestamp)} UTC</div><div className="drawer-fields"><Fact label="SOURCE" value={event.source_type} icon={Database} /><Fact label="ACTOR" value={shortIdentity(event.actor_identity_id)} icon={UserRound} /><Fact label="TARGET" value={shortIdentity(event.target_identity_id || event.actor_identity_id)} icon={Fingerprint} /><Fact label="SOURCE IP" value={event.source_ip || 'Not present'} icon={Wifi} /><Fact label="OUTCOME" value={event.outcome || 'Observed'} icon={Activity} /><Fact label="DESTINATION" value={event.destination || 'Not present'} icon={ArrowDownRight} /></div><div className="drawer-evidence"><div className="section-overline">RAW SYNTHETIC RECORD</div><pre>{JSON.stringify(event.raw_evidence, null, 2)}</pre></div><div className="drawer-note"><Shield size={15} /> Original record is preserved as inert demo evidence.</div></aside></div>
}

export default App
