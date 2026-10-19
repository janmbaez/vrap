import { useEffect, useState } from 'react'
import { Plus, RefreshCw, Search, Save, ShieldCheck, Wand2 } from 'lucide-react'
import { api, User } from '../api'
import { Badge, ErrorBox, PageTitle } from '../components/UI'

const views = ['All', 'Suggested', 'Active', 'Completed', 'Reopened', 'Archived']
const statuses = ['Planned', 'Open', 'In Progress', 'Pending Verification', 'Verified Closed', 'Blocked', 'Partially Remediated', 'Reopened']
const pageSize = 50

export default function RemediationPackages({ user }: { user: User }) {
  const canWrite = user.role === 'Administrator' || user.role === 'Security Analyst'
  const [rows, setRows] = useState<any[]>([]), [suggestions, setSuggestions] = useState<any[]>([]), [owners, setOwners] = useState<any[]>([])
  const [error, setError] = useState(''), [busy, setBusy] = useState(false), [loading, setLoading] = useState(true)
  const [view, setView] = useState('All'), [search, setSearch] = useState(''), [query, setQuery] = useState(''), [page, setPage] = useState(1), [total, setTotal] = useState(0), [refresh, setRefresh] = useState(0)
  const [open, setOpen] = useState<any>(null), [tab, setTab] = useState('Overview'), [evidence, setEvidence] = useState('')
  const [findingSearch, setFindingSearch] = useState(''), [findingResults, setFindingResults] = useState<any[]>([])

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true); setError('')
    const params = new URLSearchParams({ page: String(page), page_size: String(pageSize), include_archived: 'true', view, q: query })
    api<{items:any[];total:number}>(`/remediation-packages?${params}`, {signal:controller.signal})
      .then(result => { setRows(result.items); setTotal(result.total) })
      .catch(err => { if (err.name !== 'AbortError') setError(`Packages could not be loaded: ${err.message || 'API error'}`) })
      .finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [page, view, query, refresh])
  useEffect(() => {
    api<any[]>('/remediation-packages/suggestions').then(setSuggestions).catch(() => undefined)
    api<any[]>('/owners').then(setOwners).catch(() => undefined)
  }, [refresh])
  const reload = () => setRefresh(value => value + 1)
  const show = (item:any) => { setOpen({...item, originalFindingIds:[...(item.finding_ids || [])]}); setTab('Overview'); setFindingResults([]) }
  const updateOpen = (key:string, value:unknown) => setOpen((current:any) => ({...current, [key]:value}))
  const getPackage = async (id:number) => { const item = await api<any>(`/remediation-packages/${id}`); setOpen({...item, originalFindingIds:[...item.finding_ids]}) }
  async function create(s:any) {
    setBusy(true); setError('')
    try {
      const created = await api<any>('/remediation-packages', {method:'POST', body:JSON.stringify({name:s.name, remediation_action:s.remediation_action, source:'suggested', suggestion_key:s.suggestion_key})})
      show(created); reload()
    } catch (err) { setError((err as Error).message) } finally { setBusy(false) }
  }
  async function searchFindings() {
    try {
      const result = await api<{items:any[]}>(`/findings?q=${encodeURIComponent(findingSearch)}&limit=50`)
      setFindingResults(result.items || [])
    } catch (err) { setError((err as Error).message) }
  }
  async function save() {
    if (!open) return
    setBusy(true); setError('')
    try {
      const common = {name:open.name.trim(), remediation_action:open.remediation_action.trim(), owner_id:open.owner_id ?? null,
        jira_reference:open.jira_reference || null, due_date:open.due_date || null, change_window:open.change_window || null,
        blockers:open.blockers || []}
      const ids = open.finding_ids || []
      const changedLinks = ids.length !== open.originalFindingIds?.length || ids.some((id:number) => !open.originalFindingIds.includes(id))
      const payload = open.id ? {...common, status:open.status, ...(changedLinks ? {finding_ids:ids} : {})} : {...common, finding_ids:ids}
      const updated = await api<any>(open.id ? `/remediation-packages/${open.id}` : '/remediation-packages', {method:open.id?'PUT':'POST', body:JSON.stringify(payload)})
      show(updated); reload()
    } catch (err) { setError((err as Error).message) } finally { setBusy(false) }
  }
  async function addEvidence() {
    if (!evidence.trim() || !open?.id) return
    setBusy(true); setError('')
    try {
      await api(`/remediation-packages/${open.id}/evidence`, {method:'POST', body:JSON.stringify({evidence_type:'rescan', reference:evidence.trim()})})
      setEvidence(''); await getPackage(open.id); reload()
    } catch (err) { setError((err as Error).message) } finally { setBusy(false) }
  }
  async function verify(id:number) {
    setBusy(true); setError('')
    try {
      await api(`/remediation-packages/${open.id}/evidence/${id}/verify`, {method:'POST'})
      await getPackage(open.id); reload()
    } catch (err) { setError((err as Error).message) } finally { setBusy(false) }
  }
  async function archive() {
    if (!open?.id) return
    setBusy(true); setError('')
    try {
      show(await api(`/remediation-packages/${open.id}/${open.archived?'restore':'archive'}`, {method:'POST'})); reload()
    } catch (err) { setError((err as Error).message) } finally { setBusy(false) }
  }
  return <>
    <PageTitle title="Remediation Work Packages 2.0" description="Coordinate compatible fixes across plugins and assets, then verify every finding." actions={<>
      <button onClick={reload} disabled={loading}><RefreshCw size={16}/> Refresh</button>
      {canWrite&&<button className="primary" onClick={()=>show({name:'',remediation_action:'',status:'Planned',finding_ids:[],blockers:[]})}><Plus size={16}/> New package</button>}
    </>}/>
    <ErrorBox error={error}/>
    {loading&&<section className="panel" aria-live="polite">Loading remediation packages…</section>}
    <section className="panel"><div className="section-head"><div><h2>Suggested remediation initiatives</h2><p>Suggestions require matching action, product/platform and technical evidence.</p></div><Badge>{suggestions.length}</Badge></div>
      <div className="table-scroll"><table><thead><tr><th>Initiative</th><th>Plugins</th><th>Findings</th><th>Assets</th><th/></tr></thead><tbody>{suggestions.slice(0,20).map(s=><tr key={s.suggestion_key}><td><strong>{s.name}</strong><small>{s.remediation_action}</small></td><td>{s.plugin_ids.length}</td><td>{s.findings}</td><td>{s.assets}</td><td>{canWrite&&<button className="primary" disabled={busy} onClick={()=>create(s)}><Wand2 size={15}/> Create package</button>}</td></tr>)}</tbody></table></div>
    </section>
    <section className="panel table-panel"><div className="section-head"><h2>Packages</h2><Badge>{total}</Badge></div>
      <form className="inline-form" onSubmit={event=>{event.preventDefault();setPage(1);setQuery(search.trim())}}><input value={search} onChange={event=>setSearch(event.target.value)} placeholder="Search packages, actions or Jira references" aria-label="Search packages"/><button type="submit"><Search size={16}/> Search</button><select value={view} onChange={event=>{setView(event.target.value);setPage(1)}}>{views.map(value=><option key={value}>{value}</option>)}</select></form>
      <div className="table-scroll">{!loading&&!error&&!rows.length&&<p className="empty-state">No packages match this view.</p>}<table><thead><tr><th>Package</th><th>Findings / assets</th><th>Progress</th><th>Owner</th><th>SLA / status</th><th/></tr></thead><tbody>{rows.map(row=><tr key={row.id} onClick={()=>show(row)} onKeyDown={event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();show(row)}}} tabIndex={0} role="button"><td><strong>{row.name}</strong><small>{row.remediation_action}</small></td><td>{row.finding_ids.length} / {row.unique_assets}</td><td>{row.verified_findings||0} verified<br/><small>{Object.entries(row.finding_statuses||{}).map(([key,value])=>`${key}: ${value}`).join(' · ')}</small></td><td>{owners.find(owner=>owner.id===row.owner_id)?.username||'Unassigned'}</td><td>{row.due_date||'—'}<br/><Badge>{row.archived?'Archived':row.status}</Badge></td><td><button onClick={event=>{event.stopPropagation();show(row)}}>Manage</button></td></tr>)}</tbody></table></div>
      <div className="pagination"><button disabled={loading||page<=1} onClick={()=>setPage(value=>value-1)}>Previous</button><span>Page {page} of {Math.max(1,Math.ceil(total/pageSize))}</span><button disabled={loading||page*pageSize>=total} onClick={()=>setPage(value=>value+1)}>Next</button></div>
    </section>
    {open&&<section className="panel form-grid" aria-label="Package detail"><div className="section-head"><h2>{open.name||'New package'}</h2><button onClick={()=>setOpen(null)}>Close</button></div>
      <div className="inline-form wide" role="tablist">{['Overview','Findings','Remediation','Evidence','Activity History'].map(value=><button key={value} aria-selected={tab===value} onClick={()=>setTab(value)}>{value}</button>)}</div>
      {tab==='Overview'&&<><label>Package name<input value={open.name||''} disabled={!canWrite} onChange={event=>updateOpen('name',event.target.value)}/></label><label>Remediation action<textarea value={open.remediation_action||''} disabled={!canWrite} onChange={event=>updateOpen('remediation_action',event.target.value)}/></label><label>Status<select value={open.status||'Planned'} disabled={!canWrite||!open.id} onChange={event=>updateOpen('status',event.target.value)}>{statuses.map(value=><option key={value}>{value}</option>)}</select></label><label>Owner<select value={open.owner_id??''} disabled={!canWrite} onChange={event=>updateOpen('owner_id',event.target.value?Number(event.target.value):null)}><option value="">Unassigned</option>{owners.map(owner=><option key={owner.id} value={owner.id}>{owner.username}</option>)}</select></label><label>Jira reference<input value={open.jira_reference||''} disabled={!canWrite} onChange={event=>updateOpen('jira_reference',event.target.value)}/></label><label>Due date<input type="date" value={open.due_date||''} disabled={!canWrite} onChange={event=>updateOpen('due_date',event.target.value)}/></label><label>Change window<input value={open.change_window||''} disabled={!canWrite} onChange={event=>updateOpen('change_window',event.target.value)}/></label><label>Blockers<input value={(open.blockers||[]).join(', ')} disabled={!canWrite} onChange={event=>updateOpen('blockers',event.target.value.split(',').map((value:string)=>value.trim()).filter(Boolean))}/></label></>}
      {tab==='Findings'&&<div className="wide"><h3>Findings ({(open.finding_ids||[]).length})</h3><div className="inline-form"><input value={findingSearch} onChange={event=>setFindingSearch(event.target.value)} placeholder="Search findings, assets, or plugins"/><button onClick={searchFindings}><Search size={16}/> Search</button></div>{findingResults.map(finding=><label className="check-row" key={finding.id}><input type="checkbox" disabled={!canWrite} checked={(open.finding_ids||[]).includes(finding.id)} onChange={event=>{const ids=event.target.checked?[...(open.finding_ids||[]),finding.id]:(open.finding_ids||[]).filter((id:number)=>id!==finding.id);updateOpen('finding_ids',[...new Set(ids)])}}/> {finding.name||finding.vulnerability?.name} · {finding.asset?.hostname||finding.asset}</label>)}</div>}
      {tab==='Remediation'&&<div className="wide"><p>{(open.finding_statuses&&Object.entries(open.finding_statuses).map(([key,value])=>`${key}: ${value}`).join(' · '))||'No findings linked yet.'}</p><p>{(open.closure_blockers||[]).join('; ')||'No closure blockers.'}</p></div>}
      {tab==='Evidence'&&<div className="wide"><div className="inline-form"><input value={evidence} disabled={!canWrite||!open.id} onChange={event=>setEvidence(event.target.value)} placeholder="Rescan report or change record reference"/>{canWrite&&<button disabled={!open.id||busy} onClick={addEvidence}><ShieldCheck size={16}/> Add evidence</button>}</div>{(open.evidence||[]).map((item:any)=><div className="check-row" key={item.id}>{item.type}: {item.reference} · {item.verified?'Verified':user.role==='Administrator'?<button disabled={busy} onClick={()=>verify(item.id)}>Verify</button>:<span>Awaiting administrator verification</span>}</div>)}</div>}
      {tab==='Activity History'&&<p className="wide">Package changes are recorded in Audit History.</p>}
      {canWrite&&<div className="inline-form wide"><button className="primary" disabled={busy||!open.name?.trim()||!open.remediation_action?.trim()} onClick={save}><Save size={16}/> Save package</button>{open.id&&<button disabled={busy} onClick={archive}>{open.archived?'Restore':'Archive'}</button>}</div>}
    </section>}
  </>
}
