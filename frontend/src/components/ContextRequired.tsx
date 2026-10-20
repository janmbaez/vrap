import { useEffect, useState } from 'react'
import { api, User } from '../api'
import { Badge, ErrorBox } from './UI'
import ContextClassificationReviews from './ContextClassificationReviews'
import {selectPage, toggleAsset, selectionPayload} from './contextSelection.ts'

type Filters = Record<'q'|'subcategory'|'os'|'device_type'|'missing_field'|'raci_owner'|'tag'|'environment'|'regulatory', string>
const emptyFilters: Filters = {q:'',subcategory:'',os:'',device_type:'',missing_field:'',raci_owner:'',tag:'',environment:'',regulatory:''}
const subcategories = ['Windows Servers','Windows Workstations','Linux Servers','Network Devices','Storage','Databases','Cloud','Applications','Unknown']
const environments = ['Development','Test','QA','Staging','Production']
const scopes = ['PCI DSS','SOC 2','SOX','HIPAA','GDPR','Other','None']
const fields: [string,string,string[]][] = [
  ['asset_criticality','Asset criticality',['Low','Medium','High','Critical']],
  ['business_criticality','Business criticality',['Low','Medium','High','Critical']],
  ['data_classification','Data classification',['Public','Internal','Confidential','Restricted']],
  ['environment','Environment',environments],
  ['exposure','Exposure',['Internet Facing','Internal','Restricted Network','Isolated']],
]
type Row = {finding_id:number;category:string;asset:{id:number;hostname:string;ip:string;os:string};missing_fields:string[]}
type Result = {items:Row[];total:number;assets_total:number;filters:Filters}
type Preview = {preview_token:string;expires_at:string;assets_selected:number;findings_selected:number;proposed_assets:number;unchanged:number;unchanged_fields:number;approval_conflicts:number;pending_conflicts:number;missing_evidence:string[];sample_items:Array<{asset_id:number;hostname:string;before:Record<string,unknown>;proposed:Record<string,unknown>;unchanged_fields:string[];pending_conflict:boolean}>}
type SelectionSummary = {assets_selected:number;findings_selected:number}
type ContextJob = {id:number;status:string;queued:number;processed:number;total:number;awaiting_approval:number;unchanged:number;conflicted:number;failed:number;errors:Array<{asset_id:number;error:string}>}

export default function ContextRequired({user}:{user:User}) {
  const [filters,setFilters] = useState<Filters>(emptyFilters)
  const [draftFilters,setDraftFilters] = useState<Filters>(emptyFilters), [filtersOpen,setFiltersOpen] = useState(false)
  const [data,setData] = useState<Result>()
  const [offset,setOffset] = useState(0), [refresh,setRefresh] = useState(0)
  const [loading,setLoading] = useState(true), [error,setError] = useState('')
  const [selected,setSelected] = useState<number[]>([]), [all,setAll] = useState(false)
  const [excluded,setExcluded] = useState<number[]>([])
  const [selectionSummary,setSelectionSummary] = useState<SelectionSummary>(), [selectionLoading,setSelectionLoading] = useState(false)
  const [step,setStep] = useState(0), [busy,setBusy] = useState(false)
  const [changes,setChanges] = useState<Record<string,unknown>>({})
  const [justification,setJustification] = useState(''), [evidence,setEvidence] = useState('')
  const [preview,setPreview] = useState<Preview>(), [confirmed,setConfirmed] = useState(false)
  const [message,setMessage] = useState('')
  const [job,setJob] = useState<ContextJob>()
  const [reviewsOpen,setReviewsOpen] = useState(false)
  useEffect(()=>{
    if(user.role==='Viewer')return
    let active = true
    api<{items:ContextJob[]}>('/smart-assessment/context-required/jobs')
      .then(result=>{if(active&&result.items.length)setJob(result.items[0])})
      .catch(()=>{})
    return ()=>{active=false}
  },[user.role])
  function clearSelection() { setSelected([]);setAll(false);setExcluded([]);setSelectionSummary(undefined);setPreview(undefined);setConfirmed(false);setStep(0) }
  function changeFilters(next:Filters) { setDraftFilters(next);setFilters(next);setOffset(0);setLoading(true);clearSelection() }
  useEffect(()=>{
    const controller = new AbortController()
    setLoading(true);setError('')
    api<Result>(`/smart-assessment/context-required?${new URLSearchParams({...filters,limit:'100',offset:String(offset)})}`,{signal:controller.signal})
      .then(result=>{if(!controller.signal.aborted)setData(result)})
      .catch(cause=>{if(!controller.signal.aborted){setError(cause.message);setData(undefined);clearSelection()}})
      .finally(()=>{if(!controller.signal.aborted)setLoading(false)})
    return ()=>controller.abort()
  },[filters,offset,refresh])
  useEffect(()=>{
    if(!all&&!selected.length){setSelectionSummary(undefined);setSelectionLoading(false);return}
    const controller = new AbortController()
    setSelectionLoading(true);setSelectionSummary(undefined)
    api<SelectionSummary>('/smart-assessment/context-required/selection-summary',{method:'POST',signal:controller.signal,
      body:JSON.stringify(selectionPayload({all,selected,excluded},filters))})
      .then(result=>{if(!controller.signal.aborted)setSelectionSummary(result)})
      .catch(cause=>{if(!controller.signal.aborted)setError((cause as Error).message)})
      .finally(()=>{if(!controller.signal.aborted)setSelectionLoading(false)})
    return ()=>controller.abort()
  },[all,selected,excluded,filters,refresh])
  useEffect(()=>{
    if(!job || !['Queued','Running','Cancel requested'].includes(job.status))return
    const timer = window.setInterval(()=>api<ContextJob>(`/smart-assessment/context-required/jobs/${job.id}`)
      .then(result=>setJob(result)).catch(cause=>setError((cause as Error).message)),2000)
    return ()=>window.clearInterval(timer)
  },[job?.id,job?.status])
  const count = selectionSummary?.assets_selected || 0
  const selection = () => selectionPayload({all,selected,excluded},filters)
  async function next() {
    setError('')
    if(step===1){setStep(2);return}
    if(step===3){setConfirmed(false);setStep(4);return}
    if(!Object.keys(changes).length || !justification.trim() || !evidence.trim()){
      setError('Select a context field and provide a rationale and evidence reference.');return
    }
    setBusy(true)
    try {
      if(step===2){
        setPreview(await api<Preview>('/smart-assessment/context-required/bulk-classify',{method:'POST',body:JSON.stringify({...selection(),changes,justification,evidence,dry_run:true})}))
        setStep(3)
      } else {
        const result = await api<any>('/smart-assessment/context-required/bulk-classify',{method:'POST',body:JSON.stringify({...selection(),changes,justification,evidence,preview_token:preview?.preview_token,confirmed})})
        if(result.job_id){
          const queued = await api<ContextJob>(`/smart-assessment/context-required/jobs/${result.job_id}`)
          setJob(queued)
          setMessage(`Classification job #${result.job_id} queued for ${result.assets_selected} assets. Owner validation and independent GRC approval remain required.`)
        } else setMessage(`${result.requests_created} classification requests submitted. Assign independent owner and GRC reviewers in the asset classification review queue; approved asset context remains unchanged until review.`)
        clearSelection();setChanges({});setJustification('');setEvidence('');setLoading(true);setRefresh(v=>v+1)
      }
    } catch(cause) {
      setError((cause as Error).message)
      if(step===4 && String((cause as Error).message).toLowerCase().includes('preview')) {setPreview(undefined);setConfirmed(false);setStep(2)}
    } finally {setBusy(false)}
  }
  function setChange(key:string,value:unknown) {
    setChanges(previous=>{const next={...previous};if(value==='' || value===undefined)delete next[key];else next[key]=value;return next})
    setPreview(undefined);setConfirmed(false)
  }
  const filterSelect = (key:keyof Filters,label:string,options:string[]) => <label>{label}<select aria-label={label} value={draftFilters[key]} onChange={e=>setDraftFilters(previous=>({...previous,[key]:e.target.value}))}><option value="">Any</option>{options.map(value=><option key={value}>{value}</option>)}</select></label>
  return <section className="panel">
    <ErrorBox error={error}/>{message&&<p role="status">{message}</p>}
    {job&&<div role="status" aria-live="polite" className="notice"><strong>Classification job #{job.id}: {job.status}</strong><p>{job.queued} queued · {job.processed} processed / {job.total} · {job.awaiting_approval} awaiting approval · {job.unchanged} unchanged · {job.conflicted} conflicted · {job.failed} failed</p>{job.errors.length>0&&<details><summary>Show first {job.errors.length} errors</summary>{job.errors.map((item,index)=><p key={`${item.asset_id}-${index}`}>Asset #{item.asset_id}: {item.error}</p>)}</details>}{['Queued','Running'].includes(job.status)&&<button onClick={async()=>{try{setJob(await api<ContextJob>(`/smart-assessment/context-required/jobs/${job.id}/cancel`,{method:'POST'}))}catch(cause){setError((cause as Error).message)}}}>Cancel job</button>}{['Completed with errors','Canceled'].includes(job.status)&&<button onClick={async()=>{try{setJob(await api<ContextJob>(`/smart-assessment/context-required/jobs/${job.id}/retry`,{method:'POST'}))}catch(cause){setError((cause as Error).message)}}}>Retry unresolved assets</button>}</div>}
    <div className="section-head"><div><h2>Missing authoritative context</h2><p>{data?.total.toLocaleString() || 0} findings across {data?.assets_total.toLocaleString() || 0} unique assets await classification.</p></div>
      {user.role!=='Viewer'&&<div className="actions"><button disabled={loading||!data?.items.length} onClick={()=>{const next=selectPage({all,selected,excluded},(data?.items||[]).map(row=>row.asset.id));setAll(next.all);setSelected(next.selected);setExcluded(next.excluded);setPreview(undefined)}}>Select page</button><button disabled={loading||!data?.assets_total} onClick={()=>{setAll(true);setSelected([]);setExcluded([]);setPreview(undefined)}}>Select all matching results</button><button disabled={busy} onClick={clearSelection}>Clear selection</button><button className="primary" disabled={loading||selectionLoading||!count} onClick={()=>{setStep(1);setPreview(undefined);setConfirmed(false)}}>Bulk Classify Assets</button></div>}
    </div>
    <form className="actions" onSubmit={e=>{e.preventDefault();changeFilters(draftFilters)}}><label className="wide">Search hostname, IP, OS, plugin ID/name or subcategory<input value={draftFilters.q} onChange={e=>setDraftFilters(previous=>({...previous,q:e.target.value}))}/></label><button type="button" aria-expanded={filtersOpen} onClick={()=>setFiltersOpen(open=>!open)}>{filtersOpen?'Hide filters':'Filter'}</button><button type="submit">Search</button></form>
    {filtersOpen&&<div className="form-grid" aria-label="Context filters">
      {filterSelect('subcategory','Subcategory',subcategories)}
      <label>Operating system<input value={draftFilters.os} onChange={e=>setDraftFilters(previous=>({...previous,os:e.target.value}))}/></label>
      <label>Device type<input value={draftFilters.device_type} onChange={e=>setDraftFilters(previous=>({...previous,device_type:e.target.value}))}/></label>
      {filterSelect('missing_field','Missing context field',['asset_criticality','business_criticality','data_classification','environment','exposure','regulatory'])}
      <label>RACI owner<input value={draftFilters.raci_owner} placeholder="Exact owner or Unassigned" onChange={e=>setDraftFilters(previous=>({...previous,raci_owner:e.target.value}))}/></label>
      <label>Asset tag<input value={draftFilters.tag} placeholder="Exact tag or category:value" onChange={e=>setDraftFilters(previous=>({...previous,tag:e.target.value}))}/></label>
      {filterSelect('environment','Environment',environments)}{filterSelect('regulatory','Regulatory scope',scopes)}
      <button onClick={()=>changeFilters({...emptyFilters})}>Clear filters</button><button className="primary" onClick={()=>changeFilters(draftFilters)}>Apply filters</button>
    </div>}
    <p role="status">{loading?'Loading matching findings…':selectionLoading?'Counting selected assets and findings…':`${count.toLocaleString()} distinct assets and ${(selectionSummary?.findings_selected||0).toLocaleString()} affected findings selected${all?' across all matching pages':''}${excluded.length?` (${excluded.length} excluded)`:''}.`}</p>
    {!loading&&<div className="table-scroll"><table><thead><tr><th>Select asset</th><th>Category</th><th>Asset</th><th>Missing fields</th><th>Status</th></tr></thead><tbody>
      {data?.items.map(row=><tr key={row.finding_id}><td><input type="checkbox" aria-label={`Select asset ${row.asset.hostname} for finding ${row.finding_id}`} disabled={user.role==='Viewer'} checked={all?!excluded.includes(row.asset.id):selected.includes(row.asset.id)} onChange={e=>{const next=toggleAsset({all,selected,excluded},row.asset.id,e.target.checked);setSelected(next.selected);setExcluded(next.excluded);setPreview(undefined)}}/></td><td>{row.category}</td><td><strong>{row.asset.hostname}</strong><small>{row.asset.ip||'IP unknown'} · {row.asset.os||'OS unknown'}</small></td><td>{row.missing_fields.join(', ')}</td><td><Badge>Technical Completed · Context Required</Badge></td></tr>)}
      {!data?.items.length&&<tr><td colSpan={5}>No matching findings.</td></tr>}
    </tbody></table></div>}
    <div className="actions"><button disabled={loading||offset===0} onClick={()=>{setLoading(true);setOffset(v=>v-100)}}>Previous</button><span>{data?.total?offset+1:0}–{Math.min(offset+100,data?.total||0)} of {data?.total||0} findings</span><button disabled={loading||offset+100>=(data?.total||0)} onClick={()=>{setLoading(true);setOffset(v=>v+100)}}>Next</button><button disabled={loading} onClick={()=>{clearSelection();setLoading(true);setRefresh(v=>v+1)}}>Refresh</button></div>
    {user.role!=='Viewer'&&<><button onClick={()=>setReviewsOpen(value=>!value)}>{reviewsOpen?'Hide':'Open'} owner / GRC review queue</button>{reviewsOpen&&<ContextClassificationReviews user={user} onApplied={()=>{clearSelection();setLoading(true);setRefresh(value=>value+1)}}/>}</>}
    {step>0&&<div className="modal-backdrop"><div className="modal wide-modal" role="dialog" aria-modal="true" aria-labelledby="bulk-context-title">
      <div className="section-head"><h2 id="bulk-context-title">Bulk classify assets</h2><button disabled={busy} onClick={()=>setStep(0)}>Close</button></div><ErrorBox error={error}/>
      <div className="chips">{['Select Assets','Set Missing Context','Preview','Submit for Approval'].map((label,i)=><span key={label} className={step===i+1?'chip checked':'chip'}>{i+1}. {label}</span>)}</div>
      {step===1&&<p>{count.toLocaleString()} unique assets and {(selectionSummary?.findings_selected||0).toLocaleString()} affected findings selected{all?' across all matching pages':''}. The server will verify the cohort before submission. Approved values remain protected.</p>}
      {step===2&&<fieldset disabled={busy}><div className="form-grid">{fields.map(([key,label,options])=><label key={key}>{label}<select aria-label={label} value={String(changes[key]||'')} onChange={e=>setChange(key,e.target.value)}><option value="">Leave unchanged</option>{options.map(value=><option key={value}>{value}</option>)}</select></label>)}
        <label>Regulatory scope<select aria-label="Regulatory scope" value={Array.isArray(changes.regulatory)?changes.regulatory.join(','):''} onChange={e=>setChange('regulatory',e.target.value?[e.target.value]:undefined)}><option value="">Leave unchanged</option>{scopes.map(value=><option key={value}>{value}</option>)}</select></label>
        <label>Justification<textarea maxLength={5000} value={justification} onChange={e=>setJustification(e.target.value)}/></label><label>Evidence reference<input maxLength={10000} value={evidence} onChange={e=>setEvidence(e.target.value)}/></label>
      </div></fieldset>}
      {step>=3&&preview&&<><p>{preview.findings_selected.toLocaleString()} findings across {preview.assets_selected.toLocaleString()} unique assets verified. {preview.proposed_assets} assets will have proposals, {preview.unchanged} assets and {preview.unchanged_fields} selected fields remain unchanged. {preview.approval_conflicts} approved field changes require independent review; {preview.pending_conflicts} assets have overlapping pending requests and may be skipped.</p>{preview.missing_evidence.length>0&&<p className="error-text">Missing: {preview.missing_evidence.join(', ')}</p>}<p>Evidence: {evidence}. Justification: {justification}.</p><details><summary>Preview first {preview.sample_items.length} selected assets</summary><div className="table-scroll"><table><thead><tr><th>Asset</th><th>Before</th><th>Proposed</th><th>Unchanged fields</th><th>Conflict</th></tr></thead><tbody>{preview.sample_items.map(item=><tr key={item.asset_id}><td>{item.hostname}</td><td>{JSON.stringify(item.before)}</td><td>{JSON.stringify(item.proposed)}</td><td>{item.unchanged_fields.join(', ')||'—'}</td><td>{item.pending_conflict?'Pending approval':'—'}</td></tr>)}</tbody></table></div></details></>}
      {step===4&&<label><input type="checkbox" checked={confirmed} onChange={e=>setConfirmed(e.target.checked)}/>I confirm the verified cohort and proposed changes. Submit requests for independent owner validation followed by GRC approval. Live context changes only after approval.</label>}
      <div className="actions"><button disabled={step===1||busy} onClick={()=>{setStep(v=>v-1);setConfirmed(false);if(step===3)setPreview(undefined)}}>Back</button><button className="primary" disabled={busy||(step===4&&(!confirmed||!preview||!preview.proposed_assets||preview.missing_evidence.length>0))} onClick={next}>{busy?'Working…':step===4?'Confirm and submit for approval':'Next'}</button></div>
    </div></div>}
  </section>
}
