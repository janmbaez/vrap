import { FormEvent, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { CheckCircle2, FileText, ShieldCheck, X } from 'lucide-react'
import { api } from '../api'
import { ErrorBox, Loading } from './UI'

const fields = [
  ['asset_criticality', 'Asset criticality', ['Low', 'Medium', 'High', 'Critical']],
  ['business_criticality', 'Business criticality', ['Low', 'Medium', 'High', 'Critical']],
  ['data_classification', 'Data classification', ['Public', 'Internal', 'Confidential', 'Restricted']],
  ['environment', 'Environment', ['Development', 'Test', 'QA', 'Staging', 'Production']],
  ['exposure', 'Exposure', ['Internet Facing', 'Internal', 'Restricted Network', 'Isolated']],
] as const
const scopes = ['PCI DSS', 'SOC 2', 'SOX', 'HIPAA', 'GDPR', 'Other']

export function ClassificationChangeDialog({ asset, onClose, onSubmitted }: { asset: any; onClose: () => void; onSubmitted: () => void }) {
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [step, setStep] = useState(1)
  const initial = asset.context || {}
  const [context, setContext] = useState<Record<string, string>>(() => Object.fromEntries(fields.map(([key]) => [key, initial[key] || ''])))
  const [selectedScopes, setSelectedScopes] = useState<string[]>(initial.regulatory || [])
  const [owners, setOwners] = useState<Record<string, string>>(() => ({ business_owner: initial.business_owner || '', it_owner: initial.it_owner || '', application_owner: initial.application_owner || '', asset_group: initial.asset_group || '' }))
  const [evidence, setEvidence] = useState<any[]>([])
  const [evidenceType, setEvidenceType] = useState('BIA')
  const [evidenceReference, setEvidenceReference] = useState('')
  const steps = ['Identity', 'Business context', 'Data & scope', 'Exposure', 'Review']

  useEffect(() => {
    api<any>(`/assets/${asset.id}/classification-mission`).then(mission => {
      const draft = mission?.responses?.classification
      if (!draft) return
      if (draft.context) setContext(values => ({ ...values, ...draft.context }))
      if (Array.isArray(draft.regulatory)) setSelectedScopes(draft.regulatory)
      if (draft.owners) setOwners(values => ({ ...values, ...draft.owners }))
      if (mission.current_step) setStep(mission.current_step)
    }).catch(() => undefined)
  }, [asset.id])
  useEffect(() => { api<any[]>(`/assets/${asset.id}/classification-mission/evidence`).then(setEvidence).catch(() => undefined) }, [asset.id])
  function toggleScope(scope: string, checked: boolean) {
    setSelectedScopes(values => checked ? [...values, scope] : values.filter(value => value !== scope))
  }
  async function saveDraft(nextStep = step) {
    setError(''); setBusy(true)
    try {
      const answers = {
        'identity.business_owner': owners.business_owner, 'identity.it_owner': owners.it_owner,
        'identity.application_owner': owners.application_owner, 'business.criticality': context.business_criticality,
        'business.asset_criticality': context.asset_criticality, 'data.classification': context.data_classification,
        'scope.regulatory': selectedScopes, 'exposure.environment': context.environment, 'exposure.network': context.exposure,
      }
      await api(`/assets/${asset.id}/classification-mission`, { method: 'PUT', body: JSON.stringify({
        current_step: nextStep, responses: { classification: { context, regulatory: selectedScopes, owners, answers } },
      }) })
      setStep(nextStep)
      return true
    } catch (cause) { setError((cause as Error).message) } finally { setBusy(false) }
    return false
  }
  async function goNext() { await saveDraft(Math.min(5, step + 1)) }
  async function attachEvidence() {
    if (!evidenceReference.trim()) { setError('Enter an evidence reference first.'); return }
    if (!await saveDraft(5)) return
    setBusy(true)
    try {
      const added = await api<any>(`/assets/${asset.id}/classification-mission/evidence`, { method: 'POST', body: JSON.stringify({ evidence_type: evidenceType, reference: evidenceReference.trim() }) })
      setEvidence(rows => [added, ...rows]); setEvidenceReference('')
    } catch (cause) { setError((cause as Error).message) } finally { setBusy(false) }
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setError('')
    if (step !== 5) { await goNext(); return }
    const form = new FormData(event.currentTarget)
    const changes: Record<string, unknown> = {}
    for (const [key] of fields) if (context[key] && context[key] !== (initial[key] || '')) changes[key] = context[key]
    for (const [key, value] of Object.entries(owners)) if (value && value !== (initial[key] || '')) changes[key] = value
    const currentScopes = [...(initial.regulatory || [])].sort().join('|')
    const nextScopes = [...selectedScopes].sort().join('|')
    if (currentScopes !== nextScopes) changes.regulatory = selectedScopes.length ? selectedScopes : ['None']
    if (!Object.keys(changes).length) { setError('Choose at least one changed classification value.'); return }
    setBusy(true)
    try {
      await api(`/assets/${asset.id}/classification-change-requests`, { method: 'POST', body: JSON.stringify({
        changes, expected_context_version: asset.context_version,
        justification: String(form.get('justification') || ''), evidence: String(form.get('evidence') || ''),
      }) })
      onSubmitted()
    } catch (cause) { setError((cause as Error).message) } finally { setBusy(false) }
  }
  const field = (key: string) => fields.find(([name]) => name === key)!
  const select = (key: string) => { const [, title, options] = field(key); return <label key={key}>{title}<select value={context[key]} onChange={event => setContext(values => ({ ...values, [key]: event.target.value }))}><option value="">Keep current ({initial[key] || 'Unknown'})</option>{options.map(value => <option key={value}>{value}</option>)}</select></label> }
  return <div className="modal-backdrop" role="presentation"><form className="modal wide-modal" onSubmit={submit} aria-labelledby="classification-change-title"><div className="section-head"><div><h2 id="classification-change-title">Asset classification quest</h2><p>{asset.hostname} · protected values require an independent administrator decision.</p></div><button type="button" onClick={onClose} aria-label="Close"><X size={18}/></button></div><div className="chips" aria-label="Quest progress">{steps.map((name, index) => <span className={'chip '+(step === index + 1 ? 'checked' : '')} key={name}>{index + 1}. {name}</span>)}</div><ErrorBox error={error}/><div className="notice warning"><ShieldCheck size={16}/> Saving this quest preserves a draft only. Submission requests review; it never changes the live asset by itself.</div>{step === 1 && <section className="form-grid"><div className="wide"><h3>1. Asset identity & ownership</h3><p>Confirm the asset identity and propose accountable owners when they need validation.</p><dl className="details-list"><dt>Hostname</dt><dd>{asset.hostname}</dd><dt>IP address</dt><dd>{asset.ip || 'Unknown'}</dd></dl></div>{[['business_owner','Business owner'],['it_owner','IT owner / remediator'],['application_owner','Application owner / remediator'],['asset_group','Asset group']].map(([key,title])=><label key={key}>{title}<input value={owners[key]||''} maxLength={200} placeholder={initial[key]||'Needs owner validation'} onChange={event=>setOwners(values=>({...values,[key]:event.target.value}))}/></label>)}</section>}{step === 2 && <section className="form-grid"><div className="wide"><h3>2. Business function & impact</h3><p className="helper">Record the business impact classification supported by a BIA or asset owner.</p></div>{select('business_criticality')}{select('asset_criticality')}</section>}{step === 3 && <section className="form-grid"><div className="wide"><h3>3. Data classification & regulatory membership</h3></div>{select('data_classification')}<div className="wide field-group"><label>Regulatory memberships</label><div className="chips">{scopes.map(scope => <label className="chip" key={scope}><input type="checkbox" checked={selectedScopes.includes(scope)} onChange={event => toggleScope(scope, event.target.checked)}/>{scope}</label>)}</div><p className="helper">Removing a membership is always routed through independent review.</p></div></section>}{step === 4 && <section className="form-grid"><div className="wide"><h3>4. Exposure & operating environment</h3><p className="helper">Use Unknown by leaving a value unchanged; do not guess a verified value.</p></div>{select('environment')}{select('exposure')}</section>}{step === 5 && <section className="form-grid"><div className="wide"><h3>5. Review and submit</h3><p className="helper">The administrator sees the before/proposed diff, your rationale and evidence. Approved changes flag linked findings for reassessment.</p></div><div className="wide"><pre>{JSON.stringify({ proposed_context: { ...context, ...owners }, proposed_regulatory: selectedScopes }, null, 2)}</pre></div><label className="wide">Business justification *<textarea name="justification" required minLength={1} maxLength={5000} rows={3} placeholder="Why should the authoritative classification change?"/></label><label className="wide">Request evidence summary<input name="evidence" maxLength={10000} placeholder="CMDB, BIA, owner attestation, ticket, or review reference"/></label><div className="wide field-group"><label>Attach governed evidence reference</label><div className="actions"><select value={evidenceType} onChange={event=>setEvidenceType(event.target.value)}>{['BIA','CMDB','owner_attestation','data_inventory','GRC_scope','network_evidence','other'].map(value=><option key={value}>{value}</option>)}</select><input value={evidenceReference} maxLength={10000} onChange={event=>setEvidenceReference(event.target.value)} placeholder="Evidence identifier or URL"/><button type="button" onClick={attachEvidence} disabled={busy}>Attach</button></div>{evidence.length>0&&<ul>{evidence.map(row=><li key={row.id}>{row.evidence_type}: {row.reference}</li>)}</ul>}</div></section>}<div className="actions"><button type="button" onClick={onClose} disabled={busy}>Cancel</button><button type="button" onClick={() => saveDraft()} disabled={busy}>Save draft</button>{step > 1 && <button type="button" onClick={() => setStep(step - 1)} disabled={busy}>Back</button>}{step < 5 ? <button className="primary" disabled={busy}>{busy ? 'Saving…' : 'Save & continue'}</button> : <button className="primary" disabled={busy}><FileText size={16}/>{busy ? 'Submitting…' : 'Submit for approval'}</button>}</div></form></div>
}

export function ClassificationChangeReviewQueue({ onApplied }: { onApplied: () => void }) {
  const navigate = useNavigate()
  const [rows, setRows] = useState<any[]>([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState<number | null>(null)
  const [reasons, setReasons] = useState<Record<number, string>>({})
  const [selected, setSelected] = useState<number[]>([])
  const [bulkOpen, setBulkOpen] = useState(false)
  const [bulkReason, setBulkReason] = useState('')
  const [bulkStatus, setBulkStatus] = useState<'Approved' | 'Rejected'>('Approved')
  const [bulkBusy, setBulkBusy] = useState(false)
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(0)
  const [maxId, setMaxId] = useState<number | null>(null)
  const [selectionMaxId, setSelectionMaxId] = useState<number | null>(null)
  const [selectionTotal, setSelectionTotal] = useState(0)
  const [allPending, setAllPending] = useState(false)
  const [excluded, setExcluded] = useState<number[]>([])
  const selectedCount = allPending ? Math.max(0, selectionTotal - excluded.length) : selected.length
  const isSelected = (id: number) => allPending ? id <= (selectionMaxId || 0) && !excluded.includes(id) : selected.includes(id)
  const toggle = (id: number, checked: boolean) => {
    if (allPending) setExcluded(values => checked ? values.filter(value => value !== id) : [...new Set([...values, id])])
    else setSelected(values => checked ? [...new Set([...values, id])] : values.filter(value => value !== id))
  }
  const load = () => api<any>(`/classification-change-requests?status=Requested&limit=100&offset=${page * 100}`).then(result => { setRows(result.items); setTotal(result.total); setMaxId(result.max_id) }).catch(cause => setError((cause as Error).message))
  // The queue is intentionally a small, explicit reviewer surface rather than
  // an automatic approval hidden inside an asset form.
  useEffect(() => { load() }, [page])
  async function decide(row: any, status: 'Approved' | 'Rejected') {
    const justification = reasons[row.id]?.trim()
    if (!justification) { setError('Enter a decision rationale before approving or rejecting.'); return }
    setBusy(row.id); setError('')
    try {
      await api(`/classification-change-requests/${row.id}`, { method: 'PUT', body: JSON.stringify({ status, justification }) })
      load(); onApplied()
    } catch (cause) { setError((cause as Error).message); load() } finally { setBusy(null) }
  }
  const [decisionJob,setDecisionJob] = useState<any>()
  const [jobId,setJobId] = useState<number>(()=>Number(sessionStorage.getItem('classificationDecisionJob')||0))
  useEffect(()=>{
    if(!jobId)return
    let live=true
    const poll=async()=>{
      try{
        const result=await api<any>(`/classification-decision-jobs/${jobId}`)
        if(!live)return
        setDecisionJob(result)
        if(result.status.startsWith('Completed') || result.status === 'Blocked'){
          sessionStorage.removeItem('classificationDecisionJob');setJobId(0);load();onApplied()
        }
      }catch(cause){if(live)setError(`Progress unavailable; the server job continues. ${(cause as Error).message}`)}
    }
    poll();const timer=setInterval(poll,3000)
    return()=>{live=false;clearInterval(timer)}
  },[jobId])
  async function decideBulk() {
    const rationale = bulkReason.trim()
    if (!rationale) { setError('Enter one decision rationale for the selected requests.'); return }
    setBulkBusy(true); setError('')
    try {
      const submission = {request_ids: allPending ? [] : selected, all_pending: allPending, through_id: allPending ? selectionMaxId : null, excluded_ids: allPending ? excluded : [], status:bulkStatus, justification:rationale}
      const fingerprint = JSON.stringify(submission)
      const previous = sessionStorage.getItem('classificationSubmissionFingerprint')
      const key = previous === fingerprint && sessionStorage.getItem('classificationSubmissionKey') || Array.from(crypto.getRandomValues(new Uint32Array(4)), value => value.toString(16).padStart(8, '0')).join('')
      sessionStorage.setItem('classificationSubmissionKey',key)
      sessionStorage.setItem('classificationSubmissionFingerprint',fingerprint)
      const result=await api<any>('/classification-decision-jobs',{method:'POST',body:JSON.stringify({...submission,idempotency_key:key})})
      sessionStorage.removeItem('classificationSubmissionKey'); sessionStorage.removeItem('classificationSubmissionFingerprint')
      sessionStorage.setItem('classificationDecisionJob',String(result.id))
      setJobId(result.id);setDecisionJob(result);setSelected([]);setAllPending(false);setExcluded([]);setBulkOpen(false);setBulkReason('')
    }catch(cause){setError((cause as Error).message)}finally{setBulkBusy(false)}
  }
  return <><section className="panel table-panel"><div className="section-head"><div><h2>Classification change review queue</h2><p>Approve or reject protected asset changes with an auditable reviewer rationale.</p></div><div className="actions"><button onClick={()=>{setAllPending(true);setSelectionMaxId(maxId);setSelectionTotal(total);setSelected([]);setExcluded([])}} disabled={!total||!!jobId}>Select all pending</button>{selectedCount>0&&<button className="primary" onClick={()=>setBulkOpen(true)}>Review {selectedCount} selected</button>}<button onClick={load}>Refresh</button></div></div><ErrorBox error={error}/>{decisionJob&&<div role="status" className="notice"><strong>Approval job #{decisionJob.id}: {decisionJob.status}</strong>{['Queued','Running'].includes(decisionJob.status)&&<Loading compact>Reviewing requests…</Loading>}{decisionJob.status==='Blocked'&&<p className="warning-text">Approval stopped without consuming more requests. Bulk changes must be validated by an independent asset owner and approved by a different assigned GRC administrator. Sign in using the authorized reviewer account after owner validation, then submit a new job.</p>}<p>{decisionJob.processed} / {decisionJob.total} processed · {decisionJob.succeeded} saved · {decisionJob.skipped} already decided · {decisionJob.failed} failed</p>{decisionJob.errors?.length>0&&<details><summary>Request errors</summary>{decisionJob.errors.map((item:any)=><p key={item.request_id}>Request #{item.request_id}: {item.error}</p>)}</details>}</div>}{error&&<button onClick={()=>navigate('/assessments')}>Review missing context in Smart Assessment</button>}{rows.length ? <div className="table-scroll"><table><thead><tr><th><input type="checkbox" aria-label="Select all pending requests" checked={rows.length>0&&rows.every(row=>isSelected(row.id))} onChange={event=>rows.forEach(row=>toggle(row.id,event.target.checked))}/></th><th>Asset</th><th>Requested change</th><th>Evidence</th><th>Decision rationale</th><th></th></tr></thead><tbody>{rows.map(row => <tr key={row.id}><td><input type="checkbox" aria-label={`Select request ${row.id}`} checked={isSelected(row.id)} onChange={event=>toggle(row.id,event.target.checked)}/></td><td><strong className="mono">{row.asset_hostname}</strong><small>Request #{row.id} · {new Date(row.created_at).toLocaleString()}</small></td><td><details><summary>View before / proposed</summary><pre>{JSON.stringify({ before: row.before_context, proposed: row.proposed_context }, null, 2)}</pre></details><small>{row.justification}</small></td><td>{row.evidence || 'No reference supplied'}</td><td><textarea aria-label={`Decision rationale for request ${row.id}`} rows={2} maxLength={5000} value={reasons[row.id] || ''} onChange={event => setReasons(values => ({ ...values, [row.id]: event.target.value }))} placeholder="Required reviewer rationale"/></td><td><div className="actions"><button className="primary" disabled={busy === row.id} onClick={() => decide(row, 'Approved')}><CheckCircle2 size={15}/>Approve</button><button disabled={busy === row.id} onClick={() => decide(row, 'Rejected')}>Reject</button></div></td></tr>)}</tbody></table></div> : <p className="helper">No pending classification changes in this environment.</p>}<div className="actions"><button disabled={page===0} onClick={()=>setPage(page-1)}>Previous</button><span>{total ? page*100+1 : 0}–{Math.min((page+1)*100,total)} of {total}</span><button disabled={(page+1)*100>=total} onClick={()=>setPage(page+1)}>Next</button><button onClick={()=>{setSelected([]);setAllPending(false);setExcluded([])}} disabled={!selectedCount}>Clear selection</button></div></section>{bulkOpen&&<div className="modal-backdrop"><div className="modal" role="dialog" aria-modal="true"><div className="section-head"><h2>Bulk decision</h2><ErrorBox error={error}/><button onClick={()=>setBulkOpen(false)}>Close</button></div><p>Bulk classification requires an independent GRC reviewer and prior validation by a different asset owner. Your own bulk requests cannot be approved from this account.</p><p>Apply one decision and rationale to {selectedCount} selected requests. {allPending && 'Only requests present when selected will be included; already decided requests are skipped.'}</p><label>Decision<select value={bulkStatus} onChange={event=>setBulkStatus(event.target.value as any)}><option value="Approved">Approve</option><option value="Rejected">Reject</option></select></label><label>Decision rationale *<textarea autoFocus value={bulkReason} onChange={event=>setBulkReason(event.target.value)} placeholder="Explain this decision for all selected requests"/></label><div className="actions"><button onClick={()=>setBulkOpen(false)} disabled={bulkBusy||!!jobId}>Cancel</button><button className="primary" onClick={decideBulk} disabled={bulkBusy||!!jobId}>{bulkBusy?'Submitting…':bulkStatus==='Approved'?'Approve selected':'Reject selected'}</button></div></div></div>}</>
}
