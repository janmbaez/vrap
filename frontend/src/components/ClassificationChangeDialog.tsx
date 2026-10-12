import { FormEvent, useEffect, useState } from 'react'
import { CheckCircle2, FileText, ShieldCheck, X } from 'lucide-react'
import { api } from '../api'
import { ErrorBox } from './UI'

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
  function toggleScope(scope: string, checked: boolean) {
    setSelectedScopes(values => checked ? [...values, scope] : values.filter(value => value !== scope))
  }
  async function saveDraft(nextStep = step) {
    setError(''); setBusy(true)
    try {
      await api(`/assets/${asset.id}/classification-mission`, { method: 'PUT', body: JSON.stringify({
        current_step: nextStep, responses: { classification: { context, regulatory: selectedScopes, owners } },
      }) })
      setStep(nextStep)
    } catch (cause) { setError((cause as Error).message) } finally { setBusy(false) }
  }
  async function goNext() { await saveDraft(Math.min(5, step + 1)) }
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
  return <div className="modal-backdrop" role="presentation"><form className="modal wide-modal" onSubmit={submit} aria-labelledby="classification-change-title"><div className="section-head"><div><h2 id="classification-change-title">Asset classification quest</h2><p>{asset.hostname} · protected values require an independent administrator decision.</p></div><button type="button" onClick={onClose} aria-label="Close"><X size={18}/></button></div><div className="chips" aria-label="Quest progress">{steps.map((name, index) => <span className={'chip '+(step === index + 1 ? 'checked' : '')} key={name}>{index + 1}. {name}</span>)}</div><ErrorBox error={error}/><div className="notice warning"><ShieldCheck size={16}/> Saving this quest preserves a draft only. Submission requests review; it never changes the live asset by itself.</div>{step === 1 && <section className="form-grid"><div className="wide"><h3>1. Asset identity & ownership</h3><p>Confirm the asset identity and propose accountable owners when they need validation.</p><dl className="details-list"><dt>Hostname</dt><dd>{asset.hostname}</dd><dt>IP address</dt><dd>{asset.ip || 'Unknown'}</dd></dl></div>{[['business_owner','Business owner'],['it_owner','IT owner / remediator'],['application_owner','Application owner / remediator'],['asset_group','Asset group']].map(([key,title])=><label key={key}>{title}<input value={owners[key]||''} maxLength={200} placeholder={initial[key]||'Needs owner validation'} onChange={event=>setOwners(values=>({...values,[key]:event.target.value}))}/></label>)}</section>}{step === 2 && <section className="form-grid"><div className="wide"><h3>2. Business function & impact</h3><p className="helper">Record the business impact classification supported by a BIA or asset owner.</p></div>{select('business_criticality')}{select('asset_criticality')}</section>}{step === 3 && <section className="form-grid"><div className="wide"><h3>3. Data classification & regulatory membership</h3></div>{select('data_classification')}<div className="wide field-group"><label>Regulatory memberships</label><div className="chips">{scopes.map(scope => <label className="chip" key={scope}><input type="checkbox" checked={selectedScopes.includes(scope)} onChange={event => toggleScope(scope, event.target.checked)}/>{scope}</label>)}</div><p className="helper">Removing a membership is always routed through independent review.</p></div></section>}{step === 4 && <section className="form-grid"><div className="wide"><h3>4. Exposure & operating environment</h3><p className="helper">Use Unknown by leaving a value unchanged; do not guess a verified value.</p></div>{select('environment')}{select('exposure')}</section>}{step === 5 && <section className="form-grid"><div className="wide"><h3>5. Review and submit</h3><p className="helper">The administrator sees the before/proposed diff, your rationale and evidence. Approved changes flag linked findings for reassessment.</p></div><div className="wide"><pre>{JSON.stringify({ proposed_context: { ...context, ...owners }, proposed_regulatory: selectedScopes }, null, 2)}</pre></div><label className="wide">Business justification *<textarea name="justification" required minLength={1} maxLength={5000} rows={3} placeholder="Why should the authoritative classification change?"/></label><label className="wide">Evidence references<input name="evidence" maxLength={10000} placeholder="CMDB, BIA, owner attestation, ticket, or review reference"/></label></section>}<div className="actions"><button type="button" onClick={onClose} disabled={busy}>Cancel</button><button type="button" onClick={() => saveDraft()} disabled={busy}>Save draft</button>{step > 1 && <button type="button" onClick={() => setStep(step - 1)} disabled={busy}>Back</button>}{step < 5 ? <button className="primary" disabled={busy}>{busy ? 'Saving…' : 'Save & continue'}</button> : <button className="primary" disabled={busy}><FileText size={16}/>{busy ? 'Submitting…' : 'Submit for approval'}</button>}</div></form></div>
}

export function ClassificationChangeReviewQueue({ onApplied }: { onApplied: () => void }) {
  const [rows, setRows] = useState<any[]>([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState<number | null>(null)
  const [reasons, setReasons] = useState<Record<number, string>>({})
  const load = () => api<any[]>('/classification-change-requests?status=Requested').then(setRows).catch(cause => setError((cause as Error).message))
  // The queue is intentionally a small, explicit reviewer surface rather than
  // an automatic approval hidden inside an asset form.
  useEffect(() => { load() }, [])
  async function decide(row: any, status: 'Approved' | 'Rejected') {
    const justification = reasons[row.id]?.trim()
    if (!justification) { setError('Enter a decision rationale before approving or rejecting.'); return }
    setBusy(row.id); setError('')
    try {
      await api(`/classification-change-requests/${row.id}`, { method: 'PUT', body: JSON.stringify({ status, justification }) })
      setRows(values => values.filter(value => value.id !== row.id)); onApplied()
    } catch (cause) { setError((cause as Error).message) } finally { setBusy(null) }
  }
  return <section className="panel table-panel"><div className="section-head"><div><h2>Classification change review queue</h2><p>Approve or reject protected asset changes with an auditable reviewer rationale.</p></div><button onClick={load}>Refresh</button></div><ErrorBox error={error}/>{rows.length ? <div className="table-scroll"><table><thead><tr><th>Asset</th><th>Requested change</th><th>Evidence</th><th>Decision rationale</th><th></th></tr></thead><tbody>{rows.map(row => <tr key={row.id}><td><strong className="mono">{row.asset_hostname}</strong><small>Request #{row.id} · {new Date(row.created_at).toLocaleString()}</small></td><td><details><summary>View before / proposed</summary><pre>{JSON.stringify({ before: row.before_context, proposed: row.proposed_context }, null, 2)}</pre></details><small>{row.justification}</small></td><td>{row.evidence || 'No reference supplied'}</td><td><textarea aria-label={`Decision rationale for request ${row.id}`} rows={2} maxLength={5000} value={reasons[row.id] || ''} onChange={event => setReasons(values => ({ ...values, [row.id]: event.target.value }))} placeholder="Required reviewer rationale"/></td><td><div className="actions"><button className="primary" disabled={busy === row.id} onClick={() => decide(row, 'Approved')}><CheckCircle2 size={15}/>Approve</button><button disabled={busy === row.id} onClick={() => decide(row, 'Rejected')}>Reject</button></div></td></tr>)}</tbody></table></div> : <p className="helper">No pending classification changes in this environment.</p>}</section>
}
