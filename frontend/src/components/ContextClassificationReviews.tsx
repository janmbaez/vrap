import { useEffect, useState } from 'react'
import { api, User } from '../api'
import { ErrorBox } from './UI'

// This queue is limited to Context Required proposals. Individual classification
// requests retain their existing review surface and policy.
export default function ContextClassificationReviews({user,onApplied}:{user:User;onApplied:()=>void}) {
  const [data,setData] = useState<{items:any[];total:number}>({items:[],total:0})
  const [users,setUsers] = useState<User[]>([]), [offset,setOffset] = useState(0)
  const [error,setError] = useState(''), [busy,setBusy] = useState(false)
  const [reasons,setReasons] = useState<Record<number,string>>({}), [evidence,setEvidence] = useState<Record<number,string>>({})
  const [assignments,setAssignments] = useState<Record<string,string>>({})
  const load = () => api<typeof data>(`/smart-assessment/context-required/reviews?offset=${offset}`).then(setData).catch(cause=>setError(cause.message))
  useEffect(()=>{load()},[offset])
  useEffect(()=>{if(user.role==='Administrator')api<User[]>('/users').then(setUsers).catch(cause=>setError(cause.message))},[])
  async function assign(row:any,role:'owner'|'grc') {
    setBusy(true);setError('')
    try {
      const id = Number(assignments[`${row.id}-${role}`])
      if(!id)throw new Error('Choose an independent reviewer first.')
      await api(`/assets/${row.asset_id}/classification-mission/reviewers`,{method:'PUT',body:JSON.stringify({role,user_id:id})})
      await load()
    } catch(cause){setError((cause as Error).message)} finally{setBusy(false)}
  }
  async function review(row:any,action:'owner'|'Approved'|'Rejected') {
    setBusy(true);setError('')
    try {
      const justification = reasons[row.id]?.trim()
      if(!justification)throw new Error('A reviewer rationale is required.')
      if(action==='owner'){
        if(!evidence[row.id]?.trim())throw new Error('Owner evidence is required.')
        await api(`/classification-change-requests/${row.id}/owner-validation`,{method:'POST',body:JSON.stringify({justification,evidence:evidence[row.id].trim()})})
      } else await api(`/classification-change-requests/${row.id}`,{method:'PUT',body:JSON.stringify({status:action,justification})})
      await load();onApplied()
    } catch(cause){setError((cause as Error).message)} finally{setBusy(false)}
  }
  return <section className="panel"><h3>Context classification reviews</h3><p>Assign three distinct people: the requesting analyst, an owner validator, and a GRC administrator. Reviewer assignments are managed by administrators.</p><ErrorBox error={error}/>
    <fieldset disabled={busy}><div className="table-scroll"><table><thead><tr><th>Asset / request</th><th>Before / proposed</th><th>Reviewers</th><th>Review evidence</th><th>Action</th></tr></thead><tbody>
      {data.items.map(row=><tr key={row.id}><td>{row.hostname}<small>Request #{row.id} · Analyst #{row.requested_by}</small></td><td><pre>{JSON.stringify({before:row.before,proposed:row.proposed},null,2)}</pre><p>{row.justification}</p><small>{row.evidence}</small></td><td>
        <p>Owner: {row.owner_reviewer_id||'Unassigned'} · {row.owner_validated?'Validated':'Awaiting validation'}</p><p>GRC: {row.grc_reviewer_id||'Unassigned'}</p>
        {user.role==='Administrator'&&(['owner','grc'] as const).map(role=><div key={role}><label>{role==='owner'?'Owner validator':'GRC reviewer'}<select aria-label={`${role} reviewer for request ${row.id}`} value={assignments[`${row.id}-${role}`]||''} onChange={e=>setAssignments(values=>({...values,[`${row.id}-${role}`]:e.target.value}))}><option value="">Choose reviewer</option>{users.filter(candidate=>candidate.id!==row.requested_by&&(role==='owner'?candidate.role!=='Viewer'&&candidate.id!==row.grc_reviewer_id:candidate.role==='Administrator'&&candidate.id!==row.owner_reviewer_id)).map(candidate=><option key={candidate.id} value={candidate.id}>{candidate.username}</option>)}</select></label><button onClick={()=>assign(row,role)}>Assign {role}</button></div>)}
      </td><td><label>Reviewer rationale<textarea value={reasons[row.id]||''} maxLength={5000} onChange={e=>setReasons(values=>({...values,[row.id]:e.target.value}))}/></label>{row.owner_reviewer_id===user.id&&<label>Owner evidence<input value={evidence[row.id]||''} maxLength={10000} onChange={e=>setEvidence(values=>({...values,[row.id]:e.target.value}))}/></label>}</td><td>
        {row.owner_reviewer_id===user.id&&row.requested_by!==user.id&&<button onClick={()=>review(row,'owner')}>Validate as owner</button>}
        {user.role==='Administrator'&&row.grc_reviewer_id===user.id&&<button disabled={!row.owner_validated||row.requested_by===user.id||row.owner_reviewer_id===user.id} onClick={()=>review(row,'Approved')}>Approve as GRC</button>}
        {user.role==='Administrator'&&row.requested_by!==user.id&&<button onClick={()=>review(row,'Rejected')}>Reject</button>}
      </td></tr>)}
      {!data.items.length&&<tr><td colSpan={5}>No pending bulk classifications assigned to you.</td></tr>}
    </tbody></table></div><div className="actions"><button disabled={offset===0} onClick={()=>setOffset(v=>v-100)}>Previous</button><span>{data.total} pending requests</span><button disabled={offset+100>=data.total} onClick={()=>setOffset(v=>v+100)}>Next</button><button onClick={load}>Refresh reviews</button></div></fieldset>
  </section>
}
