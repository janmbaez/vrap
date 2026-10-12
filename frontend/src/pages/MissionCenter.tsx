import { useEffect, useState } from 'react'
import { RefreshCw, Target } from 'lucide-react'
import { api } from '../api'
import { Badge, ErrorBox, PageTitle } from '../components/UI'

const labels: Record<string,string> = { urgent_review:'Urgent review', missing_context_evidence:'Missing context / evidence', automated_provisional:'Automated provisional', monitor_reassess:'Monitor / reassess' }
export default function MissionCenter() {
  const [data,setData] = useState<any>(), [error,setError] = useState('')
  const load = () => api<any>('/mission-center').then(setData).catch(e=>setError(e.message))
  useEffect(() => { load() }, [])
  return <><PageTitle title="Analyst Mission Center" description="Prioritized daily queues and recommended next actions." actions={<button onClick={load}><RefreshCw size={16}/> Refresh</button>}/><ErrorBox error={error}/>{data && <><div className="kpi-grid">{Object.entries(data.summary).map(([key,value])=><div className="metric" key={key}><span>{labels[key]}</span><strong>{String(value)}</strong></div>)}</div><div className="grid-2">{Object.entries(data.queues).map(([key,items]:any)=><section className="panel table-panel" key={key}><div className="section-head"><h2>{labels[key]}</h2><Badge>{items.length}</Badge></div>{items.length?<div className="table-scroll"><table><thead><tr><th>Finding</th><th>Asset</th><th>Status</th><th>Recommended action</th></tr></thead><tbody>{items.slice(0,50).map((item:any)=><tr key={item.finding_id}><td><a href={`/findings/${item.finding_id}`}>{item.name}</a><small>{item.plugin_id || 'No plugin ID'}</small></td><td>{item.asset}</td><td><Badge>{item.status}</Badge></td><td>{item.recommended_action}</td></tr>)}</tbody></table></div>:<p className="helper"><Target size={15}/> No tasks in this queue.</p>}</section>)}</div></>}</>
}
