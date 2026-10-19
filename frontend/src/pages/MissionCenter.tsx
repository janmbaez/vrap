import { FormEvent, useEffect, useState } from 'react'
import { RefreshCw, Target, ChevronLeft, ChevronRight } from 'lucide-react'
import { Link } from 'react-router-dom'
import { api, MissionCenterResponse, MissionQueueKey } from '../api'
import { Badge, ErrorBox, PageTitle, Loading } from '../components/UI'

const pageSize = 50
const queueKeys: MissionQueueKey[] = ['urgent_review','missing_context_evidence','automated_provisional','monitor_reassess']
const labels: Record<MissionQueueKey,string> = { urgent_review:'Urgent review', missing_context_evidence:'Missing context / evidence', automated_provisional:'Automated provisional', monitor_reassess:'Monitor / reassess' }
export default function MissionCenter() {
  const [data,setData] = useState<MissionCenterResponse>(), [error,setError] = useState(''), [loading,setLoading] = useState(true)
  const [page,setPage] = useState(1), [search,setSearch] = useState(''), [query,setQuery] = useState(''), [refresh,setRefresh] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    setLoading(true); setError('')
    api<MissionCenterResponse>(`/mission-center?page=${page}&page_size=${pageSize}&q=${encodeURIComponent(query)}`, {signal:controller.signal})
      .then(setData).catch(error => { if (error.name !== 'AbortError') setError(error.message || 'Unable to load the Mission Center.') })
      .finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [page,query,refresh])
  const submitSearch = (event: FormEvent) => { event.preventDefault(); setPage(1); setQuery(search.trim()) }
  const total = data ? Object.values(data.summary).reduce((sum,count)=>sum+count,0) : 0
  const hasNext = data ? Object.values(data.summary).some(count=>count > page*pageSize) : false
  return <><PageTitle title="Analyst Mission Center" description="Explainable risk-prioritized daily queues and next actions." actions={<form className="actions" role="search" onSubmit={submitSearch}><input aria-label="Search missions" placeholder="Search findings or assets" value={search} onChange={event=>setSearch(event.target.value)}/><button type="submit" disabled={loading}>Search</button><button type="button" onClick={()=>setRefresh(value=>value+1)} disabled={loading}><RefreshCw size={16}/> {loading?'Loading…':'Refresh'}</button></form>}/>
  {error&&<><ErrorBox error={error}/><button className="secondary" onClick={()=>setRefresh(value=>value+1)}>Retry</button></>}
  {loading&&!data&&<div className="panel"><Loading>Loading your mission queue…</Loading></div>}
  {!loading&&!error&&data&&total===0&&<div className="panel empty-state"><Target size={20}/><p>{query?'No missions match your search.':'No tasks are currently in the mission queues.'}</p></div>}
  {data&&total>0&&<div aria-busy={loading}><div className="kpi-grid">{queueKeys.map(key=><div className="metric" key={key}><span>{labels[key]}</span><strong>{data.summary[key]??0}</strong></div>)}</div><div className="grid-2">{queueKeys.map(key=>{const items=data.queues[key]??[];return <section className="panel table-panel" key={key}><div className="section-head"><h2>{labels[key]}</h2><Badge>{data.summary[key]??0}</Badge></div>{items.length?<div className="table-scroll"><table><thead><tr><th>Finding</th><th>Asset</th><th>Priority</th><th>Recommended action</th></tr></thead><tbody>{items.map(item=><tr key={item.finding_id}><td><Link to={`/findings/${item.finding_id}`}>{item.name}</Link><small>{item.plugin_id||'No plugin ID'}</small></td><td>{item.asset}</td><td><Badge>{item.priority_score}</Badge><small>{item.priority_factors.join(' · ')}</small></td><td>{item.recommended_action}</td></tr>)}</tbody></table></div>:<p className="helper"><Target size={15}/> No tasks in this queue on this page.</p>}</section>})}</div><div className="actions"><button disabled={loading||page<=1} onClick={()=>setPage(value=>value-1)}><ChevronLeft size={16}/> Previous</button><span>Page {page}</span><button disabled={loading||!hasNext} onClick={()=>setPage(value=>value+1)}>Next <ChevronRight size={16}/></button></div></div>}</>
}
