import {useState} from 'react'
import {User} from '../api'
import MissionCenter from './MissionCenter'
import Findings from './Findings'
import Imports from './Imports'
import {Administration,AuditHistory,MethodologyPage,Tenable} from './Management'

export function AssessmentHub({user}:{user:User}){
 const [tab,setTab]=useState<'priorities'|'findings'>('priorities')
 const tabs=[['priorities','Priority queue'],['findings','All vulnerabilities']] as const
 return <><div className="hub-intro"><div><span className="eyebrow">RISK OPERATIONS</span><h1>Risk Workbench</h1><p>Prioritize findings, assign the next action, and track remediation from one place.</p></div></div><div className="hub-tabs" role="tablist" aria-label="Risk workbench sections">{tabs.map(([key,label])=><button key={key} role="tab" aria-selected={tab===key} className={tab===key?'active':''} onClick={()=>setTab(key)}>{label}</button>)}</div>{tab==='priorities'&&<MissionCenter/>}{tab==='findings'&&<Findings user={user} assessments/>}</>
}
export function SettingsHub({user}:{user:User}){
 const [tab,setTab]=useState(user.role==='Viewer'?'methodology':'imports')
 const tabs=[['imports','Imports'],['tenable','Tenable Integration'],['methodology','Risk Methodology'],['audit','Audit History'],['administration','Administration']].filter(([key])=>(key!=='tenable'&&key!=='administration'||user.role==='Administrator')&&(key!=='imports'||user.role!=='Viewer'))
 return <><div className="hub-tabs" role="tablist">{tabs.map(([key,label])=><button key={key} className={tab===key?'active':''} onClick={()=>setTab(key)}>{label}</button>)}</div>{tab==='imports'&&<Imports/>}{tab==='tenable'&&<Tenable/>}{tab==='methodology'&&<MethodologyPage user={user}/>} {tab==='audit'&&<AuditHistory/>}{tab==='administration'&&<Administration/>}</>
}
