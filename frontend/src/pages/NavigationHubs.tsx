import {useState} from 'react'
import {User} from '../api'
import AssessmentGroups from './AssessmentGroups'
import SmartAssessmentCategories from './SmartAssessmentCategories'
import MissionCenter from './MissionCenter'
import Imports from './Imports'
import {Administration,AuditHistory,MethodologyPage,Tenable} from './Management'

export function AssessmentHub({user}:{user:User}){
 const [tab,setTab]=useState('assessments')
 const tabs=[['assessments','Assessments'],['smart','Smart Assessment'],['mission','Mission Center']]
 return <><div className="hub-tabs" role="tablist">{tabs.map(([key,label])=><button key={key} className={tab===key?'active':''} onClick={()=>setTab(key)}>{label}</button>)}</div>{tab==='assessments'&&<AssessmentGroups user={user}/>} {tab==='smart'&&<SmartAssessmentCategories user={user}/>} {tab==='mission'&&<MissionCenter/>}</>
}
export function SettingsHub({user}:{user:User}){
 const [tab,setTab]=useState(user.role==='Viewer'?'methodology':'imports')
 const tabs=[['imports','Imports'],['tenable','Tenable Integration'],['methodology','Risk Methodology'],['audit','Audit History'],['administration','Administration']].filter(([key])=>(key!=='tenable'&&key!=='administration'||user.role==='Administrator')&&(key!=='imports'||user.role!=='Viewer'))
 return <><div className="hub-tabs" role="tablist">{tabs.map(([key,label])=><button key={key} className={tab===key?'active':''} onClick={()=>setTab(key)}>{label}</button>)}</div>{tab==='imports'&&<Imports/>}{tab==='tenable'&&<Tenable/>}{tab==='methodology'&&<MethodologyPage user={user}/>} {tab==='audit'&&<AuditHistory/>}{tab==='administration'&&<Administration/>}</>
}
