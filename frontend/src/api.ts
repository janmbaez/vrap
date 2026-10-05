export type User = {id:number; username:string; role:'Administrator'|'Security Analyst'|'Viewer'; environment:'Demo'|'Production'}
export type Control = {name:string; effectiveness:number; applicable:boolean; validated:boolean; evidence:string; notes:string;design_maturity:number|null;operating_effectiveness:number|null}
export type Score = {technical:number; inherent:number; residual:number; inherent_level:string; residual_level:string; appetite:string; above_appetite:boolean; factors:Array<{factor:string;component:string;value:unknown;unknown:boolean;score:number;weight:number;contribution:number}>; controls:Array<{name:string;applied:boolean;reason:string|null;score_delta:number;component:string}>; missing_required:string[]; unknowns:string[]; components_before:Record<string,number>;components_after:Record<string,number>;methodology_version?:string;as_of:string;grc_matrix:{inherent_likelihood:number;inherent_impact:number;inherent_risk:number;control_design_maturity:number;control_operating_effectiveness:number;gross_control_strength:number;remaining_risk_factor:number;residual_risk:number;residual_level:string;authorized_tolerance:number;above_tolerance:boolean;recommended_decision:string;source:string}}
export type Finding = {id:number;revision:number;name:string;plugin_id:string;cves:string[];asset:{id:number;hostname:string;ip:string;os:string;tags:unknown[]};technical:Record<string,any>;context:Record<string,any>;controls:Control[];applied_rules:Array<{id:number;name:string}>;source:string;port:number;protocol:string;status:string;decision:string;notes:string;justification:string;score:Score;saved_score:Score|null;baseline:Score;methodology_id:number;methodology_version:string;reassessment_required:boolean;assessed_at:string|null}
export type Methodology = {id:number;version:string;configuration:Record<string,any>;created_at:string}
export async function api<T=any>(path:string, options:RequestInit = {}):Promise<T> {
  const csrf = document.cookie.split('; ').find(c=>c.startsWith('vrap_csrf='))?.split('=')[1] || ''
  const headers:Record<string,string> = {'X-CSRF-Token':decodeURIComponent(csrf), ...(options.body instanceof FormData ? {} : {'Content-Type':'application/json'})}
  const result = await fetch('/api'+path, {...options,headers:{...headers,...options.headers}, credentials:'same-origin'})
  const data = await result.json()
  if(!result.ok) {
    const message = Array.isArray(data.detail) ? data.detail.map((e:any)=>`${e.loc?.slice(1).join('.')}: ${e.msg}`).join('; ') : data.detail
    throw new Error(message || 'Request failed')
  }
  return data
}
export const post = <T=any>(path:string, body:unknown) => api<T>(path,{method:'POST',body:JSON.stringify(body)})
export const label = (s:string) => s.replaceAll('_',' ').replace(/\b\w/g,c=>c.toUpperCase())
export const fmt = (n:number|undefined) => n == null ? '—' : n.toFixed(1)
