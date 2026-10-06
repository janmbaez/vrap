import { ReactNode, useEffect, useId, useRef } from 'react'
import { X, ClipboardCheck, ShieldCheck, Clock3, CheckCircle2, CircleDashed, Archive } from 'lucide-react'
import { User } from '../api'

export type Scope = Record<string, string>
export type Reviewer = { id: number; username: string; role: User['role'] }
export type Breakdown = { name: string; total: number; reviewed: number; pending: number; skipped: number; review_coverage: number | null; processed_coverage: number | null }
export type Metrics = { total: number; reviewed: number; pending: number; skipped: number; review_coverage: number | null; processed_coverage: number | null; breakdowns?: Record<string, Breakdown[]> }
export type Campaign = {
  id: number; name: string; description: string; frequency: 'one-time' | 'weekly' | 'monthly';
  period_start: string; period_end: string; start_date: string; due_date: string; workspace: string;
  scope: Scope; status: string; created_by: number; created_at: string; updated_at: string;
  activated_at: string | null; completed_at: string | null; reviewers: Reviewer[]; metrics: Metrics;
  days_remaining: number | null; days_overdue: number; overdue: boolean;
  can_manage?: boolean; can_review?: boolean; can_export?: boolean;
}
export type CampaignFinding = {
  id: number; finding_id: number; status: 'Pending' | 'Reviewed' | 'Skipped'; reviewer_id: number | null;
  reviewer: string | null; reviewed_at: string | null; decision: string | null; skip_reason: string | null;
  notes: string; evidence_references: string[]; snapshot_plugin_id: string | null;
  snapshot_vulnerability: string; snapshot_asset_id: number | null; snapshot_asset: string;
  snapshot_severity: string; snapshot_risk: number | null; snapshot_risk_level: string | null;
  snapshot_business_owner: string | null; snapshot_it_owner: string | null;
  snapshot_application_owner: string | null; snapshot_asset_group: string | null;
  snapshot_tags: string[]; snapshot_regulatory: string[];
}
export const decisions = ['Further assessment required', 'Remediation follow-up', 'Risk decision documented', 'No change required']
export const skipReasons = ['Duplicate', 'False positive', 'Asset decommissioned', 'Not applicable', 'Awaiting validation', 'Other']
export const scopeLabels: Record<string, string> = {
  q: 'Search', severity: 'Technical severity', source: 'Source', status: 'Assessment status', residual: 'Residual risk', inherent: 'Inherent risk',
  appetite: 'Risk appetite', business: 'Business criticality', classification: 'Data classification', regulatory: 'Regulatory scope',
  plugin_id: 'Plugin ID', asset_group: 'Asset group', asset_tag: 'Asset tag', business_owner: 'Business owner', it_owner: 'IT remediation owner', application_owner: 'Application owner',
}
export const scopeOptions: Record<string, string[]> = {
  severity: ['Critical', 'High', 'Medium', 'Low', 'Informational'], residual: ['Critical', 'High', 'Medium', 'Low', 'Informational'],
  inherent: ['Critical', 'High', 'Medium', 'Low', 'Informational'], appetite: ['Above', 'Within'],
  status: ['Not Assessed', 'Assessment In Progress', 'Context Required', 'Assessed', 'Pending Validation', 'Above Risk Appetite', 'Exception Requested', 'Risk Accepted', 'Remediation Required', 'Closed'],
  source: ['Tenable', 'CSV', 'Excel', 'Manual', 'Demo'], business: ['Critical', 'High', 'Medium', 'Low'],
  classification: ['Public', 'Internal', 'Confidential', 'Restricted'], regulatory: ['PCI DSS', 'SOC 2', 'SOX', 'HIPAA', 'GDPR', 'Other', 'None'],
}
export const cleanScope = (scope: Scope) => Object.fromEntries(Object.entries(scope).filter(([, value]) => value.trim()).map(([key, value]) => [key, value.trim()]))
export const percent = (value: number | null | undefined) => value == null ? 'No data' : `${Math.round(value * 10) / 10}%`
export const date = (value: string | null | undefined, includeTime = false) => !value ? '—' : new Date(value.length === 10 ? `${value}T12:00:00` : value).toLocaleString(undefined, includeTime ? { dateStyle: 'medium', timeStyle: 'short' } : { dateStyle: 'medium' })
export const canManage = (campaign: Campaign, user: User) => campaign.can_manage ?? (user.role === 'Administrator' || campaign.created_by === user.id)
export const canReview = (campaign: Campaign, user: User) => campaign.can_review ?? (user.role !== 'Viewer' && (canManage(campaign, user) || campaign.reviewers.some(reviewer => reviewer.id === user.id)))

export function CampaignBadge({ status, overdue = false }: { status: string; overdue?: boolean }) {
  const Icon = status === 'Completed' ? CheckCircle2 : status === 'Archived' ? Archive : status === 'Draft' ? CircleDashed : ClipboardCheck
  return <span className={`campaign-status ${status.toLowerCase().replaceAll(' ', '-')}`}><Icon size={12} />{status}{overdue && <span className="campaign-overdue">Overdue</span>}</span>
}
export function ScopeChips({ scope }: { scope: Scope }) {
  const values = Object.entries(cleanScope(scope))
  return <div className="campaign-chips">{values.length ? values.map(([key, value]) => <span key={key}>{scopeLabels[key] || key}: <b>{value}</b></span>) : <span>All findings in this environment</span>}</div>
}
export function Coverage({ metrics, compact = false }: { metrics: Metrics; compact?: boolean }) {
  return <div className={compact ? 'campaign-coverage compact' : 'campaign-coverage'}><div><span>Review coverage</span><strong>{percent(metrics.review_coverage)}</strong></div><progress value={metrics.reviewed} max={Math.max(1, metrics.total)} aria-label="Review coverage" /><small>{metrics.reviewed.toLocaleString()} reviewed of {metrics.total.toLocaleString()} · {percent(metrics.processed_coverage)} processed</small></div>
}
export function CampaignEmpty({ title, children, action }: { title: string; children: ReactNode; action?: ReactNode }) {
  return <div className="campaign-empty"><span className="campaign-empty-icon"><ClipboardCheck size={27} /></span><h3>{title}</h3><p>{children}</p>{action}</div>
}
export function CampaignLoading({ children = 'Loading campaign data…' }: { children?: ReactNode }) {
  return <div className="campaign-loading" role="status"><span className="campaign-spinner" />{children}</div>
}
export function CampaignPagination({ offset, limit = 50, total, loading, onChange }: { offset: number; limit?: number; total: number; loading?: boolean; onChange: (offset: number) => void }) {
  return <div className="pagination"><span>{total ? offset + 1 : 0}–{Math.min(offset + limit, total)} of {total.toLocaleString()}</span><button disabled={loading || offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}>Previous</button><button disabled={loading || offset + limit >= total} onClick={() => onChange(offset + limit)}>Next</button></div>
}
export function CampaignDialog({ title, description, children, onClose, busy = false, wide = false }: { title: string; description?: string; children: ReactNode; onClose: () => void; busy?: boolean; wide?: boolean }) {
  const ref = useRef<HTMLDivElement>(null), titleId = useId()
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null
    const focusables = () => Array.from(ref.current?.querySelectorAll<HTMLElement>('button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), a[href], [tabindex="0"]') || [])
    focusables()[0]?.focus()
    function key(event: KeyboardEvent) {
      if (event.key === 'Escape' && !busy) { event.preventDefault(); onClose() }
      if (event.key === 'Tab') { const items = focusables(), first = items[0], last = items[items.length - 1]; if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus() } else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus() } }
    }
    document.addEventListener('keydown', key)
    return () => { document.removeEventListener('keydown', key); previous?.focus() }
  }, [busy, onClose])
  return <div className="modal-backdrop campaign-modal-backdrop"><div ref={ref} className={`modal campaign-modal ${wide ? 'campaign-wide-modal' : ''}`} role="dialog" aria-modal="true" aria-labelledby={titleId}><div className="section-head"><div><h2 id={titleId}>{title}</h2>{description && <p>{description}</p>}</div><button aria-label="Close dialog" disabled={busy} onClick={onClose}><X size={18} /></button></div>{children}</div></div>
}
export function ScopeFields({ scope, onChange, snapshot = false }: { scope: Scope; onChange: (scope: Scope) => void; snapshot?: boolean }) {
  const keys = snapshot ? ['q', 'severity', 'plugin_id', 'business_owner', 'it_owner', 'application_owner', 'asset_group', 'asset_tag'] : Object.keys(scopeLabels)
  return <div className="campaign-scope-fields">{keys.map(key => <label key={key}>{scopeLabels[key]}{scopeOptions[key] ? <select value={scope[key] || ''} onChange={event => onChange({ ...scope, [key]: event.target.value })}><option value="">Any</option>{scopeOptions[key].map(value => <option key={value}>{value}</option>)}</select> : <input value={scope[key] || ''} maxLength={300} placeholder={key === 'q' ? 'Vulnerability, plugin, or asset' : `Any ${scopeLabels[key].toLowerCase()}`} onChange={event => onChange({ ...scope, [key]: event.target.value })} />}</label>)}</div>
}
export function ReviewIdentityNote() { return <p className="campaign-helper"><ShieldCheck size={15} />Reviewers are signed-in security analysts. Business, IT, and application owners describe accountability on the asset.</p> }
export function Due({ campaign }: { campaign: Campaign }) {
  return <span className={`campaign-due ${campaign.overdue ? 'late' : ''}`}><Clock3 size={13} />{['Completed', 'Archived'].includes(campaign.status) ? `Completed ${date(campaign.completed_at)}` : campaign.overdue ? `${campaign.days_overdue} day${campaign.days_overdue === 1 ? '' : 's'} overdue` : campaign.days_remaining == null ? 'No due date' : campaign.days_remaining === 0 ? 'Due today' : `Due in ${campaign.days_remaining} days`}</span>
}
export async function downloadCampaign(id: number, format: 'csv' | 'pdf', name: string) {
  const response = await fetch(`/api/review-campaigns/${id}/export/${format}`, { credentials: 'same-origin' })
  if (!response.ok) {
    const contentType = response.headers.get('Content-Type') || ''
    const detail = contentType.includes('json') ? (await response.json()).detail : 'Could not download evidence. Please try again.'
    throw new Error(typeof detail === 'string' ? detail : 'Could not download evidence.')
  }
  const blob = await response.blob()
  if (format === 'pdf' && !(await blob.slice(0, 5).text()).startsWith('%PDF-')) throw new Error('The server returned an invalid PDF. No file was saved.')
  const url = URL.createObjectURL(blob), anchor = document.createElement('a')
  anchor.href = url; anchor.download = `VRAP-Review-${name.replace(/[^a-zA-Z0-9_-]/g, '-').slice(0, 80)}.${format}`; document.body.append(anchor); anchor.click(); anchor.remove()
  setTimeout(() => URL.revokeObjectURL(url), 30000)
}
