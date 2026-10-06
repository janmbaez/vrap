"""Campaign snapshots, authorization and SQL metrics; shared by UI and report exports."""
import calendar
from datetime import date, datetime, timedelta, timezone
from fastapi import HTTPException
from sqlalchemy import select, func, case, insert, update, delete, or_, Text
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.dialects.postgresql import insert as pg_insert
from .models import (ReviewCampaign, CampaignReviewer, CampaignFinding, CampaignFindingTag,
                     CampaignEvidence, CampaignAuditEvent, User, Finding, FindingWorkflow,
                     Asset, Vulnerability, Assessment, RiskScore, Methodology, Audit, now)
from .query import finding_query, normalize_tags, json_list_has

MAX_SNAPSHOT = 100000
MAX_BULK = 10000
SNAPSHOT_FILTER_KEYS = {'q','status','severity','business_owner','it_owner','application_owner',
                        'asset_group','asset_tag','plugin_id','regulatory'}

def visible_campaigns(workspace, user=None):
    statement = select(ReviewCampaign).where(ReviewCampaign.workspace == workspace)
    if user and user.role == 'Viewer':
        statement = statement.where(ReviewCampaign.status.in_(['Completed','Archived']))
    return statement

def get_campaign(db, campaign_id, workspace, user, manage=False, review=False, lock=False):
    query = visible_campaigns(workspace,user).where(ReviewCampaign.id == campaign_id)
    if lock: query = query.with_for_update()
    row = db.scalar(query)
    if not row: raise HTTPException(404,'Review campaign not found')
    if manage and user.role != 'Administrator' and not (user.role == 'Security Analyst' and row.created_by == user.id):
        raise HTTPException(403,'Only the campaign creator or Administrator can manage this campaign')
    if review and not can_review(db,row,user):
        raise HTTPException(403,'You are not assigned to review this campaign')
    return row

def can_review(db, campaign, user):
    return user.role == 'Administrator' or (user.role == 'Security Analyst' and
        (campaign.created_by == user.id or db.scalar(select(CampaignReviewer.id).where(
           CampaignReviewer.campaign_id == campaign.id, CampaignReviewer.user_id == user.id)) is not None))

def record_event(db,campaign,user,action,details=None):
    details = details or {}
    db.add(CampaignAuditEvent(campaign_id=campaign.id,actor_id=user.id,action=action,details=details))
    db.add(Audit(actor_id=user.id,action='campaign.'+action,entity='review_campaign',entity_id=campaign.id,
                 details={'workspace':campaign.workspace,**details}))
    campaign.updated_at = now()

def reviewers(db,campaign_id):
    rows = db.execute(select(User.id,User.username,User.role).join(CampaignReviewer,
                CampaignReviewer.user_id == User.id).where(CampaignReviewer.campaign_id == campaign_id)
                .order_by(User.username)).all()
    return [{'id':r.id,'username':r.username,'role':r.role} for r in rows]

def validate_reviewers(db, ids):
    actual = set(db.scalars(select(User.id).where(User.id.in_(ids),User.active == True,
                      User.role.in_(['Administrator','Security Analyst']))).all())
    if actual != set(ids): raise HTTPException(422,'Reviewers must be active Administrators or Security Analysts')

def set_reviewers(db,campaign,ids):
    validate_reviewers(db,ids)
    db.execute(delete(CampaignReviewer).where(CampaignReviewer.campaign_id == campaign.id))
    if ids: db.execute(insert(CampaignReviewer),[{'campaign_id':campaign.id,'user_id':i} for i in ids])

def _counts_columns():
    return [func.count(CampaignFinding.id).label('total'),
            func.sum(case((CampaignFinding.status=='Reviewed',1),else_=0)).label('reviewed'),
            func.sum(case((CampaignFinding.status=='Pending',1),else_=0)).label('pending'),
            func.sum(case((CampaignFinding.status=='Skipped',1),else_=0)).label('skipped')]

def _metrics(row):
    d = {k:int(getattr(row,k,0) or 0) for k in ('total','reviewed','pending','skipped')}
    d.update(review_coverage=d['reviewed']*100/d['total'] if d['total'] else None,
             processed_coverage=(d['reviewed']+d['skipped'])*100/d['total'] if d['total'] else None)
    return d

def snapshot_query(db, campaign_ids, filters=None):
    filters = filters or {}
    unknown = set(filters)-SNAPSHOT_FILTER_KEYS
    if unknown: raise HTTPException(422,'Unsupported snapshot filter: '+', '.join(sorted(unknown)))
    if any(not isinstance(v,str) or len(v)>500 for v in filters.values()):
        raise HTTPException(422,'Snapshot filters must be text with at most 500 characters')
    query = select(CampaignFinding).where(CampaignFinding.campaign_id.in_(campaign_ids))
    for key in ('status','severity','business_owner','it_owner','application_owner','asset_group','plugin_id'):
        if filters.get(key):
            column = CampaignFinding.status if key=='status' else getattr(CampaignFinding,'snapshot_'+key)
            query = query.where(or_(column.is_(None),column=='',column=='Unassigned')
                if filters[key]=='Unassigned' and key in ('business_owner','it_owner','application_owner','asset_group','plugin_id')
                else column==filters[key])
    if filters.get('asset_tag'):
        tag_ids = select(CampaignFindingTag.campaign_finding_id).where(CampaignFindingTag.tag==filters['asset_tag'])
        query = query.where(CampaignFinding.id.in_(tag_ids))
    if filters.get('regulatory'):
        query = query.where(json_list_has(db,CampaignFinding.snapshot_regulatory,filters['regulatory']))
    if filters.get('q'):
        term='%'+filters['q']+'%'
        query=query.where(or_(CampaignFinding.snapshot_asset.ilike(term),CampaignFinding.snapshot_vulnerability.ilike(term),
                               CampaignFinding.snapshot_plugin_id.ilike(term)))
    return query

def aggregate_snapshot_metrics(db, campaign_ids, filters=None):
    query = snapshot_query(db,campaign_ids,filters)
    conditions = query._where_criteria
    result = _metrics(db.execute(select(*_counts_columns()).where(*conditions)).one())
    dimensions={'severity':CampaignFinding.snapshot_severity,'business_owner':CampaignFinding.snapshot_business_owner,
                'it_owner':CampaignFinding.snapshot_it_owner,'application_owner':CampaignFinding.snapshot_application_owner,
                'asset_group':CampaignFinding.snapshot_asset_group,'plugin':CampaignFinding.snapshot_plugin_id}
    breakdowns={}
    for name,column in dimensions.items():
        label=func.coalesce(func.nullif(column,''),'Unassigned')
        rows=db.execute(select(label.label('name'),*_counts_columns())
                    .where(*conditions).group_by(label).order_by(func.count(CampaignFinding.id).desc(),label)).all()
        breakdowns[name]=[{'name':r.name,**_metrics(r)} for r in rows]
    rows=db.execute(select(CampaignFindingTag.tag.label('name'),*_counts_columns())
             .join(CampaignFinding,CampaignFinding.id==CampaignFindingTag.campaign_finding_id)
             .where(*conditions).group_by(CampaignFindingTag.tag)
             .order_by(func.count(CampaignFinding.id).desc(),CampaignFindingTag.tag)).all()
    breakdowns['asset_tag']=[{'name':r.name,**_metrics(r)} for r in rows]
    severity_order={name:i for i,name in enumerate(['Critical','High','Medium','Low','Informational','Unknown'])}
    breakdowns['severity'].sort(key=lambda r:severity_order.get(r['name'],99))
    result['breakdowns']=breakdowns
    return result

def campaign_metrics(db,campaign_id):
    return aggregate_snapshot_metrics(db,[campaign_id])

def campaign_output(db,campaign,user=None,metrics=None,include_breakdowns=True):
    d={column.name:getattr(campaign,column.name) for column in ReviewCampaign.__table__.columns}
    for k,v in list(d.items()):
        if isinstance(v,(date,datetime)): d[k]=v.isoformat()
    today=date.today()
    finished=campaign.status in ('Completed','Archived')
    d.update(reviewers=reviewers(db,campaign.id),
             metrics=metrics if metrics is not None else campaign_metrics(db,campaign.id),
             overdue=not finished and campaign.status!='Draft' and campaign.due_date<today,
             days_remaining=max(0,(campaign.due_date-today).days) if not finished else 0,
             days_overdue=max(0,(today-campaign.due_date).days) if not finished and campaign.status!='Draft' else 0,
             can_manage=bool(user and (user.role=='Administrator' or (user.role=='Security Analyst' and campaign.created_by==user.id))),
             can_review=bool(user and can_review(db,campaign,user)),can_export=True)
    return d

def activate(db,campaign,user):
    if campaign.status!='Draft': raise HTTPException(409,'Only Draft campaigns can be activated')
    if not reviewers(db,campaign.id): raise HTTPException(422,'Assign at least one reviewer before activation')
    population=finding_query(db,campaign.workspace,campaign.scope)
    total=db.scalar(select(func.count()).select_from(population.subquery())) or 0
    if not total: raise HTTPException(422,'The scope must match at least one finding')
    if total>MAX_SNAPSHOT: raise HTTPException(422,f'Campaign populations cannot exceed {MAX_SNAPSHOT} findings')
    latest=select(Assessment.instance_id,func.max(Assessment.id).label('id')).group_by(Assessment.instance_id).subquery()
    method_id=db.scalar(select(Methodology.id).order_by(Methodology.id.desc()).limit(1))
    valid_score=(Assessment.status.in_(['Assessed','Above Risk Appetite','Exception Requested','Risk Accepted','Remediation Required','Closed']) & (Assessment.revision==Finding.revision)
                 & (Assessment.methodology_id==method_id))
    query=(population.with_only_columns(Finding.id.label('finding_id'),Asset.id.label('asset_id'),Asset.hostname,
           Asset.context,Asset.tags,Vulnerability.name,Vulnerability.plugin_id,
           func.coalesce(Finding.observed['severity'].as_string(),Vulnerability.technical['severity'].as_string(),'Unknown').label('severity'))
           .subquery())
    # Populate from compact joined records; existing scope risk filters may already join Assessment.
    records=(select(query,case((valid_score,RiskScore.result['residual'].as_float()),else_=None).label('risk'),
           case((valid_score,RiskScore.result['residual_level'].as_string()),else_=None).label('risk_level'))
           .join(Finding,Finding.id==query.c.finding_id).outerjoin(latest,latest.c.instance_id==Finding.id)
           .outerjoin(Assessment,Assessment.id==latest.c.id).outerjoin(RiskScore,RiskScore.assessment_id==Assessment.id))
    pending=[]
    def save_batch(batch):
        returned=db.execute(insert(CampaignFinding).returning(CampaignFinding.id,CampaignFinding.finding_id),batch).all()
        by_finding={x['finding_id']:x for x in batch}
        tag_rows=[{'campaign_id':campaign.id,'campaign_finding_id':x.id,'tag':tag}
                  for x in returned for tag in by_finding[x.finding_id]['snapshot_tags']]
        if tag_rows: db.execute(insert(CampaignFindingTag),tag_rows)
    for r in db.execute(records.execution_options(yield_per=1000)):
        context=r.context or {}; tags=normalize_tags(r.tags)
        group=context.get('asset_group') or next((t[6:] for t in tags if t.startswith('group:')),None)
        pending.append({'campaign_id':campaign.id,'finding_id':r.finding_id,'snapshot_plugin_id':r.plugin_id,
            'snapshot_vulnerability':r.name,'snapshot_asset_id':r.asset_id,'snapshot_asset':r.hostname,
            'snapshot_severity':r.severity,'snapshot_risk':r.risk,'snapshot_risk_level':r.risk_level,
            'snapshot_business_owner':context.get('business_owner') or None,'snapshot_it_owner':context.get('it_owner') or None,
            'snapshot_application_owner':context.get('application_owner') or None,'snapshot_asset_group':group or None,
            'snapshot_tags':tags,'snapshot_regulatory':context.get('regulatory') or [],'status':'Pending',
            'notes':'','evidence_references':[]})
        if len(pending)>=1000: save_batch(pending);pending=[]
    if pending: save_batch(pending)
    campaign.status='Active';campaign.activated_at=now()
    record_event(db,campaign,user,'activated',{'total':total,'scope':campaign.scope})

def review_rows(db,campaign,user,data,ids=None):
    if campaign.status not in ('Active','In Progress','Reopened'):
        raise HTTPException(409,'Review actions require an Active, In Progress or Reopened campaign')
    query=snapshot_query(db,[campaign.id],data.filters if hasattr(data,'filters') and data.selection=='matching' else {})
    if ids is not None: query=query.where(CampaignFinding.finding_id.in_(ids))
    total=db.scalar(select(func.count()).select_from(query.subquery())) or 0
    if not total: raise HTTPException(422,'No campaign findings selected')
    if total>MAX_BULK: raise HTTPException(422,f'Bulk review is limited to {MAX_BULK} findings')
    if ids is not None and total!=len(set(ids)): raise HTTPException(404,'A selected finding does not belong to this campaign')
    # One bounded read captures prior decisions and supports a single auditable set-based transaction.
    rows=db.scalars(query.order_by(CampaignFinding.id)).all()
    selected=[r.finding_id for r in rows];row_ids=[r.id for r in rows]
    before=[{'finding_id':r.finding_id,'status':r.status,'decision':r.decision,'skip_reason':r.skip_reason,
             'reviewer_id':r.reviewer_id,'reviewed_at':r.reviewed_at.isoformat() if r.reviewed_at else None,
             'notes':r.notes,'evidence_references':r.evidence_references} for r in rows]
    timestamp=now()
    changes={'status':data.status,'decision':data.decision,'skip_reason':data.skip_reason,'notes':data.notes,
             'evidence_references':data.evidence_references,'reviewer_id':user.id,'reviewed_at':timestamp}
    db.execute(update(CampaignFinding).where(CampaignFinding.id.in_(row_ids)).values(**changes))
    # Preserve the prior live review independently from campaign evidence and remediation fields.
    old_live=db.execute(select(FindingWorkflow.finding_id,FindingWorkflow.review_state,FindingWorkflow.review_decision,
                               FindingWorkflow.reviewed_by,FindingWorkflow.reviewed_at,FindingWorkflow.review_notes)
                         .where(FindingWorkflow.finding_id.in_(selected))).all()
    live_before=[{'finding_id':r.finding_id,'review_state':r.review_state,'review_decision':r.review_decision,
                   'reviewed_by':r.reviewed_by,'reviewed_at':r.reviewed_at.isoformat() if r.reviewed_at else None,
                   'review_notes':r.review_notes} for r in old_live]
    live_rows=[{'finding_id':i,'status':'New','updated_by':user.id,'updated_at':timestamp,
                'review_state':data.status,'reviewed_at':timestamp,'reviewed_by':user.id,
                'review_decision':data.decision,'review_notes':data.notes} for i in selected]
    dialect_insert=pg_insert if db.bind.dialect.name=='postgresql' else sqlite_insert
    # Chunk statements to keep parameter counts bounded on SQLite and PostgreSQL.
    for start in range(0,len(live_rows),500):
        statement=dialect_insert(FindingWorkflow).values(live_rows[start:start+500])
        statement=statement.on_conflict_do_update(index_elements=['finding_id'],set_={
            name:getattr(statement.excluded,name) for name in ('review_state','reviewed_at','reviewed_by','review_decision','review_notes')})
        db.execute(statement)
    evidence=[{'campaign_id':campaign.id,'finding_id':i,'reference':reference,'notes':data.notes,
               'created_by':user.id,'created_at':timestamp} for i in selected for reference in data.evidence_references]
    if evidence: db.execute(insert(CampaignEvidence),evidence)
    campaign.status='In Progress'
    record_event(db,campaign,user,'bulk_review' if len(rows)>1 or hasattr(data,'selection') else 'finding_review',
                 {'count':total,'finding_ids':selected,'before':before,'live_review_before':live_before,
                  'after':{**{k:v for k,v in changes.items() if k!='reviewed_at'},'reviewed_at':timestamp.isoformat()}})
    return total

def transition(db,campaign,user,action,reason=None):
    if action=='complete':
        if campaign.status not in ('Active','In Progress','Reopened'): raise HTTPException(409,'Only an active campaign can be completed')
        if campaign_metrics(db,campaign.id)['pending']: raise HTTPException(409,'Review or document a skip for every pending finding before completion')
        campaign.status='Completed';campaign.completed_at=now()
    elif action=='reopen':
        if user.role!='Administrator': raise HTTPException(403,'Only an Administrator can reopen a campaign')
        if campaign.status!='Completed': raise HTTPException(409,'Only Completed campaigns can be reopened')
        if not reason or not reason.strip(): raise HTTPException(422,'A reopen reason is required')
        campaign.status='Reopened';campaign.completed_at=None
    elif action=='archive':
        if campaign.status!='Completed': raise HTTPException(409,'Only Completed campaigns can be archived')
        campaign.status='Archived'
    else: raise HTTPException(422,'Unsupported transition')
    record_event(db,campaign,user,action,{'reason':reason,'status':campaign.status})

def shifted_date(value,frequency):
    if frequency=='monthly':
        year=value.year+(value.month==12);month=1 if value.month==12 else value.month+1
        return value.replace(year=year,month=month,day=min(value.day,calendar.monthrange(year,month)[1]))
    return value+timedelta(days=7 if frequency=='weekly' else max(1,7))

def governance_analytics(db,workspace,user=None,filters=None):
    filters=dict(filters or {})
    period_start=filters.pop('period_start',filters.pop('start_date',None))
    period_end=filters.pop('period_end',filters.pop('end_date',None))
    campaign_id=filters.pop('campaign_id',None)
    exclude_ids=filters.pop('exclude_campaign_ids',[])
    query=visible_campaigns(workspace,user).where(ReviewCampaign.status!='Draft')
    if exclude_ids: query=query.where(ReviewCampaign.id.not_in(exclude_ids))
    if period_start: query=query.where(ReviewCampaign.period_end>=date.fromisoformat(str(period_start)))
    if period_end: query=query.where(ReviewCampaign.period_start<=date.fromisoformat(str(period_end)))
    if campaign_id: query=query.where(ReviewCampaign.id==int(campaign_id))
    campaigns=db.scalars(query.order_by(ReviewCampaign.period_start,ReviewCampaign.id)).all()
    ids=[c.id for c in campaigns]
    metrics=aggregate_snapshot_metrics(db,ids,filters)
    conditions=snapshot_query(db,ids,filters)._where_criteria
    today=date.today();done=lambda c:c.status in ('Completed','Archived')
    counts=db.execute(select(CampaignFinding.campaign_id,*_counts_columns()).where(*conditions)
                      .group_by(CampaignFinding.campaign_id)).all()
    by_campaign={r.campaign_id:_metrics(r) for r in counts}
    # Batch reviewer loading keeps analytics/list performance independent of campaign count.
    assigned=db.execute(select(CampaignReviewer.campaign_id,User.id,User.username,User.role)
                        .join(User,User.id==CampaignReviewer.user_id).where(CampaignReviewer.campaign_id.in_(ids))).all()
    by_reviewers={i:[] for i in ids}
    for r in assigned: by_reviewers[r.campaign_id].append({'id':r.id,'username':r.username,'role':r.role})
    output=[];trends={}
    for c in campaigns:
        count=by_campaign.get(c.id,_metrics(None));covered=count['review_coverage']
        overdue=not done(c) and c.due_date<today
        output.append({'id':c.id,'name':c.name,'description':c.description,'workspace':c.workspace,'status':c.status,
                      'frequency':c.frequency,'period_start':c.period_start.isoformat(),'period_end':c.period_end.isoformat(),
                      'start_date':c.start_date.isoformat(),'due_date':c.due_date.isoformat(),'created_by':c.created_by,
                      'scope':c.scope,'reviewers':by_reviewers[c.id],'metrics':count,'overdue':overdue,
                      'days_remaining':max(0,(c.due_date-today).days) if not done(c) else 0,
                      'days_overdue':max(0,(today-c.due_date).days) if overdue else 0,
                      'can_manage':bool(user and (user.role=='Administrator' or (user.role=='Security Analyst' and c.created_by==user.id))),
                      'can_review':bool(user and (user.role=='Administrator' or (user.role=='Security Analyst' and
                            (c.created_by==user.id or any(r['id']==user.id for r in by_reviewers[c.id]))))),
                      'can_export':True})
        period=c.period_start.isoformat()
        bucket=trends.setdefault(period,{'period':period,'total':0,'reviewed':0,'pending':0,'skipped':0,'campaigns':0,
                                       'completed':0,'overdue':0,'incomplete':0})
        for key in ('total','reviewed','pending','skipped'): bucket[key]+=count[key]
        bucket['campaigns']+=1;bucket['completed']+=int(done(c));bucket['overdue']+=int(overdue)
        bucket['incomplete']+=int(not done(c) and not overdue)
    for bucket in trends.values():
        bucket['review_coverage']=bucket['reviewed']*100/bucket['total'] if bucket['total'] else None
        bucket['processed_coverage']=(bucket['reviewed']+bucket['skipped'])*100/bucket['total'] if bucket['total'] else None
    covered=[x['metrics']['review_coverage'] for x in output if x['metrics']['review_coverage'] is not None]
    summary={k:v for k,v in metrics.items() if k!='breakdowns'}
    summary.update(population_basis='campaign finding participations',active_campaigns=sum(not done(c) for c in campaigns),
       completed_campaigns=sum(done(c) for c in campaigns),overdue_campaigns=sum(not done(c) and c.due_date<today for c in campaigns),
       due_soon_campaigns=sum(not done(c) and today<=c.due_date<=today+timedelta(days=7) for c in campaigns),
       average_review_coverage=sum(covered)/len(covered) if covered else None,
       campaign_completion_rate=sum(done(c) for c in campaigns)*100/len(campaigns) if campaigns else None,
       critical_pending=db.scalar(select(func.count(CampaignFinding.id)).where(*conditions,
                         CampaignFinding.snapshot_severity=='Critical',CampaignFinding.status=='Pending')) or 0,
       asset_coverage=db.scalar(select(func.count(func.distinct(CampaignFinding.snapshot_asset_id))).where(*conditions)) or 0)
    return {'summary':summary,'campaigns':output,'trends':list(trends.values()),'breakdowns':metrics['breakdowns'],
            'population_basis':'campaign finding participations'}
