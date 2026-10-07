from datetime import date
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy import select, func, insert, case
from pydantic import ValidationError
from ..db import get_db
from ..auth import require_user,writer
from ..models import (ReviewCampaign,CampaignReviewer,CampaignFinding,CampaignEvidence,
                      CampaignAuditEvent,User,Finding,Asset,Vulnerability)
from ..query import finding_query
from ..campaign_schemas import (CampaignInput,CampaignPatch,ScopePreview,ReviewInput,BulkReview,
                                 EvidenceInput,ReopenInput,CloneInput)
from ..campaigns import (visible_campaigns,get_campaign,record_event,set_reviewers,reviewers,
                        campaign_output,campaign_metrics,activate,transition,review_rows,
                        snapshot_query,shifted_date,governance_analytics,_counts_columns,_metrics)

router=APIRouter(prefix='/review-campaigns',tags=['Review Campaigns'])

def workspace(request): return request.state.session.workspace

def _page(db,query,limit,offset):
    total=db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0
    return total,query.limit(limit).offset(offset)

@router.get('')
def list_campaigns(request:Request,q:str='',status:str='',history:bool=False,overdue:bool=False,
                   sort:Literal['id','name','due_date','period_start','status']='id',
                   direction:Literal['asc','desc']='desc',
                   limit:int=Query(50,ge=1,le=200),offset:int=Query(0,ge=0),
                   user=Depends(require_user),db=Depends(get_db)):
    query=visible_campaigns(workspace(request),user)
    if q: query=query.where(ReviewCampaign.name.ilike('%'+q+'%'))
    if status: query=query.where(ReviewCampaign.status==status)
    elif history: query=query.where(ReviewCampaign.status.in_(['Completed','Archived']))
    if overdue: query=query.where(ReviewCampaign.due_date<date.today(),ReviewCampaign.status.in_(['Active','In Progress','Reopened']))
    order=getattr(ReviewCampaign,sort)
    total,page=_page(db,query.order_by(order.asc() if direction=='asc' else order.desc(),ReviewCampaign.id.desc()),limit,offset)
    rows=db.scalars(page).all();ids=[c.id for c in rows]
    counts=db.execute(select(CampaignFinding.campaign_id,*_counts_columns())
                      .where(CampaignFinding.campaign_id.in_(ids)).group_by(CampaignFinding.campaign_id)).all()
    metrics={r.campaign_id:_metrics(r) for r in counts}
    assigned=db.execute(select(CampaignReviewer.campaign_id,User.id,User.username,User.role)
                       .join(User,User.id==CampaignReviewer.user_id).where(CampaignReviewer.campaign_id.in_(ids))).all()
    reviewers_by_id={i:[] for i in ids}
    for r in assigned: reviewers_by_id[r.campaign_id].append({'id':r.id,'username':r.username,'role':r.role})
    today=date.today();output=[]
    for c in rows:
        completed=c.status in ('Completed','Archived')
        d={column.name:getattr(c,column.name) for column in ReviewCampaign.__table__.columns}
        d.update(reviewers=reviewers_by_id[c.id],metrics=metrics.get(c.id,_metrics(None)),
                 overdue=not completed and c.status!='Draft' and c.due_date<today,
                 days_remaining=max(0,(c.due_date-today).days) if not completed else 0,
                 days_overdue=max(0,(today-c.due_date).days) if not completed and c.status!='Draft' else 0,
                 can_manage=user.role=='Administrator' or (user.role=='Security Analyst' and c.created_by==user.id),
                 can_review=user.role=='Administrator' or (user.role=='Security Analyst' and
                   (c.created_by==user.id or any(r['id']==user.id for r in reviewers_by_id[c.id]))),can_export=True)
        output.append(d)
    return {'items':output,'total':total}

@router.post('',status_code=201)
def create_campaign(data:CampaignInput,request:Request,user=Depends(writer),db=Depends(get_db)):
    campaign=ReviewCampaign(**data.model_dump(exclude={'reviewer_ids'}),workspace=workspace(request),created_by=user.id)
    try:
        db.add(campaign);db.flush();set_reviewers(db,campaign,data.reviewer_ids)
        record_event(db,campaign,user,'created',data.model_dump(mode='json'));db.commit()
    except Exception: db.rollback();raise
    return campaign_output(db,campaign,user)

@router.post('/preview')
def preview_scope(data:ScopePreview,request:Request,user=Depends(writer),db=Depends(get_db)):
    query=finding_query(db,workspace(request),data.scope)
    total=db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows=db.execute(query.with_only_columns(Finding.id,Asset.id.label('asset_id'),Asset.hostname,Vulnerability.name,
             Vulnerability.plugin_id,func.coalesce(Finding.observed['severity'].as_string(),
                       Vulnerability.technical['severity'].as_string(),'Unknown').label('severity'))
             .order_by(Finding.id).limit(10)).all()
    return {'total':total,'items':[{'id':r.id,'finding_id':r.id,'name':r.name,'plugin_id':r.plugin_id,
              'severity':r.severity,'asset':{'id':r.asset_id,'hostname':r.hostname}} for r in rows]}

@router.get('/reviewers')
def eligible_reviewers(user=Depends(writer),db=Depends(get_db)):
    return [{'id':r.id,'username':r.username,'role':r.role} for r in db.scalars(select(User)
           .where(User.active==True,User.role.in_(['Administrator','Security Analyst'])).order_by(User.username))]

@router.get('/analytics')
def analytics(request:Request,campaign_id:int|None=None,period_start:date|None=None,period_end:date|None=None,
              severity:str='',business_owner:str='',it_owner:str='',application_owner:str='',asset_group:str='',
              asset_tag:str='',regulatory:str='',user=Depends(require_user),db=Depends(get_db)):
    if period_start and period_end and period_end<period_start: raise HTTPException(422,'Invalid reporting period')
    filters={k:v for k,v in locals().items() if k in {'campaign_id','period_start','period_end','severity','business_owner',
             'it_owner','application_owner','asset_group','asset_tag','regulatory'} and v is not None and v!=''}
    if campaign_id: get_campaign(db,campaign_id,workspace(request),user)
    return governance_analytics(db,workspace(request),user,filters)

@router.get('/{campaign_id}')
def get_details(campaign_id:int,request:Request,user=Depends(require_user),db=Depends(get_db)):
    return campaign_output(db,get_campaign(db,campaign_id,workspace(request),user),user)

@router.patch('/{campaign_id}')
def edit_campaign(campaign_id:int,data:CampaignPatch,request:Request,user=Depends(writer),db=Depends(get_db)):
    campaign=get_campaign(db,campaign_id,workspace(request),user,manage=True,lock=True)
    if campaign.status == 'Archived':
        raise HTTPException(409, 'Archived campaigns are read-only')
    changes=data.model_dump(exclude_unset=True)
    if any(v is None for v in changes.values()): raise HTTPException(422,'Campaign fields cannot be null')
    original={k:getattr(campaign,k) for k in CampaignInput.model_fields if k!='reviewer_ids'}
    original['reviewer_ids']=[r['id'] for r in reviewers(db,campaign.id)]
    try: validated=CampaignInput(**{**original,**changes})
    except ValidationError as e: raise HTTPException(422,str(e))
    try:
        for k,v in validated.model_dump(exclude={'reviewer_ids'}).items(): setattr(campaign,k,v)
        set_reviewers(db,campaign,validated.reviewer_ids)
        record_event(db,campaign,user,'edited',{'before':{k:str(v) if isinstance(v,date) else v for k,v in original.items()},
                                              'after':validated.model_dump(mode='json')});db.commit()
    except Exception: db.rollback();raise
    result = campaign_output(db,campaign,user)
    result['population_unchanged'] = campaign.status != 'Draft'
    return result

@router.post('/{campaign_id}/activate')
def activate_campaign(campaign_id:int,request:Request,user=Depends(writer),db=Depends(get_db)):
    campaign=get_campaign(db,campaign_id,workspace(request),user,manage=True,lock=True)
    try: activate(db,campaign,user);db.commit()
    except Exception: db.rollback();raise
    return campaign_output(db,campaign,user)

@router.post('/{campaign_id}/complete')
def complete_campaign(campaign_id:int,request:Request,user=Depends(writer),db=Depends(get_db)):
    campaign=get_campaign(db,campaign_id,workspace(request),user,manage=True,lock=True)
    try: transition(db,campaign,user,'complete');db.commit()
    except Exception: db.rollback();raise
    return campaign_output(db,campaign,user)

@router.post('/{campaign_id}/reopen')
def reopen_campaign(campaign_id:int,data:ReopenInput,request:Request,user=Depends(writer),db=Depends(get_db)):
    campaign=get_campaign(db,campaign_id,workspace(request),user,manage=True,lock=True)
    try: transition(db,campaign,user,'reopen',data.reason);db.commit()
    except Exception: db.rollback();raise
    return campaign_output(db,campaign,user)

@router.post('/{campaign_id}/archive')
def archive_campaign(campaign_id:int,request:Request,user=Depends(writer),db=Depends(get_db)):
    campaign=get_campaign(db,campaign_id,workspace(request),user,manage=True,lock=True)
    try: transition(db,campaign,user,'archive');db.commit()
    except Exception: db.rollback();raise
    return campaign_output(db,campaign,user)

@router.post('/{campaign_id}/clone',status_code=201)
def clone_campaign(campaign_id:int,request:Request,data:CloneInput|None=None,user=Depends(writer),db=Depends(get_db)):
    original=get_campaign(db,campaign_id,workspace(request),user,manage=True)
    values={k:getattr(original,k) for k in CampaignInput.model_fields if k!='reviewer_ids'}
    for key in ('period_start','period_end','start_date','due_date'): values[key]=shifted_date(values[key],original.frequency)
    values['name']=original.name+' (next period)';values['name']=values['name'][:200]
    values.update(data.model_dump(exclude_none=True) if data else {})
    values['reviewer_ids']=[r['id'] for r in reviewers(db,original.id)]
    try: validated=CampaignInput(**values)
    except ValidationError as e: raise HTTPException(422,str(e))
    campaign=ReviewCampaign(**validated.model_dump(exclude={'reviewer_ids'}),workspace=workspace(request),created_by=user.id)
    try:
        db.add(campaign);db.flush();set_reviewers(db,campaign,validated.reviewer_ids)
        record_event(db,campaign,user,'cloned',{'source_campaign_id':original.id,'dates':validated.model_dump(mode='json')})
        record_event(db,original,user,'clone_created',{'new_campaign_id':campaign.id});db.commit()
    except Exception: db.rollback();raise
    return campaign_output(db,campaign,user)

@router.get('/{campaign_id}/findings')
def campaign_findings(campaign_id:int,request:Request,q:str='',status:str='',severity:str='',business_owner:str='',
           it_owner:str='',application_owner:str='',asset_group:str='',asset_tag:str='',plugin_id:str='',
           sort:Literal['finding_id','severity','asset','status','business_owner','it_owner','application_owner','plugin','risk','reviewed_at']='finding_id',
           direction:Literal['asc','desc']='asc',
           limit:int=Query(50,ge=1,le=200),offset:int=Query(0,ge=0),user=Depends(require_user),db=Depends(get_db)):
    get_campaign(db,campaign_id,workspace(request),user)
    filters={k:v for k,v in locals().items() if k in {'q','status','severity','business_owner','it_owner',
          'application_owner','asset_group','asset_tag','plugin_id'} and v}
    query=snapshot_query(db,[campaign_id],filters)
    order_by={'finding_id':CampaignFinding.finding_id,'severity':case((CampaignFinding.snapshot_severity=='Critical',0),
          (CampaignFinding.snapshot_severity=='High',1),(CampaignFinding.snapshot_severity=='Medium',2),
          (CampaignFinding.snapshot_severity=='Low',3),(CampaignFinding.snapshot_severity=='Informational',4),else_=5),
          'asset':CampaignFinding.snapshot_asset,'status':CampaignFinding.status,
          'business_owner':CampaignFinding.snapshot_business_owner,'it_owner':CampaignFinding.snapshot_it_owner,
          'application_owner':CampaignFinding.snapshot_application_owner,'plugin':CampaignFinding.snapshot_plugin_id,
          'risk':CampaignFinding.snapshot_risk,'reviewed_at':CampaignFinding.reviewed_at}
    order=order_by[sort]
    total,page=_page(db,query.order_by((order.asc() if direction=='asc' else order.desc()).nulls_last(),CampaignFinding.id),limit,offset)
    rows=db.execute(page.add_columns(User.username.label('reviewer')).outerjoin(User,User.id==CampaignFinding.reviewer_id)).all()
    return {'items':[{**{column.name:getattr(row[0],column.name) for column in CampaignFinding.__table__.columns},
                      'reviewer':row.reviewer} for row in rows],'total':total}

@router.patch('/{campaign_id}/findings/{finding_id}')
def review_finding(campaign_id:int,finding_id:int,data:ReviewInput,request:Request,user=Depends(writer),db=Depends(get_db)):
    campaign=get_campaign(db,campaign_id,workspace(request),user,review=True,lock=True)
    try: count=review_rows(db,campaign,user,data,[finding_id]);db.commit()
    except Exception: db.rollback();raise
    return {'updated':count,'metrics':campaign_metrics(db,campaign.id)}

@router.post('/{campaign_id}/bulk-review')
def bulk_review(campaign_id:int,data:BulkReview,request:Request,user=Depends(writer),db=Depends(get_db)):
    campaign=get_campaign(db,campaign_id,workspace(request),user,review=True,lock=True)
    try: count=review_rows(db,campaign,user,data,data.ids if data.selection=='selected' else None);db.commit()
    except Exception: db.rollback();raise
    return {'updated':count,'metrics':campaign_metrics(db,campaign.id)}

@router.get('/{campaign_id}/metrics')
def metrics(campaign_id:int,request:Request,user=Depends(require_user),db=Depends(get_db)):
    get_campaign(db,campaign_id,workspace(request),user)
    return campaign_metrics(db,campaign_id)

@router.get('/{campaign_id}/audit')
def audit_events(campaign_id:int,request:Request,limit:int=Query(50,ge=1,le=200),offset:int=Query(0,ge=0),
                 user=Depends(require_user),db=Depends(get_db)):
    get_campaign(db,campaign_id,workspace(request),user)
    query=select(CampaignAuditEvent).where(CampaignAuditEvent.campaign_id==campaign_id)
    total,page=_page(db,query.order_by(CampaignAuditEvent.id.desc()),limit,offset)
    rows=db.execute(page.add_columns(User.username.label('actor')).join(User,User.id==CampaignAuditEvent.actor_id)).all()
    return {'items':[{**{c.name:getattr(r[0],c.name) for c in CampaignAuditEvent.__table__.columns},'actor':r.actor} for r in rows],'total':total}

@router.get('/{campaign_id}/evidence')
def evidence(campaign_id:int,request:Request,limit:int=Query(50,ge=1,le=200),offset:int=Query(0,ge=0),
             user=Depends(require_user),db=Depends(get_db)):
    get_campaign(db,campaign_id,workspace(request),user)
    query=select(CampaignEvidence).where(CampaignEvidence.campaign_id==campaign_id)
    total,page=_page(db,query.order_by(CampaignEvidence.id.desc()),limit,offset)
    rows=db.execute(page.add_columns(User.username.label('author')).join(User,User.id==CampaignEvidence.created_by)).all()
    return {'items':[{**{c.name:getattr(r[0],c.name) for c in CampaignEvidence.__table__.columns},'author':r.author} for r in rows],'total':total}

@router.post('/{campaign_id}/evidence',status_code=201)
def add_evidence(campaign_id:int,data:EvidenceInput,request:Request,user=Depends(writer),db=Depends(get_db)):
    campaign=get_campaign(db,campaign_id,workspace(request),user,review=True,lock=True)
    if campaign.status not in ('Active','In Progress','Reopened'): raise HTTPException(409,'Evidence can be added only to active campaigns')
    if data.finding_id and not db.scalar(select(CampaignFinding.id).where(CampaignFinding.campaign_id==campaign_id,
                                        CampaignFinding.finding_id==data.finding_id)):
        raise HTTPException(404,'Finding does not belong to this campaign')
    row=CampaignEvidence(campaign_id=campaign_id,created_by=user.id,**data.model_dump())
    try:
        db.add(row);db.flush();record_event(db,campaign,user,'evidence_added',{'evidence_id':row.id,**data.model_dump()});db.commit()
    except Exception: db.rollback();raise
    return {**{c.name:getattr(row,c.name) for c in CampaignEvidence.__table__.columns},'author':user.username}
