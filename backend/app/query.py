"""One server-side AND filter builder shared by findings, saved filters and campaigns."""
from fastapi import HTTPException
from sqlalchemy import select, func, Text, exists, or_, cast
from sqlalchemy.dialects.postgresql import JSONB
from .models import Finding, Asset, Vulnerability, Assessment, FindingWorkflow, RiskScore

FILTER_KEYS = {'q', 'severity', 'source', 'status', 'residual', 'inherent', 'appetite',
               'business', 'classification', 'regulatory', 'plugin_id', 'asset_group',
               'asset_tag', 'vulnerability_tag', 'business_owner', 'it_owner', 'application_owner'}

def validate_filters(filters):
    if not isinstance(filters, dict) or set(filters) - FILTER_KEYS:
        raise HTTPException(422, 'Unsupported scope filter: ' + ', '.join(sorted(set(filters or {}) - FILTER_KEYS)))
    for key, value in filters.items():
        if not isinstance(value, str) or len(value) > 500:
            raise HTTPException(422, f'{key} must be text with at most 500 characters')
    if filters.get('severity') and filters['severity'] not in {'Critical','High','Medium','Low','Informational','Unknown'}:
        raise HTTPException(422, 'Unknown severity')
    if filters.get('appetite') and filters['appetite'] not in {'Above','Within'}:
        raise HTTPException(422, 'Appetite must be Above or Within')
    return {k: v.strip() for k, v in filters.items() if v.strip()}

def normalize_tags(tags):
    out = set()
    for tag in tags or []:
        if isinstance(tag, dict):
            category = tag.get('category') or tag.get('category_name') or ''
            value = tag.get('value') or tag.get('value_name') or ''
            tag = f'{str(category).lower().replace(" ", "_")}:{value}' if category else str(value)
        if isinstance(tag, str) and tag.strip():
            out.add(tag.strip()[:500])
    return sorted(out)

def json_list_has(db, column, value):
    """Exact JSON-array membership for both SQLite tests and PostgreSQL deployments."""
    if db.bind.dialect.name == 'postgresql':
        return cast(column, JSONB).contains([value])
    values = func.json_each(column).table_valued('value').alias()
    return exists(select(1).select_from(values).where(values.c.value == value))

def asset_tag_has(db, value):
    if db.bind.dialect.name == 'postgresql':
        from sqlalchemy import case
        tags = cast(Asset.tags, JSONB)
        entries = func.jsonb_array_elements(tags).table_valued('value').alias()
        name = func.coalesce(func.jsonb_extract_path_text(entries.c.value, 'value'),
                             func.jsonb_extract_path_text(entries.c.value, 'value_name'))
        category = func.coalesce(func.jsonb_extract_path_text(entries.c.value, 'category'),
                                 func.jsonb_extract_path_text(entries.c.value, 'category_name'))
        category = func.replace(func.lower(category), ' ', '_')
        normalized = case((category.is_not(None), category + ':' + name), else_=name)
        return or_(tags.contains([value]),exists(select(1).select_from(entries).where(normalized == value)))
    entries = func.json_each(Asset.tags).table_valued('value', 'type').alias()
    # CASE prevents json_extract from parsing scalar tag text as JSON.
    from sqlalchemy import case
    safe = case((entries.c.type == 'object', entries.c.value), else_='{}')
    name = func.coalesce(func.json_extract(safe, '$.value'), func.json_extract(safe, '$.value_name'))
    category = func.coalesce(func.json_extract(safe, '$.category'), func.json_extract(safe, '$.category_name'))
    category = func.replace(func.lower(category), ' ', '_')
    normalized = case((category.is_not(None), category + ':' + name), else_=name)
    return exists(select(1).select_from(entries).where(or_(entries.c.value == value, normalized == value)))

def finding_query(db, workspace, filters=None):
    filters = validate_filters(filters or {})
    statement = (select(Finding).join(Asset, Finding.asset_id == Asset.id)
                 .join(Vulnerability, Finding.vulnerability_id == Vulnerability.id)
                 .where(Finding.workspace == workspace, Asset.workspace == workspace))
    if filters.get('source'): statement = statement.where(Finding.source == filters['source'])
    if filters.get('q'):
        term = '%' + filters['q'] + '%'
        statement = statement.where(or_(Asset.hostname.ilike(term), Vulnerability.name.ilike(term),
                                        Vulnerability.plugin_id.ilike(term), Vulnerability.cves.cast(Text).ilike(term)))
    if filters.get('severity'):
        statement = statement.where(func.coalesce(Finding.observed['severity'].as_string(),
                              Vulnerability.technical['severity'].as_string(),'Unknown') == filters['severity'])
    if any(filters.get(k) for k in ('status','residual','inherent','appetite')):
        latest = select(Assessment.instance_id, func.max(Assessment.id).label('id')).group_by(Assessment.instance_id).subquery()
        statement = (statement.outerjoin(latest, latest.c.instance_id == Finding.id)
                     .outerjoin(Assessment, Assessment.id == latest.c.id)
                     .outerjoin(RiskScore, RiskScore.assessment_id == Assessment.id))
        if filters.get('status'):
            status = filters['status']
            if status == 'Closed':
                statement = statement.outerjoin(FindingWorkflow, FindingWorkflow.finding_id == Finding.id).where(FindingWorkflow.status == 'Closed')
            else:
                statement = statement.where(Assessment.id.is_(None) if status == 'Not Assessed' else Assessment.status == status)
        for key in ('residual','inherent'):
            if filters.get(key): statement = statement.where(RiskScore.result[key + '_level'].as_string() == filters[key])
        if filters.get('appetite'):
            statement = statement.where(RiskScore.result['above_appetite'].as_boolean() == (filters['appetite'] == 'Above'))
    for key, context in [('business','business_criticality'),('classification','data_classification'),
                         ('business_owner','business_owner'),('it_owner','it_owner'),('application_owner','application_owner')]:
        if filters.get(key):
            column=Asset.context[context].as_string()
            statement = statement.where(or_(column.is_(None),column=='',column=='Unassigned')
                 if filters[key]=='Unassigned' and key.endswith('owner') else column==filters[key])
    if filters.get('plugin_id'): statement = statement.where(Vulnerability.plugin_id == filters['plugin_id'])
    if filters.get('regulatory'): statement = statement.where(json_list_has(db, Asset.context['regulatory'], filters['regulatory']))
    if filters.get('asset_tag'): statement = statement.where(asset_tag_has(db, filters['asset_tag']))
    if filters.get('vulnerability_tag'): statement = statement.where(json_list_has(db, Finding.observed['tags'], filters['vulnerability_tag']))
    if filters.get('asset_group'):
        column=Asset.context['asset_group'].as_string()
        if filters['asset_group']=='Unassigned':
            statement=statement.where(or_(column.is_(None),column=='',column=='Unassigned'))
        else:
            statement = statement.where(or_(column == filters['asset_group'],asset_tag_has(db, 'group:' + filters['asset_group'])))
    return statement
