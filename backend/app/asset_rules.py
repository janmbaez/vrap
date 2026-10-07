from ipaddress import ip_address, ip_network
from sqlalchemy import select
from .models import AssetRule

ASSET_CONTEXT_KEYS = {'asset_criticality', 'business_criticality', 'data_classification', 'regulatory', 'environment', 'exposure',
                      'business_owner', 'it_owner', 'application_owner', 'asset_group', 'asset_type'}

def matches(rule: AssetRule, hostname: str, ip: str | None, tags: list) -> bool:
    if rule.match_type == 'All assets':
        return True
    if rule.match_type in ('Hostname prefix', 'Hostname suffix'):
        # Wildcards are optional: aws and aws* mean prefix; -DB and *-DB mean suffix.
        value = rule.match_value.strip().casefold().strip('*')
        if not value:
            return False
        normalized_hostname = hostname.casefold()
        return normalized_hostname.startswith(value) if rule.match_type == 'Hostname prefix' else normalized_hostname.endswith(value)
    if rule.match_type == 'Tag':
        value = rule.match_value.casefold()
        return any(value == str(tag).casefold() or value in str(tag).casefold() for tag in tags)
    if rule.match_type == 'CIDR' and ip:
        try:
            return ip_address(ip) in ip_network(rule.match_value, strict=False)
        except ValueError:
            return False
    return False

def resolve_rules(db, hostname: str, ip: str | None, tags: list):
    context, controls, applied = {}, {}, []
    rules = db.scalars(select(AssetRule).where(AssetRule.active.is_(True)).order_by(AssetRule.priority, AssetRule.id)).all()
    for rule in rules:
        if not matches(rule, hostname, ip, tags):
            continue
        applied.append({'id': rule.id, 'name': rule.name})
        for key, value in rule.context.items():
            if value not in (None, '', []):
                context.setdefault(key, value)
        for control in rule.controls:
            controls.setdefault(control['name'], control)
    return context, list(controls.values()), applied
