"""Tenable VM adapter. External shapes terminate here, never in the risk engine."""
import asyncio
import inspect
import time
from urllib.parse import urlparse
from datetime import datetime, timezone
import httpx
from ..schemas import FindingCreate

# Keep connector exports consistent with the documented interactive-import limit.
MAX_TENABLE_CHUNK_BYTES = 100 * 1024 * 1024
EXPORT_TIMEOUT_SECONDS = 60 * 60
VULNERABILITY_ASSETS_PER_CHUNK = 2000

class TenableError(Exception):
    pass

class TenableCancelled(TenableError):
    pass

class TenableClient:
    def __init__(self, config, transport=None):
        url = urlparse(config.tenable_base_url)
        if url.scheme != 'https' or url.hostname not in config.tenable_allowed_hosts.split(',') or url.username or url.password or url.path not in ('', '/') or url.query or url.fragment or url.port not in (None, 443):
            raise TenableError('Tenable URL must use HTTPS and an approved hostname')
        if not config.tenable_access_key or not config.tenable_secret_key:
            raise TenableError('Tenable credentials are not configured on the server')
        self.client = httpx.AsyncClient(base_url=config.tenable_base_url.rstrip('/'), headers={'X-ApiKeys': f'accessKey={config.tenable_access_key}; secretKey={config.tenable_secret_key}', 'Accept': 'application/json'}, timeout=30, follow_redirects=False, transport=transport)

    async def close(self):
        await self.client.aclose()

    async def request(self, method, path, **kwargs):
        for attempt in range(4):
            try:
                response = await self.client.request(method, path, **kwargs)
            except httpx.RequestError:
                raise TenableError('Unable to reach Tenable; check network configuration')
            if response.status_code == 429 or response.status_code >= 500:
                if attempt < 3:
                    retry = response.headers.get('retry-after', '')
                    await asyncio.sleep(min(20, float(retry) if retry.isdigit() else 2 ** attempt))
                    continue
            if response.status_code >= 300:
                raise TenableError(f'Tenable returned HTTP {response.status_code}; verify API permissions and configuration')
            if len(response.content) > MAX_TENABLE_CHUNK_BYTES:
                raise TenableError('Tenable chunk exceeded the configured 100 MiB limit')
            try:
                return response.json()
            except ValueError:
                raise TenableError('Tenable returned an invalid JSON response')
        raise TenableError('Tenable retry limit exceeded')

    async def test(self):
        await self.request('GET', '/session')

    async def export(self, kind, progress=None):
        path = '/vulns/export' if kind == 'vulnerabilities' else '/assets/export'
        # Vulnerability records can include large plugin output. Smaller asset groups
        # keep a single response below the bounded connector memory limit.
        # Tenable recommends 1,000–3,000 assets per vulnerability chunk.  A larger
        # chunk count makes large exports spend most of their time in queue/setup.
        # Filtering informational records upstream prevents them consuming export,
        # transfer, or VRAP processing capacity.
        payload = ({'num_assets': VULNERABILITY_ASSETS_PER_CHUNK,
                    'filters': {'since': 0, 'severity': ['low', 'medium', 'high', 'critical']}}
                   if kind == 'vulnerabilities' else {'chunk_size': 500})
        job = await self.request('POST', path, json=payload)
        export_id = job.get('export_uuid')
        if not isinstance(export_id, str) or not export_id or any(c not in '0123456789abcdefABCDEF-' for c in export_id):
            raise TenableError('Tenable export response did not include a valid identifier')
        deadline, seen = time.monotonic() + EXPORT_TIMEOUT_SECONDS, set()
        while time.monotonic() < deadline:
            status = await self.request('GET', f'{path}/{export_id}/status')
            if status.get('status') in ('ERROR', 'CANCELLED') or status.get('chunks_failed') or status.get('chunks_cancelled'):
                raise TenableError('Tenable export failed or was cancelled')
            for chunk in status.get('chunks_available', []):
                if not isinstance(chunk, int) or chunk < 0:
                    raise TenableError('Invalid export chunk identifier')
                if chunk in seen:
                    continue
                records = await self.request('GET', f'{path}/{export_id}/chunks/{chunk}')
                if not isinstance(records, list):
                    raise TenableError('Unexpected export chunk format')
                yield records
                seen.add(chunk)
            if progress:
                outcome = progress(status, seen)
                if inspect.isawaitable(outcome):
                    outcome = await outcome
                if outcome is False:
                    raise TenableCancelled('Synchronization cancelled by user')
            if status.get('status') == 'FINISHED':
                return
            await asyncio.sleep(2)
        raise TenableError('Export did not finish within one hour; retry synchronization or narrow the Tenable export')

def first(value):
    return value[0] if isinstance(value, list) and value else value if isinstance(value, str) else None

def date_value(value):
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, timezone.utc).date()
        return datetime.fromisoformat(str(value).replace('Z', '+00:00')).date()
    except (ValueError, TypeError, OverflowError):
        return None

def optional_score(value):
    try:
        number = float(value)
        return number if 0 <= number <= 10 else None
    except (ValueError, TypeError):
        return None

def optional_bool(value):
    if isinstance(value, bool):
        return value
    if str(value).lower() in ('true', 'yes', '1'):
        return True
    if str(value).lower() in ('false', 'no', '0'):
        return False
    return None

def canonical_severity(value):
    """Map Tenable's export labels to the application's risk taxonomy."""
    if isinstance(value, int):
        return ['Informational', 'Low', 'Medium', 'High', 'Critical'][value] if value in range(5) else None
    if value is None:
        return None
    labels = {
        'info': 'Informational',
        'informational': 'Informational',
        'low': 'Low',
        'medium': 'Medium',
        'high': 'High',
        'critical': 'Critical',
    }
    return labels.get(str(value).strip().casefold())

def cvss_vector_value(value):
    """Extract the machine-readable vector from either Tenable export shape."""
    if isinstance(value, str):
        return value
    if not isinstance(value, dict):
        return None
    strings = [item for item in value.values() if isinstance(item, str)]
    return next((item for item in strings if item.upper().startswith('CVSS:')), None)

def normalized_asset_tags(value):
    """Turn Tenable tag objects into stable, human-readable asset tags."""
    items = value if isinstance(value, list) else [value]
    output = []
    for item in items:
        if isinstance(item, str):
            tag = item.strip()
        elif isinstance(item, dict):
            category = item.get('category') or item.get('category_name') or item.get('key') or ''
            name = item.get('value') or item.get('value_name') or item.get('name') or item.get('tag_name') or ''
            category, name = str(category).strip(), str(name).strip()
            tag = f'{category.casefold().replace(" ", "_")}:{name}' if category and name else name or category
        else:
            tag = ''
        if tag:
            output.append(tag[:500])
    return list(dict.fromkeys(output))[:100]

def normalize(record):
    plugin = record.get('plugin') or record.get('definition') or {}
    asset = record.get('asset') or {}
    vpr = plugin.get('vpr') or {}
    if not isinstance(vpr, dict):
        vpr = {'score': vpr}
    port = record.get('port') or {}
    if not isinstance(port, dict):
        port = {'port': port}
    severity = canonical_severity(record.get('severity'))
    cves = plugin.get('cve') or plugin.get('cves') or []
    if isinstance(cves, str):
        cves = [cves]
    hostname = first(asset.get('hostname')) or first(asset.get('fqdn')) or first(asset.get('ipv4')) or asset.get('uuid') or asset.get('id')
    return FindingCreate(hostname=str(hostname or ''), external_id=str(asset.get('uuid') or asset.get('id') or '') or None,
        ip=first(asset.get('ipv4')), os=first(asset.get('operating_system')), asset_tags=normalized_asset_tags(asset.get('tags')),
        name=str(plugin.get('name') or ''), plugin_id=str(plugin.get('id')) if plugin.get('id') is not None else None,
        cves=cves, severity=severity, cvss=optional_score(plugin.get('cvss3_base_score') or plugin.get('cvss_v3_base_score')),
        vpr=optional_score(vpr.get('score')), cvss_vector=cvss_vector_value(plugin.get('cvss3_vector')),
        exploit_available=optional_bool(plugin.get('exploit_available')), kev=optional_bool(plugin.get('in_the_news_cisa') if 'in_the_news_cisa' in plugin else plugin.get('cisa_kev')),
        exploit_maturity=vpr.get('drivers', {}).get('exploit_code_maturity') if isinstance(vpr.get('drivers'), dict) else None,
        first_seen=date_value(record.get('first_found')), last_seen=date_value(record.get('last_found')),
        published=date_value(plugin.get('publication_date')), modified=date_value(plugin.get('modification_date')),
        family=plugin.get('family'), description=str(plugin.get('description') or '')[:30000], solution=str(plugin.get('solution') or '')[:30000],
        plugin_output=str(record.get('output') or '')[:100000], state=record.get('state'), service=port.get('service'),
        port=int(port.get('port') or 0), protocol=str(port.get('protocol') or 'tcp').lower())
