"""Threat-intel ingestion, normalization, and matching.

Three responsibilities:

1. **Parse** feed payloads (plaintext / JSON / CSV / STIX 2.x / MISP) into
   normalized `IndicatorDraft`s.
2. **Sync** a remote feed: egress-guarded fetch → parse → upsert, recording
   status/errors on the feed row.
3. **Match** active indicators against agent activity, producing hits the
   detection engine turns into findings.

Matching is deliberately conservative and bounded (capped indicator counts and
per-event text length) so a run stays cheap even with large feeds.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    EXACT_MATCH_TYPES,
    FeedFormat,
    FeedSyncStatus,
    FindingSeverity,
    IndicatorType,
    ThreatFeed,
    ThreatIndicator,
)
from app.services._http import owned_client
from app.services.crypto import unseal
from app.services.egress import EgressBlocked, assert_safe_webhook_url

# --- bounds -----------------------------------------------------------------
MAX_FEED_BYTES = 16 * 1024 * 1024  # refuse absurd feed payloads (16 MiB)
MAX_INDICATORS_PER_SYNC = 100_000
MAX_SCAN_INDICATORS = 20_000  # per-type cap when building the match index
MAX_EVENT_TEXT = 20_000  # chars of serialized args scanned per event
FETCH_TIMEOUT_SECONDS = 15.0

_SEVERITY_ORDER: dict[str, int] = {
    FindingSeverity.INFO: 0,
    FindingSeverity.LOW: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.HIGH: 3,
    FindingSeverity.CRITICAL: 4,
}


def severity_rank(severity: str) -> int:
    return _SEVERITY_ORDER.get(severity, 0)


# --- extraction patterns (over lowercased serialized args) ------------------
_RE_URL = re.compile(r"https?://[^\s\"'<>)\]]+")
_RE_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b")
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_EMAIL = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b")
_RE_SHA256 = re.compile(r"\b[a-f0-9]{64}\b")
_RE_MD5 = re.compile(r"\b[a-f0-9]{32}\b")


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------
def normalize_indicator(itype: str, value: str) -> str | None:
    """Canonical form of an indicator value, or None if malformed for its type.

    Lowercases hostnames/URLs/hashes/emails; validates IPs; leaves signatures
    and regexes untouched apart from trimming.
    """
    v = (value or "").strip()
    if not v:
        return None
    try:
        t = IndicatorType(itype)
    except ValueError:
        return None

    if t is IndicatorType.IP:
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            return None
    if t in (IndicatorType.DOMAIN, IndicatorType.EMAIL):
        return v.lower().rstrip(".")
    if t is IndicatorType.URL:
        return v.lower()
    if t in (IndicatorType.SHA256, IndicatorType.MD5):
        h = v.lower()
        expected = 64 if t is IndicatorType.SHA256 else 32
        if len(h) != expected or any(c not in "0123456789abcdef" for c in h):
            return None
        return h
    if t is IndicatorType.REGEX:
        try:
            re.compile(v)
        except re.error:
            return None
        return v
    # tool_name / package / prompt_signature: keep as-is (trimmed).
    return v


@dataclass
class IndicatorDraft:
    type: str
    value: str
    confidence: int | None = None
    severity: str | None = None
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    description: str | None = None
    expires_at: datetime | None = None


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
class FeedParseError(ValueError):
    """Raised when a feed payload cannot be parsed."""


def parse_feed(content: str, feed: ThreatFeed) -> list[IndicatorDraft]:
    fmt = feed.format
    if fmt == FeedFormat.PLAINTEXT:
        return _parse_plaintext(content, feed)
    if fmt == FeedFormat.JSON:
        return _parse_json(content, feed)
    if fmt == FeedFormat.CSV:
        return _parse_csv(content, feed)
    if fmt == FeedFormat.STIX:
        return _parse_stix(content)
    if fmt == FeedFormat.MISP:
        return _parse_misp(content)
    raise FeedParseError(f"unsupported feed format {fmt!r}")


def _require_default_type(feed: ThreatFeed) -> str:
    if not feed.default_indicator_type:
        raise FeedParseError(
            f"{feed.format} feed requires default_indicator_type"
        )
    return feed.default_indicator_type


def _parse_plaintext(content: str, feed: ThreatFeed) -> list[IndicatorDraft]:
    itype = _require_default_type(feed)
    drafts: list[IndicatorDraft] = []
    for line in content.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        drafts.append(IndicatorDraft(type=itype, value=s))
    return drafts


def _parse_json(content: str, feed: ThreatFeed) -> list[IndicatorDraft]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise FeedParseError(f"invalid JSON: {exc}") from exc
    if isinstance(data, dict):
        data = data.get("indicators") or data.get("data") or []
    if not isinstance(data, list):
        raise FeedParseError("JSON feed must be a list or {indicators: [...]}")

    drafts: list[IndicatorDraft] = []
    default_type: str | None = feed.default_indicator_type
    for item in data:
        if isinstance(item, str):
            if not default_type:
                raise FeedParseError(
                    "JSON string list requires default_indicator_type"
                )
            drafts.append(IndicatorDraft(type=default_type, value=item))
        elif isinstance(item, dict):
            itype = item.get("type") or default_type
            value = item.get("value") or item.get("indicator")
            if not itype or not value:
                continue
            drafts.append(
                IndicatorDraft(
                    type=str(itype),
                    value=str(value),
                    confidence=_opt_int(item.get("confidence")),
                    severity=_opt_str(item.get("severity")),
                    tags=_str_list(item.get("tags")),
                    references=_str_list(item.get("references")),
                    description=_opt_str(item.get("description")),
                    expires_at=_opt_dt(item.get("expires_at")),
                )
            )
    return drafts


def _parse_csv(content: str, feed: ThreatFeed) -> list[IndicatorDraft]:
    reader = csv.DictReader(io.StringIO(content))
    if reader.fieldnames is None:
        return []
    lowered = {name.lower().strip(): name for name in reader.fieldnames}
    if "value" not in lowered and "indicator" not in lowered:
        raise FeedParseError("CSV feed needs a 'value' or 'indicator' column")
    val_col = lowered.get("value") or lowered["indicator"]
    type_col = lowered.get("type")
    drafts: list[IndicatorDraft] = []
    for row in reader:
        value = (row.get(val_col) or "").strip()
        if not value:
            continue
        itype = (
            (row.get(type_col) or "").strip()
            if type_col
            else feed.default_indicator_type
        )
        if not itype:
            continue
        drafts.append(
            IndicatorDraft(
                type=itype,
                value=value,
                confidence=_opt_int(_col(row, lowered, "confidence")),
                severity=_opt_str(_col(row, lowered, "severity")),
                description=_opt_str(_col(row, lowered, "description")),
                tags=_str_list(_col(row, lowered, "tags")),
            )
        )
    return drafts


# STIX 2.x indicator patterns we understand, e.g.
#   [domain-name:value = 'evil.com']
#   [ipv4-addr:value = '1.2.3.4']
#   [url:value = 'https://evil.com/x']
#   [file:hashes.'SHA-256' = 'abcd...']
_STIX_OBJECT_TYPE = {
    "domain-name:value": IndicatorType.DOMAIN.value,
    "ipv4-addr:value": IndicatorType.IP.value,
    "ipv6-addr:value": IndicatorType.IP.value,
    "url:value": IndicatorType.URL.value,
    "email-addr:value": IndicatorType.EMAIL.value,
    "file:hashes.'sha-256'": IndicatorType.SHA256.value,
    "file:hashes.'md5'": IndicatorType.MD5.value,
}
_RE_STIX_COMP = re.compile(
    r"([a-z0-9_\-]+:[a-z0-9_.'\-]+)\s*=\s*'([^']+)'", re.IGNORECASE
)


def parse_stix_objects(objects: list[Any]) -> list[IndicatorDraft]:
    """Parse a list of STIX 2.x objects (SDOs) into indicator drafts.

    Shared by the STIX-file parser and the TAXII poller, which both surface a
    list of STIX objects (from a bundle's ``objects`` or a TAXII envelope).
    """
    drafts: list[IndicatorDraft] = []
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern", "")
        expires = _opt_dt(obj.get("valid_until"))
        confidence = _opt_int(obj.get("confidence"))
        tags = _str_list(obj.get("labels"))
        description = _opt_str(obj.get("description") or obj.get("name"))
        for comp, value in _RE_STIX_COMP.findall(pattern):
            itype = _STIX_OBJECT_TYPE.get(comp.lower())
            if itype is None:
                continue
            drafts.append(
                IndicatorDraft(
                    type=itype,
                    value=value,
                    confidence=confidence,
                    tags=tags,
                    description=description,
                    expires_at=expires,
                )
            )
    return drafts


def _parse_stix(content: str) -> list[IndicatorDraft]:
    try:
        bundle = json.loads(content)
    except json.JSONDecodeError as exc:
        raise FeedParseError(f"invalid STIX JSON: {exc}") from exc
    objects = bundle.get("objects", bundle) if isinstance(bundle, dict) else bundle
    if not isinstance(objects, list):
        raise FeedParseError("STIX bundle has no 'objects' list")
    return parse_stix_objects(objects)


# MISP attribute type -> our indicator type.
_MISP_TYPE = {
    "domain": IndicatorType.DOMAIN.value,
    "hostname": IndicatorType.DOMAIN.value,
    "ip-dst": IndicatorType.IP.value,
    "ip-src": IndicatorType.IP.value,
    "url": IndicatorType.URL.value,
    "email": IndicatorType.EMAIL.value,
    "email-src": IndicatorType.EMAIL.value,
    "sha256": IndicatorType.SHA256.value,
    "md5": IndicatorType.MD5.value,
    "filename": IndicatorType.PACKAGE.value,
}


def _parse_misp(content: str) -> list[IndicatorDraft]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise FeedParseError(f"invalid MISP JSON: {exc}") from exc
    # Accept {"response": [{"Event": {...}}]}, {"Event": {...}}, or a bare
    # list of attributes.
    attributes = _collect_misp_attributes(data)
    drafts: list[IndicatorDraft] = []
    for attr in attributes:
        if not isinstance(attr, dict):
            continue
        itype = _MISP_TYPE.get(str(attr.get("type", "")).lower())
        value = attr.get("value")
        if not itype or not value:
            continue
        drafts.append(
            IndicatorDraft(
                type=itype,
                value=str(value),
                tags=[
                    t.get("name", "")
                    for t in attr.get("Tag", [])
                    if isinstance(t, dict) and t.get("name")
                ],
                description=_opt_str(attr.get("comment")),
            )
        )
    return drafts


def _collect_misp_attributes(data: Any) -> list[Any]:
    events: list[Any] = []
    if isinstance(data, dict):
        if "response" in data and isinstance(data["response"], list):
            events = [e.get("Event", e) for e in data["response"]]
        elif "Event" in data:
            events = [data["Event"]]
        elif "Attribute" in data:
            events = [data]
        else:
            return []
    elif isinstance(data, list):
        # Bare attribute list.
        return data
    else:
        return []
    attrs: list[Any] = []
    for ev in events:
        if isinstance(ev, dict):
            attrs.extend(ev.get("Attribute", []))
    return attrs


# --- small coercion helpers -------------------------------------------------
def _opt_int(v: Any) -> int | None:
    try:
        return int(v) if v is not None and v != "" else None
    except (TypeError, ValueError):
        return None


def _opt_str(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def _str_list(v: Any) -> list[str]:
    if isinstance(v, list):
        return [str(x) for x in v if x is not None and str(x).strip()]
    if isinstance(v, str) and v.strip():
        return [p.strip() for p in v.split(";") if p.strip()]
    return []


def _opt_dt(v: Any) -> datetime | None:
    if not v:
        return None
    if isinstance(v, datetime):
        return v
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None


def _col(row: dict[str, str], lowered: dict[str, str], key: str) -> str | None:
    col = lowered.get(key)
    return row.get(col) if col else None


# ---------------------------------------------------------------------------
# Upsert
# ---------------------------------------------------------------------------
def upsert_indicators(
    session: Session,
    *,
    org_id: str,
    feed: ThreatFeed | None,
    drafts: Iterable[IndicatorDraft],
    now: datetime,
) -> tuple[int, int]:
    """Insert new indicators or refresh existing ones (dedup on
    (org, type, value)). Returns (created, updated)."""
    created = updated = 0
    default_conf = feed.default_confidence if feed else 50
    default_sev = feed.default_severity if feed else FindingSeverity.HIGH.value
    default_tlp = feed.tlp if feed else "amber"

    # Cache rows touched in this batch so a feed listing the same IOC twice
    # (e.g. differently-cased) updates the pending row instead of inserting a
    # duplicate that trips the unique constraint at flush.
    seen: dict[tuple[str, str], ThreatIndicator] = {}

    for draft in drafts:
        if created + updated >= MAX_INDICATORS_PER_SYNC:
            break
        value = normalize_indicator(draft.type, draft.value)
        if value is None:
            continue
        severity = draft.severity or default_sev
        if severity not in _SEVERITY_ORDER:
            severity = default_sev
        confidence = draft.confidence if draft.confidence is not None else default_conf
        confidence = max(0, min(100, confidence))

        key = (draft.type, value)
        existing = seen.get(key)
        if existing is None:
            existing = session.execute(
                select(ThreatIndicator).where(
                    ThreatIndicator.organization_id == org_id,
                    ThreatIndicator.type == draft.type,
                    ThreatIndicator.value == value,
                )
            ).scalar_one_or_none()
        if existing is not None:
            existing.last_seen = now
            existing.confidence = confidence
            existing.severity = severity
            existing.enabled = True
            if draft.expires_at is not None:
                existing.expires_at = draft.expires_at
            if feed is not None:
                existing.feed_id = feed.id
            if draft.tags:
                existing.tags = draft.tags
            if draft.references:
                existing.references = draft.references
            if draft.description:
                existing.description = draft.description
            seen[key] = existing
            updated += 1
        else:
            indicator = ThreatIndicator(
                organization_id=org_id,
                feed_id=feed.id if feed else None,
                type=draft.type,
                value=value,
                confidence=confidence,
                severity=severity,
                tags=draft.tags,
                references=draft.references,
                description=draft.description,
                tlp=default_tlp,
                first_seen=now,
                last_seen=now,
                expires_at=draft.expires_at,
            )
            session.add(indicator)
            seen[key] = indicator
            created += 1
    return created, updated


# ---------------------------------------------------------------------------
# Sync
# ---------------------------------------------------------------------------
def fetch_feed_content(
    feed: ThreatFeed, http_client: httpx.Client | None = None
) -> str:
    """Egress-guarded fetch of a remote feed body (size-capped)."""
    if not feed.url:
        raise FeedParseError("feed has no URL to fetch")
    # SSRF guard: refuse internal / non-global targets (feed URLs are
    # attacker-influenced tenant config).
    assert_safe_webhook_url(feed.url)
    headers: dict[str, str] = {}
    auth_header = unseal(feed.auth_header)
    if auth_header and ":" in auth_header:
        name, _, val = auth_header.partition(":")
        headers[name.strip()] = val.strip()
    with owned_client(http_client, timeout=FETCH_TIMEOUT_SECONDS) as client:
        resp = client.get(feed.url, headers=headers)
        resp.raise_for_status()
        body = resp.content[:MAX_FEED_BYTES]
    return body.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# TAXII 2.1
# ---------------------------------------------------------------------------
TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
MAX_TAXII_PAGES = 50


def _taxii_headers(feed_auth_header: str | None) -> dict[str, str]:
    headers = {"Accept": TAXII_MEDIA_TYPE}
    if feed_auth_header and ":" in feed_auth_header:
        name, _, val = feed_auth_header.partition(":")
        headers[name.strip()] = val.strip()
    return headers


def _rfc3339(value: datetime) -> str:
    """TAXII `added_after` timestamp: RFC3339 UTC with a trailing Z."""
    aware = value if value.tzinfo else value.replace(tzinfo=UTC)
    return aware.astimezone(UTC).isoformat().replace("+00:00", "Z")


def poll_taxii_collection(
    url: str,
    *,
    auth_header: str | None = None,
    added_after: datetime | None = None,
    http_client: httpx.Client | None = None,
    max_pages: int = MAX_TAXII_PAGES,
) -> list[dict[str, Any]]:
    """Poll a TAXII 2.1 collection objects endpoint and return STIX objects.

    Follows the envelope's ``more``/``next`` pagination and, when
    ``added_after`` is given, requests only objects added since then
    (incremental polling). SSRF-guarded and bounded by ``max_pages`` and the
    per-sync indicator cap.
    """
    if not url:
        raise FeedParseError("TAXII feed has no collection URL")
    assert_safe_webhook_url(url)
    headers = _taxii_headers(auth_header)

    params: dict[str, str] = {}
    if added_after is not None:
        params["added_after"] = _rfc3339(added_after)

    objects: list[dict[str, Any]] = []
    next_cursor: str | None = None
    with owned_client(http_client, timeout=FETCH_TIMEOUT_SECONDS) as client:
        for _ in range(max_pages):
            page_params = dict(params)
            if next_cursor:
                page_params["next"] = next_cursor
            resp = client.get(url, headers=headers, params=page_params)
            resp.raise_for_status()
            envelope = resp.json()
            if not isinstance(envelope, dict):
                raise FeedParseError("TAXII response is not a JSON envelope")
            page_objects = envelope.get("objects", [])
            if isinstance(page_objects, list):
                objects.extend(o for o in page_objects if isinstance(o, dict))
            if len(objects) >= MAX_INDICATORS_PER_SYNC:
                break
            if not envelope.get("more"):
                break
            next_cursor = envelope.get("next")
            if not next_cursor:
                break
    return objects


def discover_taxii_collections(
    api_root_url: str,
    *,
    auth_header: str | None = None,
    http_client: httpx.Client | None = None,
) -> list[dict[str, Any]]:
    """List collections under a TAXII 2.1 API root (`{api_root}/collections/`).

    Returns each collection's id/title/description plus a ready-to-use
    ``objects_url`` to configure a feed with. SSRF-guarded.
    """
    base = api_root_url.rstrip("/")
    collections_url = base + "/collections/"
    assert_safe_webhook_url(collections_url)
    with owned_client(http_client, timeout=FETCH_TIMEOUT_SECONDS) as client:
        resp = client.get(collections_url, headers=_taxii_headers(auth_header))
        resp.raise_for_status()
        body = resp.json()
    raw = body.get("collections", []) if isinstance(body, dict) else []
    out: list[dict[str, Any]] = []
    for c in raw:
        if not isinstance(c, dict) or not c.get("id"):
            continue
        cid = str(c["id"])
        out.append(
            {
                "id": cid,
                "title": c.get("title"),
                "description": c.get("description"),
                "can_read": bool(c.get("can_read", True)),
                "media_types": c.get("media_types", []),
                "objects_url": f"{base}/collections/{cid}/objects/",
            }
        )
    return out


def _sync_taxii(
    feed: ThreatFeed, http_client: httpx.Client | None
) -> list[IndicatorDraft]:
    objects = poll_taxii_collection(
        feed.url or "",
        auth_header=unseal(feed.auth_header),
        added_after=feed.last_synced_at,
        http_client=http_client,
    )
    return parse_stix_objects(objects)


def sync_feed(
    session: Session,
    feed: ThreatFeed,
    *,
    http_client: httpx.Client | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Fetch → parse → upsert one feed, recording status on the row.

    Never raises: fetch/parse failures are captured on the feed as an error
    status so a bad feed can't break a scheduled sweep.
    """
    now = now or datetime.now(UTC)
    if not feed.url:
        # Manual feed — nothing to fetch. Just refresh its count.
        feed.last_synced_at = now
        feed.last_status = FeedSyncStatus.OK.value
        feed.last_error = None
        feed.indicator_count = _count_indicators(session, feed.id)
        return {"created": 0, "updated": 0, "status": FeedSyncStatus.OK.value}

    try:
        if feed.format == FeedFormat.TAXII:
            drafts = _sync_taxii(feed, http_client)
        else:
            content = fetch_feed_content(feed, http_client)
            drafts = parse_feed(content, feed)
        created, updated = upsert_indicators(
            session, org_id=feed.organization_id, feed=feed, drafts=drafts, now=now
        )
        session.flush()
        feed.last_synced_at = now
        feed.last_status = FeedSyncStatus.OK.value
        feed.last_error = None
        feed.indicator_count = _count_indicators(session, feed.id)
        return {
            "created": created,
            "updated": updated,
            "status": FeedSyncStatus.OK.value,
        }
    except (EgressBlocked, FeedParseError, httpx.HTTPError, OSError) as exc:
        feed.last_synced_at = now
        feed.last_status = FeedSyncStatus.ERROR.value
        feed.last_error = f"{type(exc).__name__}: {exc}"[:1000]
        return {
            "created": 0,
            "updated": 0,
            "status": FeedSyncStatus.ERROR.value,
            "error": feed.last_error,
        }


def _count_indicators(session: Session, feed_id: str) -> int:
    from sqlalchemy import func

    return int(
        session.execute(
            select(func.count())
            .select_from(ThreatIndicator)
            .where(ThreatIndicator.feed_id == feed_id)
        ).scalar_one()
    )


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------
@dataclass
class IndicatorMeta:
    id: str
    type: str
    value: str
    severity: str
    confidence: int


@dataclass
class IndicatorIndex:
    """Prebuilt lookup over an org's active indicators for fast matching."""

    exact: dict[str, dict[str, IndicatorMeta]] = field(default_factory=dict)
    urls: list[IndicatorMeta] = field(default_factory=list)
    packages: list[IndicatorMeta] = field(default_factory=list)
    tool_names: dict[str, IndicatorMeta] = field(default_factory=dict)
    signatures: list[IndicatorMeta] = field(default_factory=list)
    regexes: list[tuple[re.Pattern[str], IndicatorMeta]] = field(
        default_factory=list
    )

    def is_empty(self) -> bool:
        return not (
            self.exact
            or self.urls
            or self.packages
            or self.tool_names
            or self.signatures
            or self.regexes
        )


def build_index(
    session: Session, org_id: str, now: datetime | None = None
) -> IndicatorIndex:
    """Load active, unexpired indicators into an `IndicatorIndex`."""
    now = now or datetime.now(UTC)
    naive_now = now.replace(tzinfo=None) if now.tzinfo else now
    rows = list(
        session.execute(
            select(
                ThreatIndicator.id,
                ThreatIndicator.type,
                ThreatIndicator.value,
                ThreatIndicator.severity,
                ThreatIndicator.confidence,
                ThreatIndicator.expires_at,
            )
            .where(
                ThreatIndicator.organization_id == org_id,
                ThreatIndicator.enabled.is_(True),
            )
            .limit(MAX_SCAN_INDICATORS)
        ).all()
    )
    index = IndicatorIndex()
    for r in rows:
        if r.expires_at is not None:
            exp = r.expires_at
            exp_cmp = exp.replace(tzinfo=None) if exp.tzinfo else exp
            if exp_cmp <= naive_now:
                continue
        meta = IndicatorMeta(
            id=r.id,
            type=r.type,
            value=r.value,
            severity=r.severity,
            confidence=r.confidence,
        )
        if r.type in EXACT_MATCH_TYPES and r.type != IndicatorType.URL.value:
            index.exact.setdefault(r.type, {})[r.value] = meta
        if r.type == IndicatorType.URL.value:
            index.urls.append(meta)
        elif r.type == IndicatorType.PACKAGE.value:
            index.packages.append(meta)
        elif r.type == IndicatorType.TOOL_NAME.value:
            index.tool_names[r.value.lower()] = meta
        elif r.type == IndicatorType.PROMPT_SIGNATURE.value:
            index.signatures.append(meta)
        elif r.type == IndicatorType.REGEX.value:
            try:
                index.regexes.append((re.compile(r.value, re.IGNORECASE), meta))
            except re.error:
                continue
    return index


def _extract(text: str) -> dict[str, set[str]]:
    return {
        IndicatorType.URL.value: set(_RE_URL.findall(text)),
        IndicatorType.DOMAIN.value: set(_RE_DOMAIN.findall(text)),
        IndicatorType.IP.value: set(_RE_IPV4.findall(text)),
        IndicatorType.EMAIL.value: set(_RE_EMAIL.findall(text)),
        IndicatorType.SHA256.value: set(_RE_SHA256.findall(text)),
        IndicatorType.MD5.value: set(_RE_MD5.findall(text)),
    }


def match_activity(
    index: IndicatorIndex, tool_name: str, tool_arguments: Any
) -> list[IndicatorMeta]:
    """Return indicators matched by one event's tool name + arguments."""
    if index.is_empty():
        return []
    try:
        args_text = json.dumps(tool_arguments, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        args_text = str(tool_arguments)
    text = f"{tool_name}\n{args_text}"[:MAX_EVENT_TEXT].lower()

    hits: dict[str, IndicatorMeta] = {}
    extracted = _extract(text)

    # Exact-match types (domain also matches subdomains of an indicator).
    for itype, bucket in index.exact.items():
        found = extracted.get(itype, set())
        if itype == IndicatorType.DOMAIN.value:
            for dom in found:
                for ind_val, meta in bucket.items():
                    if dom == ind_val or dom.endswith("." + ind_val):
                        hits[meta.id] = meta
        else:
            for val in found:
                hit = bucket.get(val)
                if hit is not None:
                    hits[hit.id] = hit

    # URL / package / signature: substring presence.
    for meta in (*index.urls, *index.packages, *index.signatures):
        if meta.value.lower() in text:
            hits[meta.id] = meta

    # Tool name: exact (case-insensitive) or substring.
    tl = tool_name.lower()
    exact_tool = index.tool_names.get(tl)
    if exact_tool is not None:
        hits[exact_tool.id] = exact_tool
    for name, meta in index.tool_names.items():
        if name in text:
            hits[meta.id] = meta

    # Regex signatures.
    for pattern, meta in index.regexes:
        if pattern.search(text):
            hits[meta.id] = meta

    return list(hits.values())


__all__ = [
    "FeedParseError",
    "IndicatorDraft",
    "IndicatorIndex",
    "IndicatorMeta",
    "build_index",
    "discover_taxii_collections",
    "fetch_feed_content",
    "match_activity",
    "normalize_indicator",
    "parse_feed",
    "parse_stix_objects",
    "poll_taxii_collection",
    "severity_rank",
    "sync_feed",
    "upsert_indicators",
]
