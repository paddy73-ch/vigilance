"""One vulnerability, several advisories.

OSV often reports the same CVE more than once for Debian: as DEBIAN-CVE-2026-1234 (the
security tracker entry) and as DSA-1234-1 / DLA-… (the announcement of the fix). The UI
counts and lists vulnerabilities, not advisories, so these are merged by their CVE.
"""

import re
from typing import Iterable, List, Optional, Sequence, Union

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}


def _ids(upstream: Union[str, Sequence[str], None]) -> List[str]:
    if not upstream:
        return []
    if isinstance(upstream, str):
        return [u for u in upstream.split(",") if u]
    return [u for u in upstream if u]


def cves_of(advisory_id: str, upstream: Union[str, Sequence[str], None] = None) -> List[str]:
    """All CVE IDs an advisory refers to (its own ID first)."""
    found = []
    for text in [advisory_id or ""] + _ids(upstream):
        for m in _CVE_RE.findall(text):
            if m not in found:
                found.append(m)
    return found


def vuln_key(advisory_id: str, upstream: Union[str, Sequence[str], None] = None) -> Optional[str]:
    """The CVE an advisory stands for, or None for advisories covering several CVEs (or none).

    CVE-2026-1 -> CVE-2026-1; DEBIAN-CVE-2026-1 -> CVE-2026-1;
    DSA-6607-1 with upstream [CVE-2026-1] -> CVE-2026-1; DSA with two CVEs -> None.
    """
    m = _CVE_RE.search(advisory_id or "")
    if m:
        return m.group(0)
    cves = cves_of("", upstream)
    return cves[0] if len(cves) == 1 else None


def _rank(row: dict) -> tuple:
    return (SEVERITY_RANK.get((row.get("severity") or "NONE").upper(), 0), row.get("cvss") or 0)


def merge_advisories(rows: Iterable[dict], max_fields: Sequence[str] = (),
                     fill_fields: Sequence[str] = ("os_hint", "note")) -> List[dict]:
    """Merge advisory rows that describe the same CVE.

    Each row needs "id" and "upstream" (list). Returned rows get "label" (the CVE, or the
    advisory ID if there is none) and "also" (the other advisory IDs merged into this row).
    The row with the highest severity/CVSS represents the group; numeric fields listed in
    max_fields take the maximum of the group; fill_fields take the first value any member has.
    An advisory covering several CVEs is folded
    into those rows if every one of its CVEs is listed, otherwise it stays on its own.
    """
    keyed: dict = {}
    bundles = []
    for row in rows:
        key = vuln_key(row["id"], row.get("upstream"))
        if key is None:
            bundles.append(row)
            continue
        cur = keyed.get(key)
        if cur is None:
            keyed[key] = {**row, "label": key, "also": []}
            continue
        merged_ids = cur["also"] + [cur["id"]] if _rank(row) > _rank(cur) else None
        if merged_ids is not None:
            new = {**row, "label": key, "also": merged_ids}
            for f in max_fields:
                new[f] = _max(row.get(f), cur.get(f))
            for f in fill_fields:
                new[f] = row.get(f) or cur.get(f)
            keyed[key] = new
        else:
            cur["also"].append(row["id"])
            for f in max_fields:
                cur[f] = _max(row.get(f), cur.get(f))
            for f in fill_fields:
                cur[f] = cur.get(f) or row.get(f)
    out = list(keyed.values())
    for row in bundles:
        cves = cves_of("", row.get("upstream"))
        if cves and all(c in keyed for c in cves):
            for c in cves:
                keyed[c]["also"].append(row["id"])
        else:
            out.append({**row, "label": row["id"], "also": []})
    return out


def _max(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


def same_vulnerability(exception_id: str, advisory_id: str, upstream: Union[str, Sequence[str], None],
                       exception_upstream: Union[str, Sequence[str], None] = None) -> bool:
    """Does an exception created for exception_id also cover this advisory?

    exception_upstream: upstream IDs of the exception's own advisory. Needed when its ID has no CVE
    in it (DSA-6000-1 for CVE-2026-1234), otherwise its siblings are not recognised."""
    if exception_id == advisory_id:
        return True
    key = vuln_key(exception_id, exception_upstream)
    return key is not None and key == vuln_key(advisory_id, upstream)
