import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class AffectedRange:
    type: str  # ECOSYSTEM, SEMVER, GIT, etc.
    introduced: str = "0"
    fixed: Optional[str] = None
    last_affected: Optional[str] = None
    repo: Optional[str] = None
    events: List[dict] = field(default_factory=list)


@dataclass
class Reference:
    url: str
    type: str  # ADVISORY, FIX, WEB, PACKAGE, etc.


@dataclass
class CVEData:
    cve_id: str
    source: str
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    affected_ranges: List[AffectedRange] = field(default_factory=list)
    references: List[Reference] = field(default_factory=list)
    published_at: Optional[datetime] = None
    modified_at: Optional[datetime] = None
    raw_data: dict = field(default_factory=dict)


@dataclass
class MatchResult:
    affected: bool
    fixed_version: Optional[str] = None
    details: dict = field(default_factory=dict)