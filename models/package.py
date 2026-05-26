from typing import Any
from pydantic import BaseModel, Field, field_validator

from models.checks import (
    AttestationChecks,
    DepsDevChecks,
    MaintainerChecks,
    MetadataChecks,
    OSVChecks,
    PackageDiffChecks,
    ReleaseAgeChecks,
    ReleaseChecks,
    ScorecardChecks,
    SecurityAdvisoryChecks,
    SocketChecks,
    VersionLineageChecks,
)
from models.pr import _validate_ecosystem_name


class PackageChecks(BaseModel):
    ecosystem: str
    package_name: str
    old_version: str
    new_version: str
    metadata: MetadataChecks = Field(default_factory=MetadataChecks)
    socket: SocketChecks = Field(default_factory=SocketChecks)
    osv: OSVChecks = Field(default_factory=OSVChecks)
    diff: PackageDiffChecks = Field(default_factory=PackageDiffChecks)
    maintainer: MaintainerChecks = Field(default_factory=MaintainerChecks)
    age: ReleaseAgeChecks = Field(default_factory=ReleaseAgeChecks)
    attestation: AttestationChecks = Field(default_factory=AttestationChecks)
    release: ReleaseChecks = Field(default_factory=ReleaseChecks)
    version_lineage: VersionLineageChecks = Field(default_factory=VersionLineageChecks)
    deps_dev: DepsDevChecks = Field(default_factory=DepsDevChecks)
    scorecard: ScorecardChecks = Field(default_factory=ScorecardChecks)
    advisory: SecurityAdvisoryChecks = Field(default_factory=SecurityAdvisoryChecks)
    custom_checks: dict[str, Any] = Field(default_factory=dict)  # plugin-supplied check results

    @field_validator("ecosystem")
    @classmethod
    def ecosystem_must_be_registered(cls, v: str) -> str:
        return _validate_ecosystem_name(v)
