from typing import Literal
from pydantic import BaseModel, Field, field_validator


class Verdict(BaseModel):
    classification: Literal["green", "yellow", "red"]
    confidence: float
    reasoning: str = Field(
        description=(
            "One to three sentences summarising the key risk factors and, when "
            "merge_recommendation differs from the classification, why the recommendation "
            "diverges. Plain text only — no markdown, no bullet points, no numbered lists. "
            "Single paragraph."
        )
    )
    flags: list[str] = Field(
        description=(
            "JSON array of strings. Each element is one short human-readable phrase "
            "describing a specific concern, e.g. 'major version bump', "
            "'release age 2 days', 'new outbound network calls in library code'. "
            "Do NOT use snake_case field names from the input JSON."
        )
    )
    merge_recommendation: Literal["merge", "hold"] | None = Field(
        default=None,
        description=(
            "Override the default action implied by the classification. "
            "'merge' = merging is recommended despite non-green signals "
            "(e.g. this bump patches a critical CVE and the yellow signals are confirmed benign). "
            "'hold' = hold for human review despite a green classification "
            "(e.g. an unusual signal warrants a second look). "
            "null = no override — follow the classification as normal."
        ),
    )

    @field_validator("flags", mode="before")
    @classmethod
    def coerce_flags_to_list(cls, v: object) -> object:
        if isinstance(v, str):
            return [f.strip() for f in v.replace(";", ",").split(",") if f.strip()]
        return v

    release_age_hours: float | None = None  # passed through for per-repo age gate enforcement
    new_dependency_count: int = 0  # passed through for per-repo max_new_dependencies gate
