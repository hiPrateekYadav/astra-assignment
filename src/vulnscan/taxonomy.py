"""The closed vocabulary of vulnerability types."""

from pathlib import Path

import yaml
from pydantic import BaseModel

OTHER_TYPE = "other"


class VulnerabilityType(BaseModel):
    id: str
    cwe: int | None = None
    description: str


class Taxonomy(BaseModel):
    types: list[VulnerabilityType]

    @property
    def ids(self) -> set[str]:
        return {item.id for item in self.types}

    def render(self) -> str:
        return "\n".join(f"- {item.id}: {item.description}" for item in self.types)


def load_taxonomy(path: Path) -> Taxonomy:
    return Taxonomy.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
