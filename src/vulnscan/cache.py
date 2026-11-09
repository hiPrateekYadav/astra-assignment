"""Disk cache of validated model responses, so a rerun pays only for unfinished chunks."""

import hashlib
import json
from pathlib import Path

from pydantic import BaseModel


class ResponseCache:
    def __init__(self, directory: Path, enabled: bool = True) -> None:
        self.directory = directory
        self.enabled = enabled

    def _path(self, key_parts: list) -> Path:
        digest = hashlib.sha256(json.dumps(key_parts, sort_keys=True).encode()).hexdigest()
        return self.directory / f"{digest}.json"

    def get[SchemaT: BaseModel](self, key_parts: list, schema: type[SchemaT]) -> SchemaT | None:
        path = self._path(key_parts)
        if not self.enabled or not path.is_file():
            return None
        return schema.model_validate_json(path.read_text(encoding="utf-8"))

    def put(self, key_parts: list, value: BaseModel) -> None:
        if not self.enabled:
            return
        self.directory.mkdir(parents=True, exist_ok=True)
        temporary = self._path(key_parts).with_suffix(".tmp")
        temporary.write_text(value.model_dump_json(), encoding="utf-8")
        temporary.replace(self._path(key_parts))  # a crash must not leave a torn entry
