from __future__ import annotations

from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class ArtifactKind(StrEnum):
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    DNS_ANSWER = "dns_answer"
    JS_FILE = "js_file"
    HTML_PAGE = "html_page"
    FORM_DATA = "form_data"
    TOOL_OUTPUT = "tool_output"
    OBSERVATION = "observation"
    VALIDATION = "validation"
    GENERIC = "generic"


class ArtifactRef(BaseModel):
    id: UUID
    sha256: str
    kind: ArtifactKind
    size_bytes: int = 0
    sensitivity: str = "normal"
    retention_days: int = 30


class ArtifactDraft(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    kind: ArtifactKind
    content: bytes = b""
    content_type: str = "application/octet-stream"
    source_task_id: str = ""
    sensitivity: str = "normal"
    retention_days: int = 30
    metadata: dict[str, str] = Field(default_factory=dict)
