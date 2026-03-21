from typing import Any

from pydantic import BaseModel


class CommandModel(BaseModel):
    name: str
    description: str
    command: str
    tool: str | None = None
    tags: list[str] | None = []
    os: str | None = None
    exam: list[str] | None = []
    notes: str | None = None

class CheatsheetModel(BaseModel):
    category: str
    description: str
    commands: list[CommandModel]

class ApplicableWhenModel(BaseModel):
    ports: list[int] | None = []
    services: list[str] | None = []

class StepModel(BaseModel):
    id: str
    name: str
    phase: str
    description: str
    commands: list[str] | None = []
    check: dict[str, Any] | None = None

class MethodologyModel(BaseModel):
    name: str
    display_name: str
    description: str
    applicable_when: ApplicableWhenModel | None = None
    steps: list[StepModel]
