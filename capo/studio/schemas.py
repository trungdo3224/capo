from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Union

class CommandModel(BaseModel):
    name: str
    description: str
    command: str
    tool: Optional[str] = None
    tags: Optional[List[str]] = []
    os: Optional[str] = None
    exam: Optional[List[str]] = []
    notes: Optional[str] = None

class CheatsheetModel(BaseModel):
    category: str
    description: str
    commands: List[CommandModel]

class ApplicableWhenModel(BaseModel):
    ports: Optional[List[int]] = []
    services: Optional[List[str]] = []

class StepModel(BaseModel):
    id: str
    name: str
    phase: str
    description: str
    commands: Optional[List[str]] = []
    check: Optional[Dict[str, Any]] = None

class MethodologyModel(BaseModel):
    name: str
    display_name: str
    description: str
    applicable_when: Optional[ApplicableWhenModel] = None
    steps: List[StepModel]
