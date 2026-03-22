from enum import StrEnum
from typing import Any, TypedDict


class Difficulty(StrEnum):
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"


class ToolDefinition(TypedDict):
    name: str
    description: str
    inputSchema: dict[str, Any]


class ObserverEvent(TypedDict):
    request_id: str
    tool_name: str
    module: str
    timestamp: str


class UsageInfo(TypedDict):
    input_tokens: int
    output_tokens: int
    cost_usd: float
    model: str
