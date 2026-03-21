from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class BrainResult:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    model: str = ""


class BrainProvider(Protocol):
    name: str

    def generate(self, prompt: str, system: str = "") -> BrainResult:
        """Return a generated response with usage metadata."""
