from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class BrainResult:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    model: str = ""

    def usage_dict(self) -> dict[str, Any]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cost_usd": round(self.cost_usd, 6),
            "model": self.model,
        }


def attach_usage(response: dict[str, Any], result: BrainResult) -> None:
    from brain_gateway.app.config import show_tokens
    if show_tokens():
        response["_usage"] = result.usage_dict()


class BrainProvider(Protocol):
    name: str

    def generate(self, prompt: str, system: str = "") -> BrainResult:
        """Return a generated response with usage metadata."""
