from typing import Protocol


class BrainProvider(Protocol):
    name: str

    def generate(self, prompt: str, system: str = "") -> str:
        """Return a generated response for a prompt."""
