from brain_gateway.app.brain.provider import BrainResult


class LocalOllamaProvider:
    name = "local"

    def generate(self, prompt: str, system: str = "") -> BrainResult:
        return BrainResult(text=f"[local-stub] {prompt}")
