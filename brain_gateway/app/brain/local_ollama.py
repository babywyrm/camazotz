class LocalOllamaProvider:
    name = "local"

    def generate(self, prompt: str, system: str = "") -> str:
        return f"[local-stub] {prompt}"
