class LocalOllamaProvider:
    name = "local"

    def generate(self, prompt: str) -> str:
        # Placeholder for local Ollama integration.
        return f"[local] {prompt}"
