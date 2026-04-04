import os

import anthropic
import boto3

from brain_gateway.app.brain.provider import BrainResult
from brain_gateway.app.config import estimate_cost


def _aws_credentials_available() -> bool:
    try:
        return boto3.Session().get_credentials() is not None
    except Exception:
        return False


class BedrockClaudeProvider:
    """Claude via Amazon Bedrock (default brain for enterprise AWS deployments)."""

    name = "bedrock"

    def __init__(self) -> None:
        self._region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or ""
        if os.getenv("CAMAZOTZ_BEDROCK_STUB", "").lower() in ("1", "true", "yes"):
            self._client = None
        elif not _aws_credentials_available():
            self._client = None
        elif self._region:
            self._client = anthropic.AnthropicBedrock(aws_region=self._region)
        else:
            self._client = anthropic.AnthropicBedrock()

    def generate(self, prompt: str, system: str = "") -> BrainResult:
        if self._client is None:
            return BrainResult(text=f"[bedrock-stub] {prompt}")

        model = (os.getenv("CAMAZOTZ_BEDROCK_MODEL") or os.getenv("CAMAZOTZ_MODEL") or "").strip()
        if not model:
            return BrainResult(
                text=(
                    "[bedrock-error] Set CAMAZOTZ_MODEL or CAMAZOTZ_BEDROCK_MODEL "
                    "to your Bedrock inference profile or foundation model id."
                )
            )
        try:
            resp = self._client.messages.create(
                model=model,
                max_tokens=512,
                system=system or "You are a tool inside the Camazotz MCP security lab.",
                messages=[{"role": "user", "content": prompt}],
            )
        except Exception:
            return BrainResult(text=f"[bedrock-error] {prompt}")

        inp = resp.usage.input_tokens
        out = resp.usage.output_tokens
        return BrainResult(
            text=resp.content[0].text,
            input_tokens=inp,
            output_tokens=out,
            cost_usd=estimate_cost(inp, out),
            model=model,
        )
