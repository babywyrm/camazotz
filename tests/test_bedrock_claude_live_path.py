from unittest.mock import MagicMock, patch

from brain_gateway.app.brain import bedrock_claude
from brain_gateway.app.brain.bedrock_claude import BedrockClaudeProvider


def test_bedrock_provider_calls_anthropic_bedrock_when_client_live(monkeypatch) -> None:
    monkeypatch.setenv(
        "CAMAZOTZ_MODEL",
        "us.anthropic.claude-3-5-sonnet-20241022-v2:0",
    )
    mock_content = MagicMock()
    mock_content.text = "mocked bedrock response"
    mock_usage = MagicMock()
    mock_usage.input_tokens = 50
    mock_usage.output_tokens = 100
    mock_response = MagicMock()
    mock_response.content = [mock_content]
    mock_response.usage = mock_usage

    with patch("brain_gateway.app.brain.bedrock_claude.anthropic.AnthropicBedrock") as mock_cls:
        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response
        mock_cls.return_value = mock_client

        provider = BedrockClaudeProvider()
        provider._client = mock_client
        result = provider.generate("test prompt", system="test system")

    assert result.text == "mocked bedrock response"
    assert result.input_tokens == 50
    assert result.output_tokens == 100
    assert result.cost_usd > 0
    mock_client.messages.create.assert_called_once()


def test_aws_credentials_available_false_when_no_session_creds(monkeypatch) -> None:
    monkeypatch.delenv("CAMAZOTZ_BEDROCK_STUB", raising=False)

    fake_session = MagicMock()
    fake_session.get_credentials.return_value = None
    with patch("brain_gateway.app.brain.bedrock_claude.boto3.Session", return_value=fake_session):
        assert bedrock_claude._aws_credentials_available() is False


def test_aws_credentials_available_exception_returns_false(monkeypatch) -> None:
    monkeypatch.delenv("CAMAZOTZ_BEDROCK_STUB", raising=False)

    with patch(
        "brain_gateway.app.brain.bedrock_claude.boto3.Session",
        side_effect=RuntimeError("no creds"),
    ):
        assert bedrock_claude._aws_credentials_available() is False


def test_bedrock_no_client_when_no_aws_credentials(monkeypatch) -> None:
    monkeypatch.delenv("CAMAZOTZ_BEDROCK_STUB", raising=False)
    with patch.object(bedrock_claude, "_aws_credentials_available", return_value=False):
        p = BedrockClaudeProvider()
        assert p._client is None


def test_bedrock_instantiates_anthropic_bedrock_when_credentials_present(monkeypatch) -> None:
    monkeypatch.delenv("CAMAZOTZ_BEDROCK_STUB", raising=False)
    monkeypatch.setenv("AWS_REGION", "us-west-2")

    with patch.object(bedrock_claude, "_aws_credentials_available", return_value=True):
        with patch("brain_gateway.app.brain.bedrock_claude.anthropic.AnthropicBedrock") as mock_ab:
            mock_ab.return_value = MagicMock()
            p = BedrockClaudeProvider()
            assert p._client is not None
            mock_ab.assert_called_once_with(aws_region="us-west-2")


def test_bedrock_instantiates_without_explicit_region(monkeypatch) -> None:
    monkeypatch.delenv("CAMAZOTZ_BEDROCK_STUB", raising=False)
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)

    with patch.object(bedrock_claude, "_aws_credentials_available", return_value=True):
        with patch("brain_gateway.app.brain.bedrock_claude.anthropic.AnthropicBedrock") as mock_ab:
            mock_ab.return_value = MagicMock()
            p = BedrockClaudeProvider()
            assert p._client is not None
            mock_ab.assert_called_once_with()


def test_bedrock_generate_returns_error_when_model_unset(monkeypatch) -> None:
    monkeypatch.delenv("CAMAZOTZ_BEDROCK_STUB", raising=False)
    monkeypatch.delenv("CAMAZOTZ_MODEL", raising=False)
    monkeypatch.delenv("CAMAZOTZ_BEDROCK_MODEL", raising=False)
    mock_client = MagicMock()
    provider = BedrockClaudeProvider()
    provider._client = mock_client
    result = provider.generate("x")
    assert "[bedrock-error]" in result.text
    assert "CAMAZOTZ_MODEL" in result.text
    mock_client.messages.create.assert_not_called()


def test_bedrock_generate_returns_error_on_api_exception(monkeypatch) -> None:
    monkeypatch.delenv("CAMAZOTZ_BEDROCK_STUB", raising=False)
    monkeypatch.setenv(
        "CAMAZOTZ_MODEL",
        "us.anthropic.claude-3-5-sonnet-20241022-v2:0",
    )
    mock_client = MagicMock()
    mock_client.messages.create.side_effect = RuntimeError("throttle")

    provider = BedrockClaudeProvider()
    provider._client = mock_client
    result = provider.generate("x")
    assert "[bedrock-error]" in result.text
