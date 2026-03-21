from unittest.mock import MagicMock, patch

from brain_gateway.app.brain.cloud_claude import CloudClaudeProvider


def test_cloud_provider_calls_anthropic_when_key_present() -> None:
    mock_content = MagicMock()
    mock_content.text = "mocked claude response"
    mock_response = MagicMock()
    mock_response.content = [mock_content]

    with patch("brain_gateway.app.brain.cloud_claude.os.getenv", side_effect=lambda k, d="": "sk-fake" if k == "ANTHROPIC_API_KEY" else d):
        with patch("brain_gateway.app.brain.cloud_claude.anthropic.Anthropic") as mock_cls:
            mock_client = MagicMock()
            mock_client.messages.create.return_value = mock_response
            mock_cls.return_value = mock_client

            provider = CloudClaudeProvider()
            result = provider.generate("test prompt", system="test system")

    assert result == "mocked claude response"
    mock_client.messages.create.assert_called_once()
