"""Protocol for optional LLM providers."""

from typing import Any, Protocol


class LLMProvider(Protocol):
    """Minimal JSON-completion interface for future hypothesis generation."""

    def complete_json(self, *, system_prompt: str, user_payload: dict[str, Any]) -> dict[str, Any]:
        """Return a JSON-like response for the supplied prompt and payload."""
        ...
