"""Mock LLM provider used by tests and offline development."""

from typing import Any


class MockProvider:
    """Return deterministic empty structured responses."""

    def complete_json(self, *, system_prompt: str, user_payload: dict[str, Any]) -> dict[str, Any]:
        return {"items": [], "summary": "", "metadata": {}}
