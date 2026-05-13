"""LLM provider interfaces for future InvariantOS workflows."""

from invariant_os.llm.base import LLMProvider
from invariant_os.llm.mock import MockProvider

__all__ = ["LLMProvider", "MockProvider"]
