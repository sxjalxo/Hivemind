from typing import Protocol, TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class LLMValidationError(RuntimeError):
    """The model returned something the schema rejects."""


class LLMClient(Protocol):
    @property
    def model_name(self) -> str: ...

    async def complete_json(self, prompt: str, schema: type[T]) -> T: ...
