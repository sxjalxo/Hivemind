from pydantic import BaseModel, ConfigDict


def to_camel(snake: str) -> str:
    head, *tail = snake.split("_")
    return head + "".join(word.capitalize() for word in tail)


class CamelModel(BaseModel):
    """Base for every model crossing the API boundary.

    Serializes snake_case Python fields as camelCase JSON to match the
    TypeScript types in frontend/src/types/.
    """

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )
