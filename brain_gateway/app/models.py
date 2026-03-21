from pydantic import BaseModel, Field


class JsonRpcRequest(BaseModel):
    jsonrpc: str = Field(default="2.0")
    id: int | str | None = None
    method: str
    params: dict = Field(default_factory=dict)
