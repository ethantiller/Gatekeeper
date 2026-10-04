from pydantic import BaseModel, ConfigDict


class HookPayload(BaseModel):
    """The fields we use from every hook body. Clients send more, so extras are ignored."""

    model_config = ConfigDict(extra="ignore")

    session_id: str
    cwd: str
