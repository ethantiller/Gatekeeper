from typing import Any

from fastapi import APIRouter

router = APIRouter()


@router.post("/before-tool")
async def before_tool() -> dict[str, Any]:
    """Stub until GK-6b."""
    return {}
