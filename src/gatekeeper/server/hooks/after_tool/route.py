from typing import Any

from fastapi import APIRouter

router = APIRouter()


@router.post("/after-tool")
async def after_tool() -> dict[str, Any]:
    """Stub until GK-6c."""
    return {}
