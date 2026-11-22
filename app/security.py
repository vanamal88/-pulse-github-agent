
import hmac

from fastapi import Header, HTTPException, Request, status

from app.config import get_settings


async def verify_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None),
) -> None:
    settings = get_settings()

    if not x_api_key or not hmac.compare_digest(
        x_api_key,
        settings.pulse_agent_api_key,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )
