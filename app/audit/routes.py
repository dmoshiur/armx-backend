# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import query_audit
from app.auth.dependencies import Principal, require_principal
from app.db.session import get_session

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
async def get_audit(
    from_at: Annotated[datetime | None, Query(alias="from")] = None,
    to_at: Annotated[datetime | None, Query(alias="to")] = None,
    risk_tier: Literal["LOW", "MEDIUM", "HIGH"] | None = None,
    outcome: Literal["SUCCESS", "FAILURE", "DENIED"] | None = None,
    actor: Annotated[str, Query(max_length=80)] = "",
    search: Annotated[str, Query(max_length=160)] = "",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=10_000)] = 0,
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
) -> list[dict[str, object]]:
    return await query_audit(
        session,
        principal,
        from_at=from_at,
        to_at=to_at,
        risk_tier=risk_tier,
        outcome=outcome,
        actor=actor,
        search=search,
        limit=limit,
        offset=offset,
    )
