# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.activity.schemas import RuleDryRunResponse, RulePayload, RuleResponse
from app.audit.service import write_audit
from app.auth.dependencies import Principal, require_principal
from app.core.errors import APIError
from app.db.models import AutomationRule
from app.db.session import get_session

router = APIRouter(prefix="/rules", tags=["rules"])
_ACTION_RISK = {
    "DEVICE_COMMAND": "HIGH",
    "SCENE": "MEDIUM",
    "NOTIFY": "LOW",
    "UNLOCK_PREPARE": "HIGH",
    "ASSISTANT_PROMPT": "MEDIUM",
}


def _response(row: AutomationRule) -> RuleResponse:
    return RuleResponse(
        id=row.id,
        name=row.name,
        trigger_type=row.trigger_type,
        action_type=row.action_type,
        enabled=row.enabled,
        dry_run=row.dry_run,
        risk_tier=row.risk_tier,
        trigger_params=row.trigger_params,
        action_params=row.action_params,
        geofence_id=row.geofence_id,
        device_id=row.device_id,
        last_run_at=row.last_run_at,
        run_count=row.run_count,
    )


@router.get("", response_model=list[RuleResponse])
async def list_rules(
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
) -> list[RuleResponse]:
    rows = (
        await session.scalars(
            select(AutomationRule)
            .where(AutomationRule.owner_id == principal.user.id)
            .order_by(AutomationRule.created_at)
        )
    ).all()
    return [_response(row) for row in rows]


@router.post("", response_model=RuleResponse)
async def upsert_rule(
    body: RulePayload,
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
) -> RuleResponse:
    row = await session.get(AutomationRule, body.id)
    if row is not None and row.owner_id != principal.user.id:
        raise APIError("rule_not_found", "Rule was not found", status_code=404)
    required_tier = _ACTION_RISK[body.action_type]
    if row is None:
        row = AutomationRule(
            id=body.id,
            owner_id=principal.user.id,
            name=body.name,
            trigger_type=body.trigger_type,
            action_type=body.action_type,
            risk_tier=required_tier,
        )
        session.add(row)
    row.name = body.name
    row.trigger_type = body.trigger_type
    row.action_type = body.action_type
    row.enabled = body.enabled
    row.dry_run = body.dry_run
    # `risk_tier` from the client is deliberately ignored. The server's action
    # policy is authoritative and the rule does not execute at save time.
    row.risk_tier = required_tier
    row.trigger_params = body.trigger_params
    row.action_params = body.action_params
    row.geofence_id = body.geofence_id
    row.device_id = body.device_id
    await write_audit(
        session,
        actor_user_id=principal.user.id,
        subject_user_id=principal.user.id,
        device_id=principal.device.id,
        action="rules.upsert",
        target=row.id,
        risk_tier=required_tier,
        detail="Automation rule stored; no action was executed.",
    )
    await session.commit()
    await session.refresh(row)
    return _response(row)


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: str,
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
) -> Response:
    row = await session.get(AutomationRule, rule_id)
    if row is not None and row.owner_id == principal.user.id:
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=principal.user.id,
            device_id=principal.device.id,
            action="rules.delete",
            target=row.id,
            risk_tier=row.risk_tier,
            detail="Automation rule deleted.",
        )
        await session.delete(row)
        await session.commit()
    return Response(status_code=204)


@router.post("/dry-run", response_model=RuleDryRunResponse)
async def dry_run_rule(
    body: RulePayload,
    principal: Principal = Depends(require_principal),
) -> RuleDryRunResponse:
    del principal
    now = datetime.now(UTC)
    required_tier = _ACTION_RISK[body.action_type]
    would_fire = body.enabled
    blocked_reason = "" if would_fire else "Rule is disabled"
    steps = [
        f"Evaluating WHEN {body.trigger_type}",
        f"Risk tier: {required_tier}",
        "Dry-run only: the THEN action will not execute",
        f"Would execute THEN {body.action_type}" if would_fire else "THEN action would not execute",
    ]
    return RuleDryRunResponse(
        rule_id=body.id,
        would_fire=would_fire,
        blocked_reason=blocked_reason,
        steps=steps,
        at=now,
    )
