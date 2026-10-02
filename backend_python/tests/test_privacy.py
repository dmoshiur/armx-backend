# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import pytest
from pydantic import ValidationError

from app.activity.schemas import RulePayload
from app.core.privacy import contains_raw_biometric_data
from app.devices.schemas import DeviceCommandRequest


def test_raw_biometric_fields_are_rejected_recursively() -> None:
    assert contains_raw_biometric_data({"nested": {"faceTemplate": "secret"}})
    assert contains_raw_biometric_data({"payload": "data:image/png;base64,AAAA"})
    assert contains_raw_biometric_data({"user_text": "A" * 300})
    assert not contains_raw_biometric_data({"threshold": 0.4, "label": "entry light"})


def test_device_command_and_rule_payload_reject_biometric_data() -> None:
    with pytest.raises(ValidationError):
        DeviceCommandRequest.model_validate(
            {"command": "relay:ON", "parameters": {"audio": "raw bytes"}}
        )

    with pytest.raises(ValidationError):
        RulePayload.model_validate(
            {
                "id": "rule-1",
                "name": "Light rule",
                "trigger_type": "ACTIVITY_IS",
                "action_type": "DEVICE_COMMAND",
                "action_params": {"face_template": "not allowed"},
            }
        )
