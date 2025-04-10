from typing import Any, Dict
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def mock_iam_data():
    """Mock IAMData to return consistent test data"""
    with patch("py_iam_expand.actions.iam_data") as mock:
        mock.services.get_service_keys.return_value = ["s3", "ec2", "iam", "sts"]
        mock.actions.get_actions_for_service.side_effect = lambda service: {
            "s3": ["GetObject", "GetBucket"],
            "ec2": ["DescribeInstances", "DescribeVolumes"],
            "iam": ["PassRole", "CreateAccessKey", "ListAccessKeys"],
            "sts": ["AssumeRole"],
        }.get(service, [])
        yield mock


@pytest.fixture
def sample_policy() -> Dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"},
            {
                "Effect": "Deny",
                "NotAction": ["ec2:Describe*", "iam:*AccessKey*"],
                "Resource": "*",
            },
        ],
    }
