# tests/conftest.py
from typing import Any, Dict
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def mock_iam_data():
    """Mock IAMData to return consistent test data"""
    with patch("py_iam_expand.actions.iam_data") as mock:
        mock.services.get_service_keys.return_value = ["S3", "EC2", "IAM", "STS"]
        mock.actions.get_actions_for_service.side_effect = lambda service: {
            "S3": ["GetObject", "GetBucket"],
            "EC2": ["DescribeInstances", "DescribeVolumes"],
            "IAM": ["PassRole", "CreateAccessKey", "ListAccessKeys"],
            "STS": ["AssumeRole"],
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
