import pytest

from py_iam_expand.policy import expand_policy_actions


class TestPolicyExpansion:
    def test_expand_basic_policy(self, sample_policy):
        """Test basic policy expansion"""
        result = expand_policy_actions(sample_policy)

        # Verify first statement (Action)
        assert result["Statement"][0]["Action"] == ["S3:GetBucket", "S3:GetObject"]

        # Verify second statement (NotAction)
        assert result["Statement"][1]["NotAction"] == [
            "EC2:DescribeInstances",
            "EC2:DescribeVolumes",
            "IAM:CreateAccessKey",
            "IAM:ListAccessKeys",
        ]

    def test_empty_policy(self):
        """Test handling of empty policy"""
        policy = {"Statement": []}
        result = expand_policy_actions(policy)
        assert result == policy

    def test_invalid_policy_structure(self):
        """Test handling of invalid policy structure"""
        invalid_policies = [
            {},  # Missing Statement
            {"Statement": "not-a-list"},  # Statement not a list
            {"Statement": [{"Action": 123}]},  # Invalid Action type
        ]

        for policy in invalid_policies:
            with pytest.raises((ValueError, TypeError)):
                expand_policy_actions(policy)
