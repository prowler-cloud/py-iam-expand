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

    def test_expand_policy_with_unicode(self):
        """Test handling of Unicode characters in policy"""
        policy = {
            "Statement": [
                {"Effect": "\u0041llow", "Action": "s3:Get*"}  # Unicode "Allow"
            ]
        }
        result = expand_policy_actions(policy)
        assert result["Statement"][0]["Effect"] == "Allow"
        assert isinstance(result["Statement"][0]["Action"], list)

    def test_expand_policy_empty_actions(self):
        """Test handling of empty action lists"""
        policy = {"Statement": [{"Action": []}]}
        result = expand_policy_actions(policy)
        assert result["Statement"][0]["Action"] == []

    def test_expand_policy_mixed_actions(self):
        """Test policy with both Action and NotAction"""
        policy = {"Statement": [{"Action": "s3:Get*", "NotAction": "iam:*"}]}
        result = expand_policy_actions(policy)
        assert isinstance(result["Statement"][0]["Action"], list)
        assert isinstance(result["Statement"][0]["NotAction"], list)

    @pytest.mark.parametrize(
        "invalid_action",
        [
            123,  # Number
            True,  # Boolean
            {"key": "value"},  # Dictionary
            None,  # None
        ],
    )
    def test_expand_policy_invalid_action_types(self, invalid_action):
        """Test handling of invalid action value types"""
        policy = {"Statement": [{"Action": invalid_action}]}
        with pytest.raises(TypeError):
            expand_policy_actions(policy)
