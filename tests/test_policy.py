import pytest

from py_iam_expand.actions import InvalidActionHandling, InvalidActionPatternError
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

    @pytest.fixture
    def policy_with_invalid_actions(self):
        """Policy containing various invalid patterns"""
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:Get*", "invalid-format", "nonexistent:*"],
                    "Resource": "*",
                },
                {
                    "Effect": "Deny",
                    "NotAction": ["ec2:Describe*", "iam:no-colon", "fake-svc:*"],
                    "Resource": "*",
                },
            ],
        }

    def test_policy_invalid_action_raise(self, policy_with_invalid_actions):
        """Test RAISE_ERROR for invalid patterns in Action"""
        with pytest.raises(InvalidActionPatternError) as exc_info:
            expand_policy_actions(
                policy_with_invalid_actions,
                invalid_handling_action=InvalidActionHandling.RAISE_ERROR,
            )
        # Check that the error message indicates the first invalid pattern
        assert "invalid-format" in str(exc_info.value)
        assert "Statement 0" in str(exc_info.value)

    def test_policy_invalid_action_remove(self, policy_with_invalid_actions):
        """Test REMOVE for invalid patterns in Action"""
        result = expand_policy_actions(
            policy_with_invalid_actions,
            invalid_handling_action=InvalidActionHandling.REMOVE,
            # Keep NotAction default (KEEP) to isolate Action handling
        )
        # Valid action expanded, invalid ones removed
        assert result["Statement"][0]["Action"] == ["S3:GetBucket", "S3:GetObject"]
        # NotAction should still contain invalid patterns (default KEEP)
        assert "iam:no-colon" in result["Statement"][1]["NotAction"]
        assert "fake-svc:*" in result["Statement"][1]["NotAction"]

    def test_policy_invalid_action_keep(self, policy_with_invalid_actions):
        """Test KEEP for invalid patterns in Action"""
        result = expand_policy_actions(
            policy_with_invalid_actions,
            invalid_handling_action=InvalidActionHandling.KEEP,
            # Keep NotAction default (KEEP) to isolate Action handling
        )
        # Valid action expanded, invalid ones kept as-is
        expected_actions = sorted(
            ["S3:GetBucket", "S3:GetObject", "invalid-format", "nonexistent:*"]
        )
        assert result["Statement"][0]["Action"] == expected_actions
        # NotAction should still contain invalid patterns (default KEEP)
        assert "iam:no-colon" in result["Statement"][1]["NotAction"]
        assert "fake-svc:*" in result["Statement"][1]["NotAction"]

    def test_policy_invalid_notaction_raise(self, policy_with_invalid_actions):
        """Test RAISE_ERROR for invalid patterns in NotAction"""
        with pytest.raises(InvalidActionPatternError) as exc_info:
            expand_policy_actions(
                policy_with_invalid_actions,
                # Keep Action default (REMOVE) to isolate NotAction handling
                invalid_handling_notaction=InvalidActionHandling.RAISE_ERROR,
            )
        # Check that the error message indicates the first pattern that causes an error
        # In this case, it's the non-existent service 'fake-svc'
        error_message = str(exc_info.value)
        assert "fake-svc:*" in error_message  # Check the pattern causing the error
        assert (
            "Service 'fake-svc' not found" in error_message
        )  # Check the specific reason
        assert "Statement 1" in error_message  # Check the context

    def test_policy_invalid_notaction_remove(self, policy_with_invalid_actions):
        """Test REMOVE for invalid patterns in NotAction"""
        result = expand_policy_actions(
            policy_with_invalid_actions,
            # Keep Action default (REMOVE) to isolate NotAction handling
            invalid_handling_notaction=InvalidActionHandling.REMOVE,
        )
        # Action should have invalid patterns removed (default REMOVE)
        assert result["Statement"][0]["Action"] == ["S3:GetBucket", "S3:GetObject"]
        # Valid NotAction expanded, invalid ones removed
        assert result["Statement"][1]["NotAction"] == [
            "EC2:DescribeInstances",
            "EC2:DescribeVolumes",
        ]

    def test_policy_invalid_notaction_keep(self, policy_with_invalid_actions):
        """Test KEEP (default) for invalid patterns in NotAction"""
        result = expand_policy_actions(
            policy_with_invalid_actions,
            # Keep Action default (REMOVE) to isolate NotAction handling
            invalid_handling_notaction=InvalidActionHandling.KEEP,  # Explicitly set default
        )
        # Action should have invalid patterns removed (default REMOVE)
        assert result["Statement"][0]["Action"] == ["S3:GetBucket", "S3:GetObject"]
        # Valid NotAction expanded, invalid ones kept as-is
        expected_notactions = sorted(
            [
                "EC2:DescribeInstances",
                "EC2:DescribeVolumes",
                "iam:no-colon",
                "fake-svc:*",
            ]
        )
        assert result["Statement"][1]["NotAction"] == expected_notactions

    def test_policy_combined_handling(self, policy_with_invalid_actions):
        """Test different handling for Action (KEEP) and NotAction (REMOVE)"""
        result = expand_policy_actions(
            policy_with_invalid_actions,
            invalid_handling_action=InvalidActionHandling.KEEP,
            invalid_handling_notaction=InvalidActionHandling.REMOVE,
        )
        # Action: Valid expanded, invalid kept
        expected_actions = sorted(
            ["S3:GetBucket", "S3:GetObject", "invalid-format", "nonexistent:*"]
        )
        assert result["Statement"][0]["Action"] == expected_actions
        # NotAction: Valid expanded, invalid removed
        assert result["Statement"][1]["NotAction"] == [
            "EC2:DescribeInstances",
            "EC2:DescribeVolumes",
        ]
