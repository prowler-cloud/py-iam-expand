import pytest

from py_iam_expand.actions import (
    InvalidActionHandling,
    InvalidActionPatternError,
    expand_actions,
    invert_actions,
)


class TestActionExpansion:
    def test_expand_single_pattern(self):
        """Test expanding a single pattern"""
        result = expand_actions("s3:Get*")
        assert result == ["s3:GetBucket", "s3:GetObject"]

    def test_expand_multiple_patterns(self):
        """Test expanding multiple patterns"""
        result = expand_actions(["s3:Get*", "ec2:Describe*"])
        assert result == [
            "ec2:DescribeInstances",
            "ec2:DescribeVolumes",
            "s3:GetBucket",
            "s3:GetObject",
        ]

    def test_expand_all_wildcard(self):
        """Test expanding '*' pattern"""
        result = expand_actions("*")
        assert len(result) > 0
        assert all(":" in action for action in result)

    def test_expand_empty_list(self):
        """Test expanding empty list of patterns"""
        result = expand_actions([])
        assert result == []

    def test_expand_invalid_service(self):
        """Test handling of non-existent service"""
        # Test with RAISE_ERROR (default)
        with pytest.raises(InvalidActionPatternError) as exc_info:
            expand_actions("nonexistent:*")
        assert "Service 'nonexistent' not found" in str(exc_info.value)

        # Test with KEEP
        result = expand_actions(
            "nonexistent:*", invalid_handling=InvalidActionHandling.KEEP
        )
        assert result == ["nonexistent:*"]

        # Test with REMOVE
        result = expand_actions(
            "nonexistent:*", invalid_handling=InvalidActionHandling.REMOVE
        )
        assert result == []

    def test_expand_case_sensitivity(self):
        """Test case insensitive matching"""
        lower_result = expand_actions("s3:get*")
        upper_result = expand_actions("S3:GET*")
        mixed_result = expand_actions("s3:GeT*")
        assert lower_result == upper_result == mixed_result

    @pytest.mark.parametrize(
        "pattern",
        [
            "s3GetObject",  # Missing colon
            ":GetObject",  # Missing service
            "s3:",  # Missing action
            "",  # Empty string
        ],
    )
    def test_expand_invalid_formats(self, pattern):
        """Test various invalid pattern formats"""
        with pytest.raises(InvalidActionPatternError):
            expand_actions(pattern)


class TestActionInversion:

    # Define the expected full set of actions based on the conftest.py mock
    # This is what _get_all_actions() SHOULD return when using the mock
    EXPECTED_ALL_ACTIONS_FROM_MOCK = {
        "s3:GetObject",
        "s3:GetBucket",
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "iam:PassRole",
        "iam:CreateAccessKey",
        "iam:ListAccessKeys",
        "sts:AssumeRole",
    }

    def test_invert_single_pattern(self):
        """Test inverting a single pattern"""
        actions_to_exclude = {"s3:GetBucket", "s3:GetObject"}
        result = invert_actions("s3:Get*")
        expected = sorted(
            list(self.EXPECTED_ALL_ACTIONS_FROM_MOCK - actions_to_exclude)
        )
        assert result == expected

    def test_invert_multiple_patterns(self):
        """Test inverting multiple patterns"""
        actions_to_exclude = {
            "s3:GetBucket",
            "s3:GetObject",
            "ec2:DescribeInstances",
            "ec2:DescribeVolumes",
            "iam:PassRole",
        }
        result = invert_actions(["s3:Get*", "ec2:Describe*", "iam:PassRole"])
        expected = sorted(
            list(self.EXPECTED_ALL_ACTIONS_FROM_MOCK - actions_to_exclude)
        )
        assert result == expected

    def test_invert_all_wildcard(self):
        """Test inverting the '*' pattern (should exclude everything from the mock set)"""
        # expand_actions("*") will expand based on the conftest mock
        actions_to_exclude = self.EXPECTED_ALL_ACTIONS_FROM_MOCK
        result = invert_actions("*")
        # Subtracting all known mock actions from all known mock actions
        expected = sorted(
            list(self.EXPECTED_ALL_ACTIONS_FROM_MOCK - actions_to_exclude)
        )
        assert result == []
        assert expected == []  # Double check calculation

    def test_invert_empty_list(self):
        """Test inverting an empty list (should exclude nothing)"""
        actions_to_exclude = set()
        result = invert_actions([])
        # Subtracting an empty set should return all actions
        expected = sorted(
            list(self.EXPECTED_ALL_ACTIONS_FROM_MOCK - actions_to_exclude)
        )
        assert result == expected
        assert result == sorted(list(self.EXPECTED_ALL_ACTIONS_FROM_MOCK))

    def test_invert_non_matching_pattern(self):
        """Test inverting a pattern that matches no actions"""
        actions_to_exclude = set()  # "s3:List*" matches nothing in the mock
        result = invert_actions("s3:List*")
        # Should exclude nothing
        expected = sorted(
            list(self.EXPECTED_ALL_ACTIONS_FROM_MOCK - actions_to_exclude)
        )
        assert result == expected
        assert result == sorted(list(self.EXPECTED_ALL_ACTIONS_FROM_MOCK))

    def test_invert_case_insensitivity(self):
        """Test case insensitivity for patterns during inversion"""
        actions_to_exclude = {"ec2:DescribeInstances", "ec2:DescribeVolumes"}
        result = invert_actions("Ec2:DESCRIBE*")  # Mixed case
        expected = sorted(
            list(self.EXPECTED_ALL_ACTIONS_FROM_MOCK - actions_to_exclude)
        )
        assert result == expected

    def test_invert_invalid_pattern_raise(self):
        """Test RAISE_ERROR for invalid patterns during inversion"""
        with pytest.raises(InvalidActionPatternError) as exc_info:
            invert_actions(
                ["s3:Get*", "invalid-format"],
                invalid_handling=InvalidActionHandling.RAISE_ERROR,
            )
        assert "invalid-format" in str(exc_info.value)

    def test_invert_invalid_pattern_remove(self):
        """Test REMOVE for invalid patterns during inversion"""
        # 'invalid-format' should be ignored, only 's3:Get*' used for exclusion
        actions_to_exclude = {"s3:GetBucket", "s3:GetObject"}
        result = invert_actions(
            ["s3:Get*", "invalid-format"], invalid_handling=InvalidActionHandling.REMOVE
        )
        expected = sorted(
            list(self.EXPECTED_ALL_ACTIONS_FROM_MOCK - actions_to_exclude)
        )
        assert result == expected

    def test_invert_invalid_pattern_keep(self):
        """Test KEEP for invalid patterns during inversion"""
        # 'invalid-format' should be ignored for exclusion purposes, only 's3:Get*' used
        # KEEP behaves like REMOVE in the context of *excluding* actions
        actions_to_exclude = {"s3:GetBucket", "s3:GetObject"}
        result = invert_actions(
            ["s3:Get*", "invalid-format"], invalid_handling=InvalidActionHandling.KEEP
        )
        expected = sorted(
            list(self.EXPECTED_ALL_ACTIONS_FROM_MOCK - actions_to_exclude)
        )
        assert result == expected

    def test_invert_invalid_service_raise(self):
        """Test RAISE_ERROR for non-existent service during inversion"""
        with pytest.raises(InvalidActionPatternError) as exc_info:
            invert_actions(
                ["s3:Get*", "nonexistent:*"],
                invalid_handling=InvalidActionHandling.RAISE_ERROR,
            )
        assert "Service 'nonexistent' not found" in str(exc_info.value)

    def test_invert_invalid_service_remove_or_keep(self):
        """Test REMOVE/KEEP for non-existent service during inversion"""
        # 'nonexistent:*' should be ignored for exclusion, only 's3:Get*' used
        actions_to_exclude = {"s3:GetBucket", "s3:GetObject"}
        for mode in [InvalidActionHandling.REMOVE, InvalidActionHandling.KEEP]:
            result = invert_actions(["s3:Get*", "nonexistent:*"], invalid_handling=mode)
            expected = sorted(
                list(self.EXPECTED_ALL_ACTIONS_FROM_MOCK - actions_to_exclude)
            )
            assert result == expected
