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
        assert result == ["S3:GetBucket", "S3:GetObject"]

    def test_expand_multiple_patterns(self):
        """Test expanding multiple patterns"""
        result = expand_actions(["s3:Get*", "ec2:Describe*"])
        assert result == [
            "EC2:DescribeInstances",
            "EC2:DescribeVolumes",
            "S3:GetBucket",
            "S3:GetObject",
        ]

    def test_invalid_pattern(self):
        """Test handling of invalid patterns"""
        with pytest.raises(InvalidActionPatternError):
            expand_actions("s3")  # Missing colon

    def test_case_insensitive_matching(self):
        """Test that pattern matching is case-insensitive"""
        result = expand_actions("S3:get*")
        assert result == ["S3:GetBucket", "S3:GetObject"]


class TestActionInversion:
    def test_invert_single_pattern(self):
        """Test inverting a single pattern"""
        result = invert_actions("s3:Get*")
        expected = [
            "EC2:DescribeInstances",
            "EC2:DescribeVolumes",
            "IAM:CreateAccessKey",
            "IAM:ListAccessKeys",
            "IAM:PassRole",
            "STS:AssumeRole",
        ]
        assert result == expected

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
