import pytest

from py_iam_expand.actions import (
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
