from unittest.mock import call, patch

import pytest

from py_iam_expand.actions import (
    InvalidActionPatternError,
    _expand_single_pattern,
    expand_actions,
    invert_actions,
)


def test_expand_single_pattern_no_wildcards():
    """Test _expand_single_pattern with a specific, existing action."""

    @patch("py_iam_expand.actions.iam_data")
    def run_test(mock_iam_data):
        mock_iam_data.services.get_service_keys.return_value = ["S3"]
        mock_iam_data.actions.get_actions_for_service.return_value = [
            "GetObject",
            "PutObject",
        ]

        result = _expand_single_pattern("s3:GetObject")
        assert result == {"S3:GetObject"}

        mock_iam_data.services.get_service_keys.assert_called_once()
        mock_iam_data.actions.get_actions_for_service.assert_called_once_with("S3")

    run_test()


def test_expand_single_pattern_with_wildcards():
    """Test _expand_single_pattern with wildcards."""

    @patch("py_iam_expand.actions.iam_data")
    def run_test(mock_iam_data):
        mock_iam_data.services.get_service_keys.return_value = ["S3"]
        mock_iam_data.actions.get_actions_for_service.return_value = [
            "GetObject",
            "GetBucket",
            "PutObject",
            "ListBucket",
        ]

        result = _expand_single_pattern("s3:Get*")
        assert result == {"S3:GetBucket", "S3:GetObject"}

        mock_iam_data.services.get_service_keys.assert_called_once()
        mock_iam_data.actions.get_actions_for_service.assert_called_once_with("S3")

    run_test()


def test_expand_single_pattern_service_not_exists():
    """Test _expand_single_pattern when service doesn't exist."""

    @patch("py_iam_expand.actions.iam_data")
    def run_test(mock_iam_data):
        mock_iam_data.services.get_service_keys.return_value = ["EC2", "IAM"]

        result = _expand_single_pattern("s13:Get*")
        assert result == set()

        mock_iam_data.services.get_service_keys.assert_called_once()
        mock_iam_data.actions.get_actions_for_service.assert_not_called()

    run_test()


def test_expand_single_pattern_all_wildcards():
    """Test _expand_single_pattern with '*'."""

    @patch("py_iam_expand.actions.iam_data")
    def run_test(mock_iam_data):
        mock_iam_data.services.get_service_keys.return_value = ["S3", "EC2"]
        mock_iam_data.actions.get_actions_for_service.side_effect = [
            ["GetObject", "PutObject"],
            ["RunInstances"],
        ]

        result = _expand_single_pattern("*")
        assert result == {"S3:GetObject", "S3:PutObject", "EC2:RunInstances"}

        mock_iam_data.services.get_service_keys.assert_called_once()
        mock_iam_data.actions.get_actions_for_service.assert_has_calls(
            [call("S3"), call("EC2")], any_order=True
        )

    run_test()


def test_expand_single_pattern_invalid_format():
    """Test _expand_single_pattern raises error for invalid format."""

    def run_test():
        with pytest.raises(InvalidActionPatternError):
            _expand_single_pattern("s3")  # Missing colon

    run_test()


def test_expand_actions_single_pattern():
    """Test expand_actions with a single pattern in a list."""

    @patch(
        "py_iam_expand.actions._expand_single_pattern", return_value={"S3:GetObject"}
    )
    def run_test(mock_expand_single):
        result = expand_actions(["s3:GetObject"])  # Pass list
        assert result == ["S3:GetObject"]  # Returns sorted list
        mock_expand_single.assert_called_once_with("s3:GetObject")

    run_test()


def test_expand_actions_single_pattern_string():
    """Test expand_actions with a single pattern as a string."""

    @patch(
        "py_iam_expand.actions._expand_single_pattern", return_value={"S3:GetObject"}
    )
    def run_test(mock_expand_single):
        result = expand_actions("s3:GetObject")  # Pass string
        assert result == ["S3:GetObject"]  # Returns sorted list
        mock_expand_single.assert_called_once_with("s3:GetObject")

    run_test()


def test_expand_actions_multiple_patterns():
    """Test expand_actions with multiple patterns, deduplication, and sorting."""

    def expand_side_effect(pattern):
        if pattern == "s3:Get*":
            return {"S3:GetObject", "S3:GetBucket"}
        elif pattern == "s3:PutObject":
            return {"S3:PutObject"}
        elif pattern == "ec2:Describe*":
            return {"EC2:DescribeInstances", "EC2:DescribeImages"}
        elif pattern == "s3:GetBucket":
            return {"S3:GetBucket"}
        else:
            return set()

    @patch(
        "py_iam_expand.actions._expand_single_pattern", side_effect=expand_side_effect
    )
    def run_test(mock_expand_single):
        patterns = ["s3:Get*", "s3:PutObject", "ec2:Describe*", "s3:GetBucket"]
        result = expand_actions(patterns)
        expected = sorted(
            [
                "S3:GetObject",
                "S3:GetBucket",
                "S3:PutObject",
                "EC2:DescribeInstances",
                "EC2:DescribeImages",
            ]
        )
        assert result == expected
        assert mock_expand_single.call_count == len(patterns)
        mock_expand_single.assert_has_calls(
            [
                call("s3:Get*"),
                call("s3:PutObject"),
                call("ec2:Describe*"),
                call("s3:GetBucket"),
            ],
            any_order=False,
        )

    run_test()


def test_expand_actions_with_invalid_pattern():
    """Test expand_actions stops and raises error if one pattern is invalid."""

    @patch("py_iam_expand.actions._expand_single_pattern")
    def run_test(mock_expand_single):
        mock_expand_single.side_effect = [
            {"S3:GetObject"},
            InvalidActionPatternError("ec2", "Test error"),
            {"IAM:PassRole"},
        ]
        patterns = ["s3:GetObject", "ec2", "iam:PassRole"]
        with pytest.raises(InvalidActionPatternError) as excinfo:
            expand_actions(patterns)
        assert "'ec2'" in str(excinfo.value)
        assert mock_expand_single.call_count == 2
        mock_expand_single.assert_has_calls([call("s3:GetObject"), call("ec2")])

    run_test()


MOCK_ALL_ACTIONS = {
    "S3:GetObject",
    "S3:PutObject",
    "S3:DeleteObject",
    "EC2:RunInstances",
    "EC2:StopInstances",
    "IAM:PassRole",
}


def test_invert_actions_single_pattern():
    """Test invert_actions with a single pattern in a list."""

    @patch("py_iam_expand.actions._get_all_actions", return_value=MOCK_ALL_ACTIONS)
    @patch(
        "py_iam_expand.actions._expand_single_pattern", return_value={"S3:GetObject"}
    )
    def run_test(mock_expand_single, mock_get_all):
        result = invert_actions(["s3:GetObject"])
        expected = sorted(list(MOCK_ALL_ACTIONS - {"S3:GetObject"}))
        assert result == expected
        mock_expand_single.assert_called_once_with("s3:GetObject")
        mock_get_all.assert_called_once()

    run_test()


def test_invert_actions_single_pattern_string():
    """Test invert_actions with a single pattern as a string."""

    @patch("py_iam_expand.actions._get_all_actions", return_value=MOCK_ALL_ACTIONS)
    @patch(
        "py_iam_expand.actions._expand_single_pattern", return_value={"S3:GetObject"}
    )
    def run_test(mock_expand_single, mock_get_all):
        result = invert_actions("s3:GetObject")
        expected = sorted(list(MOCK_ALL_ACTIONS - {"S3:GetObject"}))
        assert result == expected
        mock_expand_single.assert_called_once_with("s3:GetObject")
        mock_get_all.assert_called_once()

    run_test()


def test_invert_actions_multiple_patterns():
    """Test invert_actions with multiple patterns."""

    def expand_side_effect(pattern):
        if pattern == "s3:Get*":
            return {"S3:GetObject"}
        elif pattern == "ec2:*Instances":
            return {"EC2:RunInstances", "EC2:StopInstances"}
        else:
            return set()

    @patch("py_iam_expand.actions._get_all_actions", return_value=MOCK_ALL_ACTIONS)
    @patch(
        "py_iam_expand.actions._expand_single_pattern", side_effect=expand_side_effect
    )
    def run_test(mock_expand_single, mock_get_all):
        patterns = ["s3:Get*", "ec2:*Instances"]
        result = invert_actions(patterns)

        actions_to_exclude = {"S3:GetObject", "EC2:RunInstances", "EC2:StopInstances"}
        expected = sorted(list(MOCK_ALL_ACTIONS - actions_to_exclude))
        assert result == expected

        assert mock_expand_single.call_count == len(patterns)
        mock_expand_single.assert_has_calls([call("s3:Get*"), call("ec2:*Instances")])
        mock_get_all.assert_called_once()

    run_test()


def test_invert_actions_with_invalid_pattern():
    """Test invert_actions stops and raises error if one pattern is invalid."""

    @patch("py_iam_expand.actions._get_all_actions")
    @patch("py_iam_expand.actions._expand_single_pattern")
    def run_test(mock_expand_single, mock_get_all):
        mock_expand_single.side_effect = [
            {"S3:GetObject"},
            InvalidActionPatternError("ec2", "Test error"),
        ]
        patterns = ["s3:GetObject", "ec2"]
        with pytest.raises(InvalidActionPatternError) as excinfo:
            invert_actions(patterns)

        assert "'ec2'" in str(excinfo.value)
        assert mock_expand_single.call_count == 2
        mock_expand_single.assert_has_calls([call("s3:GetObject"), call("ec2")])
        mock_get_all.assert_not_called()

    run_test()
