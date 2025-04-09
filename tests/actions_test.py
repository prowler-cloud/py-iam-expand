from unittest.mock import patch

import pytest
from iamdata import IAMData

from py_iam_expand.actions import (
    InvalidActionPatternError,
    expand_actions,
    invert_actions,
)

iam_data = IAMData()


def test_expand_actions_no_wildcards():
    @patch("py_iam_expand.actions.iam_data.services.service_exists")
    @patch("py_iam_expand.actions.iam_data.actions.action_exists")
    @patch("py_iam_expand.actions.iam_data.actions.get_action_details")
    def run_test(mock_get_action_details, mock_action_exists, mock_service_exists):
        mock_service_exists.return_value = True
        mock_action_exists.return_value = True
        mock_get_action_details.return_value = {"name": "GetObject"}

        result = expand_actions("s3:GetObject")
        assert result == ["s3:GetObject"]

    run_test()


def test_expand_actions_with_wildcards():
    @patch("py_iam_expand.actions.iam_data.services.service_exists")
    @patch("py_iam_expand.actions.iam_data.actions.get_actions_for_service")
    def run_test(mock_get_actions_for_service, mock_iam_service_exists):
        mock_iam_service_exists.return_value = True
        mock_get_actions_for_service.return_value = [
            "GetObject",
            "GetBucket",
            "PutObject",
        ]

        result = expand_actions("s3:Get*")
        assert result == ["s3:GetBucket", "s3:GetObject"]

    run_test()


def test_expand_actions_service_not_exists():
    @patch("py_iam_expand.actions.iam_data.services.service_exists")
    def run_test(mock_iam_service_exists):
        mock_iam_service_exists.return_value = False

        result = expand_actions("s13:Get*")
        assert result == []

    run_test()


def test_expand_actions_all_wildcards():
    @patch("py_iam_expand.actions.iam_data.services.get_service_keys")
    @patch("py_iam_expand.actions.iam_data.services.service_exists")
    @patch("py_iam_expand.actions.iam_data.actions.get_actions_for_service")
    def run_test(
        mock_get_actions_for_service,
        mock_iam_service_exists,
        mock_get_service_keys,
    ):
        mock_iam_service_exists.return_value = True
        mock_get_actions_for_service.return_value = [
            "GetObject",
            "PutObject",
        ]
        mock_get_service_keys.return_value = ["s3"]

        result = expand_actions("*")
        assert result == ["s3:GetObject", "s3:PutObject"]

    run_test()


MOCK_ALL_ACTIONS = {
    "s3:GetObject",
    "s3:PutObject",
    "s3:DeleteObject",
    "ec2:RunInstances",
    "ec2:StopInstances",
    "iam:PassRole",
}


def test_invert_actions_specific():
    @patch("py_iam_expand.actions._get_all_actions", return_value=MOCK_ALL_ACTIONS)
    @patch("py_iam_expand.actions.expand_actions", return_value=["s3:GetObject"])
    def run_test(mock_expand, mock_get_all):
        pattern = "s3:GetObject"
        result = invert_actions(pattern)

        mock_expand.assert_called_once_with(pattern)
        mock_get_all.assert_called_once()

        expected = sorted(list(MOCK_ALL_ACTIONS - {"s3:GetObject"}))
        assert result == expected

    run_test()


def test_invert_actions_wildcard():
    actions_to_exclude = ["ec2:RunInstances", "ec2:StopInstances"]

    @patch("py_iam_expand.actions._get_all_actions", return_value=MOCK_ALL_ACTIONS)
    @patch("py_iam_expand.actions.expand_actions", return_value=actions_to_exclude)
    def run_test(mock_expand, mock_get_all):
        pattern = "ec2:*Instances"
        result = invert_actions(pattern)

        mock_expand.assert_called_once_with(pattern)
        mock_get_all.assert_called_once()

        # Expected: all actions except the ec2 ones, sorted
        expected = sorted(list(MOCK_ALL_ACTIONS - set(actions_to_exclude)))
        assert result == expected

    run_test()


def test_invert_actions_all_wildcard():
    @patch("py_iam_expand.actions._get_all_actions", return_value=MOCK_ALL_ACTIONS)
    @patch("py_iam_expand.actions.expand_actions", return_value=list(MOCK_ALL_ACTIONS))
    def run_test(mock_expand, mock_get_all):
        pattern = "*"
        result = invert_actions(pattern)

        mock_expand.assert_called_once_with(pattern)
        mock_get_all.assert_called_once()

        assert result == []

    run_test()


def test_invert_actions_no_match():
    @patch("py_iam_expand.actions._get_all_actions", return_value=MOCK_ALL_ACTIONS)
    @patch("py_iam_expand.actions.expand_actions", return_value=[])
    def run_test(mock_expand, mock_get_all):
        pattern = "s3:NoSuchAction*"
        result = invert_actions(pattern)

        mock_expand.assert_called_once_with(pattern)
        mock_get_all.assert_called_once()

        expected = sorted(list(MOCK_ALL_ACTIONS))
        assert result == expected

    run_test()


def test_invert_actions_invalid_pattern():
    @patch("py_iam_expand.actions._get_all_actions")
    @patch("py_iam_expand.actions.expand_actions")
    def run_test(mock_expand, mock_get_all):
        pattern = "s3"  # Invalid pattern
        mock_expand.side_effect = InvalidActionPatternError(
            pattern=pattern, message="Test error"
        )

        with pytest.raises(InvalidActionPatternError):
            invert_actions(pattern)

        mock_expand.assert_called_once_with(pattern)
        mock_get_all.assert_not_called()  # Should fail before getting all actions

    run_test()
