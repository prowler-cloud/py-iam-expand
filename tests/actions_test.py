from unittest.mock import patch

from iamdata import IAMData

from py_iam_expand.actions import expand_actions

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
