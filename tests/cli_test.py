from unittest.mock import patch

import pytest
from iamdata import IAMData

from py_iam_expand.actions import InvalidActionPatternError
from py_iam_expand.cli import main

iam_data = IAMData()


def test_cli_expand_success(capsys):
    @patch("py_iam_expand.cli.expand_actions")
    @patch("sys.argv", ["py-iam-expand", "s3:Get*"])
    def run_test(mock_expand):
        mock_expand.return_value = ["s3:GetBucket", "s3:GetObject"]
        main()
        mock_expand.assert_called_once_with("s3:Get*")

        captured = capsys.readouterr()
        assert captured.out == "s3:GetBucket\ns3:GetObject\n"
        assert captured.err == ""

    run_test()


def test_cli_expand_invalid_format(capsys):
    @patch("py_iam_expand.cli.expand_actions")
    @patch("sys.argv", ["py-iam-expand", "s3:"])  # Invalid format
    def run_test(mock_expand):
        mock_expand.side_effect = InvalidActionPatternError(
            pattern="s3:", message="Test error message"
        )
        # Expect SystemExit with code 1
        with pytest.raises(SystemExit) as e:
            main()
        assert e.type == SystemExit
        assert e.value.code == 1

        mock_expand.assert_called_once_with("s3:")
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "Error: Invalid action pattern 's3:': Test error message" in captured.err

    run_test()


def test_cli_expand_unexpected_error(capsys):
    @patch("py_iam_expand.cli.expand_actions")
    @patch("sys.exit")
    @patch("sys.argv", ["py-iam-expand", "s3:Something"])
    def run_test(mock_exit, mock_expand):
        mock_expand.side_effect = Exception("Something went wrong!")
        main()
        mock_expand.assert_called_once_with("s3:Something")

        # Assert sys.exit was called with 2
        mock_exit.assert_called_once_with(2)

        # Assert the generic error message was printed to stderr
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "An unexpected error occurred: Something went wrong!" in captured.err

    run_test()


def test_cli_expand_no_matches(capsys):
    @patch("py_iam_expand.cli.expand_actions")
    @patch("sys.exit")
    @patch("sys.argv", ["py-iam-expand", "s3:NonExistent*"])
    def run_test(mock_exit, mock_expand):
        mock_expand.return_value = []  # Empty list
        main()
        mock_expand.assert_called_once_with("s3:NonExistent*")

        # Assert sys.exit was NOT called with non-zero
        if mock_exit.called:
            mock_exit.assert_called_once_with(0)

        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    run_test()


def test_cli_no_args(capsys):
    @patch("sys.exit")
    @patch("sys.argv", ["py-iam-expand"])  # No action pattern arg
    def run_test(mock_exit):
        main()

        # Assert help/usage message was printed to stderr
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "usage: py-iam-expand" in captured.err
        assert "ACTION_PATTERN" in captured.err  # Check positional arg is mentioned

    run_test()
