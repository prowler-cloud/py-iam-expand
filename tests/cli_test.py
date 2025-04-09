import io
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


def test_cli_no_args_interactive(capsys):
    @patch("sys.exit")
    @patch("sys.argv", ["py-iam-expand"])  # No action pattern arg
    def run_test(_mock_argv):
        main()

        # Assert help/usage message was printed to stderr
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "usage: py-iam-expand" in captured.err
        assert "ACTION_PATTERN" in captured.err  # Check positional arg is mentioned

    run_test()


def test_cli_read_from_stdin(capsys):
    # Simulate piped input: argv has no pattern, stdin is not a tty
    # Mock stdin itself to provide controlled input
    mock_stdin = io.StringIO("s3:Get*Tagging\n")

    @patch("py_iam_expand.cli.expand_actions")
    @patch("sys.stdin.isatty", return_value=False)  # Simulate non-interactive
    @patch("sys.stdin", mock_stdin)  # Replace sys.stdin with our mock
    @patch("sys.argv", ["py-iam-expand"])  # No positional arg
    def run_test(_mock_isatty, mock_expand):
        mock_expand.return_value = [
            "s3:GetBucketTagging",
            "s3:GetObjectTagging",
        ]  # Example return

        main()

        # Assert expand was called with the pattern from stdin
        mock_expand.assert_called_once_with("s3:Get*Tagging")

        captured = capsys.readouterr()
        assert captured.out == "s3:GetBucketTagging\ns3:GetObjectTagging\n"
        assert captured.err == ""

    run_test()


def test_cli_empty_stdin(capsys):
    mock_stdin = io.StringIO("\n")  # Empty line

    @patch("py_iam_expand.cli.expand_actions")
    @patch("sys.stdin.isatty", return_value=False)
    @patch("sys.stdin", mock_stdin)
    @patch("sys.argv", ["py-iam-expand"])
    def run_test(_mock_isatty, mock_expand):
        with pytest.raises(SystemExit) as e:
            main()
        assert e.type == SystemExit
        assert e.value.code == 1  # Exit code 1 for bad input

        mock_expand.assert_not_called()  # expand_actions shouldn't be hit

        captured = capsys.readouterr()
        assert captured.out == ""
        assert "Error: Received empty pattern from stdin." in captured.err

    run_test()


def test_cli_invert_success_long_flag(capsys):
    @patch("py_iam_expand.cli.invert_actions")
    @patch("sys.argv", ["py-iam-expand", "--invert", "s3:Get*"])
    def run_test(mock_invert):
        mock_invert.return_value = [
            "s3:DeleteObject",
            "iam:PassRole",
        ]  # Example inverted result
        main()
        mock_invert.assert_called_once_with("s3:Get*")
        captured = capsys.readouterr()
        assert captured.out == "s3:DeleteObject\niam:PassRole\n"
        assert captured.err == ""

    run_test()


def test_cli_invert_success_short_flag(capsys):
    @patch("py_iam_expand.cli.invert_actions")
    @patch("sys.argv", ["py-iam-expand", "-i", "s3:Get*"])
    def run_test(mock_invert):
        mock_invert.return_value = ["s3:DeleteObject", "iam:PassRole"]
        main()
        mock_invert.assert_called_once_with("s3:Get*")
        captured = capsys.readouterr()
        assert captured.out == "s3:DeleteObject\niam:PassRole\n"
        assert captured.err == ""

    run_test()


def test_cli_invert_invalid_format(capsys):
    @patch("py_iam_expand.cli.invert_actions")  # Mock invert to raise error
    @patch("sys.argv", ["py-iam-expand", "--invert", "s3:"])  # Invalid format
    def run_test(mock_invert):  # Correct order
        mock_invert.side_effect = InvalidActionPatternError(
            pattern="s3:", message="Invert test error"
        )
        with pytest.raises(SystemExit) as e:
            main()
        assert e.type == SystemExit
        assert e.value.code == 1
        mock_invert.assert_called_once_with("s3:")
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "Error: Invalid action pattern 's3:': Invert test error" in captured.err

    run_test()


def test_cli_invert_read_from_stdin(capsys):
    mock_stdin = io.StringIO("ec2:Run*\n")

    @patch("py_iam_expand.cli.invert_actions")  # Mock invert
    @patch("sys.stdin.isatty", return_value=False)
    @patch("sys.stdin", mock_stdin)
    @patch("sys.argv", ["py-iam-expand", "--invert"])  # Flag, no positional arg
    def run_test(_mock_isatty, mock_invert):  # Correct order
        mock_invert.return_value = ["s3:GetObject", "iam:PassRole"]
        main()
        mock_invert.assert_called_once_with("ec2:Run*")  # Pattern from stdin
        captured = capsys.readouterr()
        assert captured.out == "s3:GetObject\niam:PassRole\n"
        assert captured.err == ""

    run_test()
