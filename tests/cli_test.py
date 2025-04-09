import io
from unittest.mock import patch

import pytest

from py_iam_expand.actions import InvalidActionPatternError
from py_iam_expand.cli import main


def test_cli_expand_success_single_arg(capsys):
    """Test expand with a single command line argument."""

    @patch("sys.argv", ["py-iam-expand", "s3:Get*"])
    @patch("py_iam_expand.cli.expand_actions")
    def run_test(mock_expand):
        mock_expand.return_value = ["s3:GetBucket", "s3:GetObject"]
        main()
        # Should be called with a list containing the single pattern
        mock_expand.assert_called_once_with(["s3:Get*"])
        captured = capsys.readouterr()
        assert captured.out == "s3:GetBucket\ns3:GetObject\n"
        assert captured.err == ""

    run_test()


def test_cli_expand_success_multiple_args(capsys):
    """Test expand with multiple command line arguments."""

    @patch("sys.argv", ["py-iam-expand", "s3:Get*", "ec2:Describe*"])
    @patch("py_iam_expand.cli.expand_actions")
    def run_test(mock_expand):
        mock_expand.return_value = sorted(
            [
                "s3:GetBucket",
                "s3:GetObject",
                "ec2:DescribeInstances",
                "ec2:DescribeImages",
            ]
        )
        main()
        # Should be called with a list containing all patterns
        mock_expand.assert_called_once_with(["s3:Get*", "ec2:Describe*"])
        captured = capsys.readouterr()
        expected_out = (
            "ec2:DescribeImages\n"
            "ec2:DescribeInstances\n"
            "s3:GetBucket\n"
            "s3:GetObject\n"
        )
        assert captured.out == expected_out
        assert captured.err == ""

    run_test()


def test_cli_expand_invalid_format_single_arg(capsys):
    """Test error handling with one invalid argument."""

    @patch("sys.argv", ["py-iam-expand", "s3:"])  # Invalid arg
    @patch("py_iam_expand.cli.expand_actions")
    def run_test(mock_expand):
        mock_expand.side_effect = InvalidActionPatternError(
            pattern="s3:", message="Test error message"
        )
        with pytest.raises(SystemExit) as e:
            main()
        assert e.type == SystemExit
        assert e.value.code == 1
        # Check it was called with the list containing the invalid pattern
        mock_expand.assert_called_once_with(["s3:"])
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "Error: Invalid action pattern 's3:': Test error message" in captured.err

    run_test()


def test_cli_expand_invalid_format_mixed_args(capsys):
    """Test error handling with one invalid argument among valid ones."""

    @patch(
        "sys.argv", ["py-iam-expand", "s3:Get*", "ec2", "iam:PassRole"]
    )  # ec2 is invalid
    @patch("py_iam_expand.cli.expand_actions")
    def run_test(mock_expand):
        mock_expand.side_effect = InvalidActionPatternError(
            pattern="ec2", message="Missing colon"
        )
        with pytest.raises(SystemExit) as e:
            main()
        assert e.type == SystemExit
        assert e.value.code == 1
        # Check it was called with the full list
        mock_expand.assert_called_once_with(["s3:Get*", "ec2", "iam:PassRole"])
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "Error: Invalid action pattern 'ec2': Missing colon" in captured.err

    run_test()


def test_cli_expand_unexpected_error(capsys):
    """Verify CLI handles unexpected errors during expansion and exits."""

    @patch("sys.argv", ["py-iam-expand", "s3:Something"])
    @patch("py_iam_expand.cli.expand_actions")
    def run_test(mock_expand):
        mock_expand.side_effect = Exception("Something went wrong!")
        with pytest.raises(SystemExit) as e:
            main()
        assert e.type == SystemExit
        assert e.value.code == 2
        mock_expand.assert_called_once_with(["s3:Something"])
        captured = capsys.readouterr()
        assert captured.out == ""
        assert (
            "An unexpected error occurred processing patterns: Something went wrong!"
            in captured.err
        )

    run_test()


def test_cli_expand_no_matches(capsys):
    """Verify CLI prints nothing when expansion yields no results (exit 0)."""

    @patch("sys.argv", ["py-iam-expand", "s3:NonExistent*", "ec2:Foo*"])
    @patch("py_iam_expand.cli.expand_actions")
    def run_test(mock_expand):
        mock_expand.return_value = []
        main()
        mock_expand.assert_called_once_with(["s3:NonExistent*", "ec2:Foo*"])
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    run_test()


def test_cli_no_args_interactive(capsys):
    """Verify CLI prints help and exits with 1 if no args and stdin is tty."""

    @patch("sys.argv", ["py-iam-expand"])  # No args
    @patch("sys.stdin.isatty", return_value=True)
    def run_test(mock_isatty):
        with pytest.raises(SystemExit) as e:
            main()
        assert e.type == SystemExit
        assert e.value.code == 1
        mock_isatty.assert_called_once()
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "usage: py-iam-expand" in captured.err
        assert "ACTION_PATTERN" in captured.err

    run_test()


def test_cli_read_single_line_from_stdin(capsys):
    """Test reading a single pattern line from stdin."""
    mock_stdin = io.StringIO("s3:Get*Tagging\n")

    @patch("sys.argv", ["py-iam-expand"])  # No args
    @patch("sys.stdin", mock_stdin)
    @patch("sys.stdin.isatty", return_value=False)
    @patch("py_iam_expand.cli.expand_actions")
    def run_test(mock_expand, _mock_isatty):
        mock_expand.return_value = ["s3:GetBucketTagging", "s3:GetObjectTagging"]
        main()
        # Called with a list containing the single line
        mock_expand.assert_called_once_with(["s3:Get*Tagging"])
        captured = capsys.readouterr()
        assert captured.out == "s3:GetBucketTagging\ns3:GetObjectTagging\n"
        assert captured.err == ""

    run_test()


def test_cli_read_multiple_lines_from_stdin(capsys):
    """Test reading multiple pattern lines from stdin."""
    mock_stdin = io.StringIO(
        "s3:Get*\n\nec2:Describe*\niam:PassRole\n"
    )  # Includes empty line

    @patch("sys.argv", ["py-iam-expand"])  # No args
    @patch("sys.stdin", mock_stdin)
    @patch("sys.stdin.isatty", return_value=False)
    @patch("py_iam_expand.cli.expand_actions")
    def run_test(mock_expand, _mock_isatty):
        mock_expand.return_value = sorted(
            ["s3:GetObject", "s3:GetBucket", "ec2:DescribeInstances", "iam:PassRole"]
        )
        main()
        # Called with list of non-empty lines
        expected_patterns = ["s3:Get*", "ec2:Describe*", "iam:PassRole"]
        mock_expand.assert_called_once_with(expected_patterns)
        captured = capsys.readouterr()
        expected_out = (
            "ec2:DescribeInstances\n" "iam:PassRole\n" "s3:GetBucket\n" "s3:GetObject\n"
        )
        assert captured.out == expected_out
        assert captured.err == ""

    run_test()


def test_cli_read_invalid_line_from_stdin(capsys):
    """Test reading stdin with an invalid pattern line."""
    mock_stdin = io.StringIO("s3:Get*\nec2\niam:PassRole\n")  # ec2 is invalid

    @patch("sys.argv", ["py-iam-expand"])  # No args
    @patch("sys.stdin", mock_stdin)
    @patch("sys.stdin.isatty", return_value=False)
    @patch("py_iam_expand.cli.expand_actions")
    def run_test(mock_expand, _mock_isatty):
        mock_expand.side_effect = InvalidActionPatternError(
            pattern="ec2", message="Missing colon"
        )
        with pytest.raises(SystemExit) as e:
            main()
        assert e.type == SystemExit
        assert e.value.code == 1
        # Called with list including the invalid one
        expected_patterns = ["s3:Get*", "ec2", "iam:PassRole"]
        mock_expand.assert_called_once_with(expected_patterns)
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "Error: Invalid action pattern 'ec2': Missing colon" in captured.err

    run_test()


def test_cli_empty_stdin(capsys):
    """Verify CLI handles empty stdin input as an error."""
    mock_stdin = io.StringIO("\n   \n")  # Only whitespace/empty lines

    @patch("sys.argv", ["py-iam-expand"])
    @patch("sys.stdin", mock_stdin)
    @patch("sys.stdin.isatty", return_value=False)
    @patch("py_iam_expand.cli.expand_actions")
    def run_test(mock_expand, _mock_isatty):
        with pytest.raises(SystemExit) as e:
            main()
        assert e.type == SystemExit
        assert e.value.code == 1
        mock_expand.assert_not_called()
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "Error: Received no patterns from stdin." in captured.err

    run_test()


def test_cli_invert_success_multiple_args(capsys):
    """Verify CLI calls invert_actions with multiple args and --invert flag."""

    @patch("sys.argv", ["py-iam-expand", "--invert", "s3:Get*", "ec2:*Instances"])
    @patch("py_iam_expand.cli.invert_actions")
    def run_test(mock_invert):
        mock_invert.return_value = ["s3:DeleteObject", "iam:PassRole"]
        main()
        # Called with list of patterns
        mock_invert.assert_called_once_with(["s3:Get*", "ec2:*Instances"])
        captured = capsys.readouterr()
        assert captured.out == "s3:DeleteObject\niam:PassRole\n"
        assert captured.err == ""

    run_test()


def test_cli_invert_invalid_format_multiple_args(capsys):
    """Verify CLI handles InvalidActionPatternError with multiple args and --invert."""

    @patch(
        "sys.argv", ["py-iam-expand", "-i", "s3:Get*", "ec2", "iam:*"]
    )  # ec2 invalid
    @patch("py_iam_expand.cli.invert_actions")
    def run_test(mock_invert):
        mock_invert.side_effect = InvalidActionPatternError(
            pattern="ec2", message="Invert test error"
        )
        with pytest.raises(SystemExit) as e:
            main()
        assert e.type == SystemExit
        assert e.value.code == 1
        mock_invert.assert_called_once_with(["s3:Get*", "ec2", "iam:*"])
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "Error: Invalid action pattern 'ec2': Invert test error" in captured.err

    run_test()


def test_cli_invert_read_multiple_lines_from_stdin(capsys):
    """Verify CLI reads multiple lines from stdin with --invert flag."""
    mock_stdin = io.StringIO("ec2:Run*\ns3:PutObject\n")

    @patch("sys.argv", ["py-iam-expand", "--invert"])  # Flag, no positional arg
    @patch("sys.stdin", mock_stdin)
    @patch("sys.stdin.isatty", return_value=False)
    @patch("py_iam_expand.cli.invert_actions")
    def run_test(mock_invert, _mock_isatty):
        mock_invert.return_value = ["s3:GetObject", "iam:PassRole"]
        main()
        # Called with list of patterns from stdin
        mock_invert.assert_called_once_with(["ec2:Run*", "s3:PutObject"])
        captured = capsys.readouterr()
        assert captured.out == "s3:GetObject\niam:PassRole\n"
        assert captured.err == ""

    run_test()
