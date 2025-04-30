import json
from unittest.mock import patch

import pytest

from py_iam_expand.cli import main


class TestCliInterface:
    def test_basic_command(self, capsys):
        """Test basic command line usage"""
        with patch("sys.argv", ["py-iam-expand", "s3:Get*"]):
            main()
            captured = capsys.readouterr()
            assert "s3:GetBucket" in captured.out
            assert "s3:GetObject" in captured.out

    def test_policy_input(self, sample_policy, capsys):
        """Test processing policy from stdin"""
        with patch("sys.stdin.read", return_value=json.dumps(sample_policy)):
            with patch("sys.stdin.isatty", return_value=False):
                with patch("sys.argv", ["py-iam-expand"]):
                    main()
                    captured = capsys.readouterr()
                    output_policy = json.loads(captured.out)
                    assert output_policy["Statement"][0]["Action"] == [
                        "s3:GetBucket",
                        "s3:GetObject",
                    ]
                    assert output_policy["Statement"][1]["NotAction"] == [
                        "ec2:DescribeInstances",
                        "ec2:DescribeVolumes",
                        "iam:CreateAccessKey",
                        "iam:ListAccessKeys",
                    ]

    @pytest.mark.parametrize(
        "invalid_input,expected_error",
        [
            # Non-JSON input is treated as an action pattern
            (
                "not-json",
                "Invalid action pattern 'not-json': Must be 'service:action' or '*'",
            ),
            ('{"Statement": "invalid"}', "'Statement' value must be a list"),
            (
                '{"Statement": [{"Action": 123}]}',
                "'Action' must be a string or list of strings",
            ),
        ],
    )
    def test_invalid_inputs(self, invalid_input, expected_error, capsys):
        """Test handling of various invalid inputs"""
        with patch("sys.stdin.read", return_value=invalid_input):
            with patch("sys.stdin.isatty", return_value=False):
                with patch("sys.argv", ["py-iam-expand"]):
                    with pytest.raises(SystemExit):
                        main()
                    captured = capsys.readouterr()
                    assert expected_error in captured.err

    def test_no_args_interactive(self, capsys):
        """Test behavior when no args provided in interactive mode"""
        with patch("sys.argv", ["py-iam-expand"]):
            with patch("sys.stdin.isatty", return_value=True):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 1
                captured = capsys.readouterr()
                assert "usage: py-iam-expand" in captured.err

    def test_invert_with_policy_input(self, sample_policy, capsys):
        """Test that --invert flag is rejected when processing policy"""
        with patch("sys.stdin.read", return_value=json.dumps(sample_policy)):
            with patch("sys.stdin.isatty", return_value=False):
                with patch("sys.argv", ["py-iam-expand", "--invert"]):
                    with pytest.raises(SystemExit) as exc_info:
                        main()
                    assert exc_info.value.code == 1
                    captured = capsys.readouterr()
                    assert (
                        "Error: --invert flag cannot be used when processing a JSON policy"
                        in captured.err
                    )

    def test_invalid_json_policy(self, capsys):
        """Test handling of malformed JSON input"""
        invalid_json = "{invalid json"
        with patch("sys.stdin.read", return_value=invalid_json):
            with patch("sys.stdin.isatty", return_value=False):
                with patch("sys.argv", ["py-iam-expand"]):
                    with pytest.raises(SystemExit):
                        main()
                    captured = capsys.readouterr()
                    assert "Invalid JSON policy provided via stdin" in captured.err

    def test_cli_multiple_patterns(self, capsys):
        """Test handling multiple patterns as arguments"""
        with patch("sys.argv", ["py-iam-expand", "s3:Get*", "ec2:Describe*"]):
            main()
            captured = capsys.readouterr()
            assert "s3:" in captured.out
            assert "ec2:" in captured.out

    def test_cli_empty_stdin(self, capsys):
        """Test handling empty stdin"""
        with patch("sys.stdin.read", return_value=""):
            with patch("sys.stdin.isatty", return_value=False):
                with patch("sys.argv", ["py-iam-expand"]):
                    with pytest.raises(SystemExit) as exc_info:
                        main()
                    assert exc_info.value.code == 1
                    captured = capsys.readouterr()
                    assert "Error:" in captured.err

    @pytest.mark.parametrize("flag", ["-i", "--invert"])
    def test_cli_invert_flags(self, flag, capsys):
        """Test both short and long invert flags"""
        with patch("sys.argv", ["py-iam-expand", flag, "s3:Get*"]):
            main()
            captured = capsys.readouterr()
            output_lines = captured.out.splitlines()

            # Verify that the output:
            # 1. Contains actions from other services
            # 2. Does not contain the actions we excluded (s3:Get*)
            # 3. Contains at least one line
            assert len(output_lines) > 0
            assert any(
                line.startswith(("ec2:", "iam:", "sts:")) for line in output_lines
            )
            assert not any(line.startswith("s3:Get") for line in output_lines)

            # Optional: Verify specific expected actions are present
            assert "iam:PassRole" in output_lines
            assert "ec2:DescribeInstances" in output_lines

    def test_cli_invert_specific_verification(self, capsys):
        """Test invert operation with specific pattern and verification"""
        with patch("sys.argv", ["py-iam-expand", "-i", "s3:Get*"]):
            with patch("py_iam_expand.actions._get_all_actions") as mock_all_actions:
                # Mock a smaller set of actions for easier testing
                mock_all_actions.return_value = {
                    "s3:GetObject",
                    "s3:GetBucket",
                    "s3:PutObject",
                    "EC2:DescribeInstances",
                    "IAM:PassRole",
                }

                main()
                captured = capsys.readouterr()
                output_lines = set(captured.out.splitlines())

                # Should contain these actions
                expected_actions = {
                    "s3:PutObject",
                    "EC2:DescribeInstances",
                    "IAM:PassRole",
                }
                # Should not contain these actions
                excluded_actions = {"s3:GetObject", "s3:GetBucket"}

                assert output_lines == expected_actions
                assert not (output_lines & excluded_actions)

    def test_cli_invalid_service_keep(self, capsys):
        """Test CLI with invalid service and KEEP handling"""
        with patch("sys.stdin.read", return_value="nonexistent:*"):
            with patch("sys.stdin.isatty", return_value=False):
                with patch("sys.argv", ["py-iam-expand", "--invalid-action", "keep"]):
                    main()
                    captured = capsys.readouterr()
                    # Split by newline and filter out empty lines
                    output = [line for line in captured.out.splitlines() if line]
                    assert output == ["nonexistent:*"]

    def test_cli_invalid_service_remove(self, capsys):
        """Test CLI with invalid service and REMOVE handling"""
        with patch("sys.stdin.read", return_value="nonexistent:*"):
            with patch("sys.stdin.isatty", return_value=False):
                with patch("sys.argv", ["py-iam-expand", "--invalid-action", "remove"]):
                    main()
                    captured = capsys.readouterr()
                    # Split by newline and filter out empty lines
                    output = [line for line in captured.out.splitlines() if line]
                    assert output == []

    def test_cli_invalid_service_default(self, capsys):
        """Test CLI with invalid service and default (RAISE_ERROR) handling"""
        with patch("sys.stdin.read", return_value="nonexistent:*"):
            with patch("sys.stdin.isatty", return_value=False):
                with patch("sys.argv", ["py-iam-expand"]):
                    with pytest.raises(SystemExit) as exc_info:
                        main()
                    assert exc_info.value.code == 1
                    captured = capsys.readouterr()
                    assert "Service 'nonexistent' not found" in captured.err

    def test_cli_policy_invalid_service_keep(self, sample_policy, capsys):
        """Test CLI policy mode with invalid service and KEEP handling"""
        policy = {
            "Statement": [
                {"Effect": "Allow", "Action": "nonexistent:*", "Resource": "*"}
            ]
        }
        with patch("sys.stdin.read", return_value=json.dumps(policy)):
            with patch("sys.stdin.isatty", return_value=False):
                with patch("sys.argv", ["py-iam-expand", "--invalid-action", "keep"]):
                    main()
                    captured = capsys.readouterr()
                    output_policy = json.loads(captured.out)
                    assert output_policy["Statement"][0]["Action"] == ["nonexistent:*"]

    def test_cli_policy_invalid_service_remove(self, sample_policy, capsys):
        """Test CLI policy mode with invalid service and REMOVE handling"""
        policy = {
            "Statement": [
                {"Effect": "Allow", "Action": "nonexistent:*", "Resource": "*"}
            ]
        }
        with patch("sys.stdin.read", return_value=json.dumps(policy)):
            with patch("sys.stdin.isatty", return_value=False):
                with patch("sys.argv", ["py-iam-expand", "--invalid-action", "remove"]):
                    main()
                    captured = capsys.readouterr()
                    output_policy = json.loads(captured.out)
                    assert output_policy["Statement"][0]["Action"] == []
