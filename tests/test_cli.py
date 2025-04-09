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
            assert "S3:GetBucket" in captured.out
            assert "S3:GetObject" in captured.out

    def test_policy_input(self, sample_policy, capsys):
        """Test processing policy from stdin"""
        with patch("sys.stdin.read", return_value=json.dumps(sample_policy)):
            with patch("sys.stdin.isatty", return_value=False):
                with patch("sys.argv", ["py-iam-expand"]):
                    main()
                    captured = capsys.readouterr()
                    output_policy = json.loads(captured.out)
                    assert output_policy["Statement"][0]["Action"] == [
                        "S3:GetBucket",
                        "S3:GetObject",
                    ]
                    assert output_policy["Statement"][1]["NotAction"] == [
                        "EC2:DescribeInstances",
                        "EC2:DescribeVolumes",
                        "IAM:CreateAccessKey",
                        "IAM:ListAccessKeys",
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
