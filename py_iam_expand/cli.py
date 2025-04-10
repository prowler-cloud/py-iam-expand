import argparse
import json
import sys

from .actions import (
    InvalidActionHandling,
    InvalidActionPatternError,
    expand_actions,
    invert_actions,
)
from .policy import expand_policy_actions
from .utils import get_version


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Expand AWS IAM action provided as arguments/stdin lines OR "
            "expand actions within an AWS IAM Policy JSON provided via stdin."
        ),
        prog="py-iam-expand",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {get_version()}",
        help="Show the package version and exit",
    )

    parser.add_argument(
        "action_patterns",
        nargs="*",
        help=(
            "IAM action pattern(s) to expand/invert (e.g., 's3:Get*' 'ec2:*'). "
            "If omitted, reads from stdin. Cannot be used if stdin is a JSON policy."
        ),
        metavar="ACTION_PATTERN",
    )

    parser.add_argument(
        "-i",
        "--invert",
        action="store_true",
        help=(
            "Invert pattern expansion result. Cannot be used if stdin is a JSON policy."
        ),
    )

    parser.add_argument(
        "--invalid-action",
        choices=["raise", "remove", "keep"],
        default="raise",
        help=(
            "How to handle invalid patterns in Action elements: "
            "raise - raise an error (default), "
            "remove - silently remove invalid patterns, "
            "keep - keep invalid patterns in the result"
        ),
    )

    parser.add_argument(
        "--invalid-notaction",
        choices=["raise", "remove", "keep"],
        default="keep",
        help=(
            "How to handle invalid patterns in NotAction elements: "
            "raise - raise an error, "
            "remove - silently remove invalid patterns, "
            "keep - keep invalid patterns in the result (default)"
        ),
    )

    args = parser.parse_args()

    # Map CLI options to enum values
    invalid_handling_map = {
        "raise": InvalidActionHandling.RAISE_ERROR,
        "remove": InvalidActionHandling.REMOVE,
        "keep": InvalidActionHandling.KEEP,
    }

    invalid_handling_action = invalid_handling_map[args.invalid_action]
    invalid_handling_notaction = invalid_handling_map[args.invalid_notaction]

    is_policy_mode = False
    stdin_content = None

    if not args.action_patterns:  # No positional args, check stdin
        if sys.stdin.isatty():
            # Interactive use without arguments: show help and exit
            parser.print_help(sys.stderr)
            sys.exit(1)
        else:
            stdin_content = sys.stdin.read()
            if stdin_content.strip().startswith("{"):
                is_policy_mode = True

    if is_policy_mode and args.invert:
        print(
            "Error: --invert flag cannot be used when processing a JSON policy from stdin.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        if is_policy_mode:
            if not stdin_content:
                print("Error: Received empty policy from stdin.", file=sys.stderr)
                sys.exit(1)
            try:
                policy_data = json.loads(stdin_content)
            except json.JSONDecodeError as e:
                print(
                    f"Error: Invalid JSON policy provided via stdin: {e}",
                    file=sys.stderr,
                )
                sys.exit(1)

            expanded_policy = expand_policy_actions(
                policy_data,
                invalid_handling_action=invalid_handling_action,
                invalid_handling_notaction=invalid_handling_notaction,
            )

            print(json.dumps(expanded_policy, indent=2))

        else:
            patterns_to_process = []
            if args.action_patterns:
                patterns_to_process = args.action_patterns
            elif stdin_content is not None:
                patterns_from_stdin = [
                    line for line in stdin_content.splitlines() if line.strip()
                ]
                if not patterns_from_stdin:
                    print("Error: Received no patterns from stdin.", file=sys.stderr)
                    sys.exit(1)
                patterns_to_process = patterns_from_stdin
            else:
                print("Error: No action patterns provided.", file=sys.stderr)
                sys.exit(1)

            if args.invert:
                result_actions = invert_actions(
                    patterns_to_process, invalid_handling=invalid_handling_action
                )
            else:
                result_actions = expand_actions(
                    patterns_to_process, invalid_handling=invalid_handling_action
                )

            if result_actions:
                for action in result_actions:
                    print(action)

    except InvalidActionPatternError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except (ValueError, TypeError) as e:
        print(f"Error processing policy: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
