import argparse
import sys

from .actions import InvalidActionPatternError, expand_actions, invert_actions
from .utils import get_version


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Expand or invert one or more AWS IAM action patterns. "
            "Reads patterns from arguments or stdin (one per line) if arguments are omitted."
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
            "One or more IAM action patterns to expand or invert "
            "(e.g., 's3:Get*' 'ec2:*'). If omitted, reads patterns from stdin "
            "(one per line)."
        ),
        metavar="ACTION_PATTERN",
    )

    parser.add_argument(
        "-i",
        "--invert",
        action="store_true",
        help="Invert the result: show all actions *except* those matching the patterns.",
    )

    args = parser.parse_args()

    patterns_to_process = []

    if args.action_patterns:
        patterns_to_process = args.action_patterns
    else:
        # No arguments provided, check stdin
        if sys.stdin.isatty():
            # Interactive use without arguments: show help and exit
            parser.print_help(sys.stderr)
            sys.exit(1)
        else:
            # Not a tty, likely piped input: read all lines from stdin
            # Filter out empty lines after stripping whitespace
            patterns_from_stdin = [
                line for line in sys.stdin.read().splitlines() if line.strip()
            ]
            if not patterns_from_stdin:
                # Handle empty input from stdin as an error
                print("Error: Received no patterns from stdin.", file=sys.stderr)
                sys.exit(1)
            patterns_to_process = patterns_from_stdin

    try:
        if not patterns_to_process:
            print("Error: No action patterns provided.", file=sys.stderr)
            sys.exit(1)

        if args.invert:
            result_actions = invert_actions(patterns_to_process)
        else:
            result_actions = expand_actions(patterns_to_process)

        if result_actions:
            for action in result_actions:
                print(action)

    except InvalidActionPatternError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    except Exception as e:
        print(f"An unexpected error occurred processing patterns: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
