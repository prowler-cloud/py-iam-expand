import argparse
import sys

from .actions import InvalidActionPatternError, expand_actions, invert_actions
from .utils import get_version


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Expand AWS IAM action patterns like 's3:Get*' or '*:*'. "
            "Reads pattern from argument or stdin if argument is omitted."
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
        "action_pattern",
        nargs="?",
        help=(
            "The IAM action pattern to expand or invert (e.g., 's3:Get*', "
            "'ec2:*', '*'). If omitted, reads from stdin."
        ),
        metavar="ACTION_PATTERN",
    )

    parser.add_argument(
        "-i",
        "--invert",
        action="store_true",
        help="Invert the result: show all actions *except* those matching the pattern.",
    )

    args = parser.parse_args()

    pattern_to_process = None

    if args.action_pattern is not None:
        pattern_to_process = args.action_pattern
    else:
        # No argument provided, check stdin
        # sys.stdin.isatty() is True if connected to a terminal (interactive)
        if sys.stdin.isatty():
            # Interactive use without an argument: show help and exit
            parser.print_help(sys.stderr)
            sys.exit(1)
        else:
            # Not a tty, likely piped input: read from stdin
            pattern_from_stdin = sys.stdin.readline().strip()
            if not pattern_from_stdin:
                print("Error: Received empty pattern from stdin.", file=sys.stderr)
                sys.exit(1)
            pattern_to_process = pattern_from_stdin

    try:
        if pattern_to_process is None:
            print("Error: Could not determine action pattern.", file=sys.stderr)
            sys.exit(1)

        if args.invert:
            result_actions = invert_actions(pattern_to_process)
        else:
            result_actions = expand_actions(pattern_to_process)

        if result_actions:
            for action in result_actions:
                print(action)

    except InvalidActionPatternError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
