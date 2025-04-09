import argparse
import sys

from .actions import expand_actions
from .utils import get_version


def main():
    parser = argparse.ArgumentParser(
        description="Expand AWS IAM action patterns like 's3:Get*' or '*:*'.",
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
        help="The IAM action pattern to expand (e.g., 's3:Get*', 'ec2:*', '*').",
        metavar="ACTION_PATTERN",
    )

    args = parser.parse_args()

    if args.action_pattern is None:
        parser.print_help(sys.stderr)
        sys.exit(1)

    try:
        expanded = expand_actions(args.action_pattern)
        if expanded:
            for action in expanded:
                print(action)

    except ValueError as e:
        # Print the specific error message from the exception to stderr
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    except Exception as e:
        # Catch any other unexpected errors during expansion
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
