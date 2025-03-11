import argparse

from .utils import get_version


def main():
    parser = argparse.ArgumentParser(
        description="PyIAMExpand CLI - Shows package version.",
        prog="py-iam-expand",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {get_version()}",
        help="Show the package version and exit",
    )

    # Add other arguments here if the tool did more
    # parser.add_argument("input", help="Input file")
    # parser.add_argument("-o", "--output", help="Output file")

    parser.parse_args()

    # If no arguments, just print the version again or a help message.
    print(f"Welcome to py_iam_expand version {get_version()}")
    print("Use --help for options or --version to see the version.")


if __name__ == "__main__":
    main()
