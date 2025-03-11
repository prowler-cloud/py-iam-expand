import importlib.metadata


def get_version() -> str:
    """
    Retrieves the package version from installed metadata.

    Returns:
        The package version string (e.g., "0.1.0")
    """
    return importlib.metadata.version("py_iam_expand")
