import fnmatch
from typing import List, Set

from iamdata import IAMData

iam_data = IAMData()


class InvalidActionPatternError(ValueError):
    """Custom exception for invalid IAM action pattern formats."""

    def __init__(self, pattern: str, message: str):
        self.pattern = pattern
        self.message = message
        super().__init__(f"Invalid action pattern '{pattern}': {message}")


def _get_all_actions() -> Set[str]:
    """Helper function to retrieve all known IAM actions."""
    all_actions: Set[str] = set()
    service_keys = iam_data.services.get_service_keys()
    for service_prefix in service_keys:
        service_actions = iam_data.actions.get_actions_for_service(service_prefix)
        if service_actions:
            for action_name in service_actions:
                all_actions.add(f"{service_prefix}:{action_name}")
    return all_actions


def expand_actions(action_pattern: str) -> List[str]:
    """
    Expands IAM action patterns (like s3:GetObject, s3:Get*, s3:*, *)
    into a list of matching IAM actions.

    Args:
        action_pattern: The action pattern string. Can include wildcards (*).
                        Examples: "s3:GetObject", "s3:Get*", "ec2:*", "*".

    Returns:
        A sorted list of unique matching IAM actions.
        Returns an empty list if the service doesn't exist or no actions match.

    Raises:
        ValueError: If the input `action_pattern` does not
            conform to the 'service:action' format or is not '*'.
    """
    expanded_actions: Set[str] = set()
    target_services: List[str] = []

    if action_pattern == "*":
        service_pattern = "*"
        action_name_pattern = "*"
    elif ":" not in action_pattern:
        raise InvalidActionPatternError(
            pattern=action_pattern,
            message="Must be 'service:action' or '*'. Missing colon.",
        )
    else:
        try:
            service_pattern, action_name_pattern = action_pattern.split(":", 1)
            if not service_pattern or not action_name_pattern:
                # Invalid format: "s3:" or ":action"
                raise InvalidActionPatternError(
                    pattern=action_pattern,
                    message=(
                        "Both service and action parts are required " "after the colon."
                    ),
                )
        except InvalidActionPatternError:
            raise InvalidActionPatternError(
                pattern=action_pattern, message="Unexpected parsing error."
            )

    all_service_keys = iam_data.services.get_service_keys()

    if "*" in service_pattern or "?" in service_pattern:
        target_services = [
            svc for svc in all_service_keys if fnmatch.fnmatchcase(svc, service_pattern)
        ]
        if not target_services:
            return []
    else:
        if iam_data.services.service_exists(service_pattern):
            target_services = [service_pattern]
        else:
            return []

    for service_prefix in target_services:
        service_actions = iam_data.actions.get_actions_for_service(service_prefix)
        if not service_actions:
            continue

        if action_name_pattern == "*":
            for action_name in service_actions:
                expanded_actions.add(f"{service_prefix}:{action_name}")
        elif "*" in action_name_pattern or "?" in action_name_pattern:
            for action_name in service_actions:
                if fnmatch.fnmatchcase(action_name, action_name_pattern):
                    expanded_actions.add(f"{service_prefix}:{action_name}")
        else:
            if action_name_pattern in service_actions:
                expanded_actions.add(f"{service_prefix}:{action_name_pattern}")

    return sorted(list(expanded_actions))


def invert_actions(action_pattern: str) -> List[str]:
    """
    Finds all IAM actions *except* those matching the given pattern.

    Useful for handling NotAction statements.

    Args:
        action_pattern: The action pattern string to exclude. Must follow
                        the same format rules as `expand_actions`.

    Returns:
        A sorted list of unique IAM actions that do *not* match the pattern.

    Raises:
        InvalidActionPatternError: If the input `action_pattern` does not
            conform to the 'service:action' format or is not '*'.
    """
    actions_to_exclude = set(expand_actions(action_pattern))

    all_actions = _get_all_actions()

    inverted_actions = all_actions - actions_to_exclude

    return sorted(list(inverted_actions))
