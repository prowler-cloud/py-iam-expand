import fnmatch
from typing import List, Set, Union

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


def _expand_single_pattern(action_pattern: str) -> Set[str]:
    """Expands a single IAM action pattern."""
    expanded_actions: Set[str] = set()
    target_service_keys: List[str] = []

    if action_pattern == "*":
        service_pattern_lower = "*"
        action_name_pattern_lower = "*"
    elif ":" not in action_pattern:
        raise InvalidActionPatternError(
            pattern=action_pattern,
            message="Must be 'service:action' or '*'. Missing colon.",
        )
    else:
        try:
            service_part, action_part = action_pattern.split(":", 1)
            if not service_part or not action_part:
                raise InvalidActionPatternError(
                    pattern=action_pattern,
                    message=(
                        "Both service and action parts are required " "after the colon."
                    ),
                )
            service_pattern_lower = service_part.lower()
            action_name_pattern_lower = action_part.lower()
        except ValueError:  # Should not happen, but defensive
            raise InvalidActionPatternError(
                pattern=action_pattern, message="Unexpected parsing error."
            )

    all_service_keys = iam_data.services.get_service_keys()
    lower_to_original_key = {key.lower(): key for key in all_service_keys}

    if service_pattern_lower == "*":
        target_service_keys = list(all_service_keys)
    elif "*" in service_pattern_lower or "?" in service_pattern_lower:
        for lower_key, original_key in lower_to_original_key.items():
            if fnmatch.fnmatchcase(lower_key, service_pattern_lower):
                target_service_keys.append(original_key)
    else:
        if service_pattern_lower in lower_to_original_key:
            target_service_keys = [lower_to_original_key[service_pattern_lower]]

    if not target_service_keys:
        return set()

    for service_key in target_service_keys:
        service_actions = iam_data.actions.get_actions_for_service(service_key)
        if not service_actions:
            continue

        if action_name_pattern_lower == "*":
            for action_name in service_actions:
                expanded_actions.add(f"{service_key}:{action_name}")
        elif "*" in action_name_pattern_lower or "?" in action_name_pattern_lower:
            for action_name in service_actions:
                if fnmatch.fnmatchcase(action_name.lower(), action_name_pattern_lower):
                    expanded_actions.add(f"{service_key}:{action_name}")
        else:
            for action_name in service_actions:
                if action_name.lower() == action_name_pattern_lower:
                    expanded_actions.add(f"{service_key}:{action_name}")
                    break

    return expanded_actions


def expand_actions(action_patterns: Union[str, List[str]]) -> List[str]:
    """
    Expands one or more IAM action patterns into a list of matching actions.

    Args:
        action_patterns: A single pattern string or a list of pattern strings.
                        Each pattern must follow 'service:action' format or be '*'.

    Returns:
        A sorted list of unique matching IAM actions combined from all patterns.

    Raises:
        InvalidActionPatternError: If any input pattern is invalid.
    """
    if isinstance(action_patterns, str):
        patterns = [action_patterns]  # Treat single string as a list of one
    else:
        patterns = action_patterns

    combined_actions: Set[str] = set()
    for pattern in patterns:
        expanded = _expand_single_pattern(pattern)
        combined_actions.update(expanded)

    return sorted(list(combined_actions))


def invert_actions(action_patterns: Union[str, List[str]]) -> List[str]:
    """
    Finds all IAM actions *except* those matching the given pattern(s).

    Args:
        action_patterns: A single pattern string or a list of pattern strings
                        to exclude. Each pattern must follow the same format
                        rules as `expand_actions`.

    Returns:
        A sorted list of unique IAM actions that do *not* match any of the
        given patterns.

    Raises:
        InvalidActionPatternError: If any input pattern is invalid.
    """
    if isinstance(action_patterns, str):
        patterns = [action_patterns]
    else:
        patterns = action_patterns

    total_actions_to_exclude: Set[str] = set()
    for pattern in patterns:
        excluded_for_pattern = _expand_single_pattern(pattern)
        total_actions_to_exclude.update(excluded_for_pattern)

    all_actions = _get_all_actions()
    inverted_actions = all_actions - total_actions_to_exclude

    return sorted(list(inverted_actions))
