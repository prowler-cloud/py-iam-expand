import fnmatch
from enum import Enum
from typing import List, Set, Union

from iamdata import IAMData

iam_data = IAMData()


class InvalidActionPatternError(ValueError):
    """Custom exception for invalid IAM action pattern formats."""

    def __init__(self, pattern: str, message: str):
        self.pattern = pattern
        self.message = message
        super().__init__(f"Invalid action pattern '{pattern}': {message}")


class InvalidActionHandling(Enum):
    """Defines how to handle invalid action patterns."""

    RAISE_ERROR = "raise_error"  # Raise an exception for invalid patterns
    REMOVE = "remove"  # Silently remove invalid patterns
    KEEP = "keep"  # Keep invalid patterns as-is


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


def _expand_single_pattern(
    action_pattern: str,
    invalid_handling: InvalidActionHandling = InvalidActionHandling.RAISE_ERROR,
) -> Set[str]:
    """
    Expands a single IAM action pattern.

    Args:
        action_pattern: The pattern to expand
        invalid_handling: How to handle invalid patterns

    Returns:
        A set of expanded actions

    Raises:
        InvalidActionPatternError: If pattern is invalid and invalid_handling is RAISE_ERROR
    """
    expanded_actions: Set[str] = set()
    target_service_keys: List[str] = []

    if action_pattern == "*":
        service_pattern_lower = "*"
        action_name_pattern_lower = "*"
    elif ":" not in action_pattern:
        if invalid_handling == InvalidActionHandling.RAISE_ERROR:
            raise InvalidActionPatternError(
                pattern=action_pattern,
                message="Must be 'service:action' or '*'. Missing colon.",
            )
        elif invalid_handling == InvalidActionHandling.KEEP:
            # Return the original pattern as a single-item set
            return {action_pattern}
        else:  # REMOVE
            return set()
    else:
        try:
            service_part, action_part = action_pattern.split(":", 1)
            if not service_part or not action_part:
                if invalid_handling == InvalidActionHandling.RAISE_ERROR:
                    raise InvalidActionPatternError(
                        pattern=action_pattern,
                        message=(
                            "Both service and action parts are required "
                            "after the colon."
                        ),
                    )
                elif invalid_handling == InvalidActionHandling.KEEP:
                    return {action_pattern}
                else:  # REMOVE
                    return set()
            service_pattern_lower = service_part.lower()
            action_name_pattern_lower = action_part.lower()
        except ValueError:  # Should not happen, but defensive
            if invalid_handling == InvalidActionHandling.RAISE_ERROR:
                raise InvalidActionPatternError(
                    pattern=action_pattern, message="Unexpected parsing error."
                )
            elif invalid_handling == InvalidActionHandling.KEEP:
                return {action_pattern}
            else:  # REMOVE
                return set()

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

    # If no matching services found and we're keeping invalid patterns
    if not target_service_keys and invalid_handling == InvalidActionHandling.KEEP:
        return {action_pattern}

    # If no matching services found and we're removing invalid patterns
    if not target_service_keys and invalid_handling == InvalidActionHandling.REMOVE:
        return set()

    # If no matching services found and we're raising errors
    if (
        not target_service_keys
        and invalid_handling == InvalidActionHandling.RAISE_ERROR
    ):
        raise InvalidActionPatternError(
            pattern=action_pattern, message=f"Service '{service_part}' not found"
        )

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

    # If no matching actions found and we're keeping invalid patterns
    if not expanded_actions and invalid_handling == InvalidActionHandling.KEEP:
        return {action_pattern}

    return expanded_actions


def expand_actions(
    action_patterns: Union[str, List[str]],
    invalid_handling: InvalidActionHandling = InvalidActionHandling.RAISE_ERROR,
) -> List[str]:
    """
    Expands one or more IAM action patterns into a list of matching actions.

    Args:
        action_patterns: A single pattern string or a list of pattern strings.
                        Each pattern must follow 'service:action' format or be '*'.
        invalid_handling: How to handle invalid patterns:
                        - RAISE_ERROR: Raise an exception (default)
                        - REMOVE: Silently remove invalid patterns
                        - KEEP: Keep invalid patterns in the result

    Returns:
        A sorted list of unique matching IAM actions combined from all patterns.

    Raises:
        InvalidActionPatternError: If any input pattern is invalid and invalid_handling is RAISE_ERROR.
    """
    if isinstance(action_patterns, str):
        patterns = [action_patterns]  # Treat single string as a list of one
    else:
        patterns = action_patterns

    combined_actions: Set[str] = set()
    for pattern in patterns:
        try:
            expanded = _expand_single_pattern(pattern, invalid_handling)
            combined_actions.update(expanded)
        except InvalidActionPatternError:
            if invalid_handling == InvalidActionHandling.RAISE_ERROR:
                raise
            elif invalid_handling == InvalidActionHandling.KEEP:
                combined_actions.add(pattern)
            # For REMOVE, we just skip it

    return sorted(list(combined_actions))


def invert_actions(
    action_patterns: Union[str, List[str]],
    invalid_handling: InvalidActionHandling = InvalidActionHandling.RAISE_ERROR,
) -> List[str]:
    """
    Finds all IAM actions *except* those matching the given pattern(s).

    Args:
        action_patterns: A single pattern string or a list of pattern strings
                        to exclude. Each pattern must follow the same format
                        rules as `expand_actions`.
        invalid_handling: How to handle invalid patterns:
                        - RAISE_ERROR: Raise an exception (default)
                        - REMOVE: Silently remove invalid patterns
                        - KEEP: Keep invalid patterns in the result

    Returns:
        A sorted list of unique IAM actions that do *not* match any of the
        given patterns.

    Raises:
        InvalidActionPatternError: If any input pattern is invalid and invalid_handling is RAISE_ERROR.
    """
    if isinstance(action_patterns, str):
        patterns = [action_patterns]
    else:
        patterns = action_patterns

    total_actions_to_exclude: Set[str] = set()
    for pattern in patterns:
        try:
            excluded_for_pattern = _expand_single_pattern(pattern, invalid_handling)
            total_actions_to_exclude.update(excluded_for_pattern)
        except InvalidActionPatternError:
            if invalid_handling == InvalidActionHandling.RAISE_ERROR:
                raise
            # For KEEP and REMOVE in invert context, we just skip it
            # since we're excluding actions, not including them

    all_actions = _get_all_actions()
    inverted_actions = all_actions - total_actions_to_exclude

    return sorted(list(inverted_actions))
