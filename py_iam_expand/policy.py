from copy import deepcopy
from typing import Any, Dict, List

from .actions import InvalidActionHandling, InvalidActionPatternError, expand_actions


def expand_policy_actions(
    policy_data: Dict[str, Any],
    invalid_handling_action: InvalidActionHandling = InvalidActionHandling.REMOVE,
    invalid_handling_notaction: InvalidActionHandling = InvalidActionHandling.KEEP,
) -> Dict[str, Any]:
    """
    Expands Action and NotAction fields within an IAM policy document.

    Args:
        policy_data: A dictionary representing the parsed IAM policy JSON.
        invalid_handling_action: How to handle invalid patterns in Action elements:
                                - RAISE_ERROR: Raise an exception
                                - REMOVE: Silently remove invalid patterns
                                - KEEP: Keep invalid patterns in the result
        invalid_handling_notaction: How to handle invalid patterns in NotAction elements:
                                    - RAISE_ERROR: Raise an exception
                                    - REMOVE: Silently remove invalid patterns
                                    - KEEP: Keep invalid patterns in the result (default)

    Returns:
        A dictionary representing the policy with expanded actions.

    Raises:
        ValueError: If the policy structure is invalid (e.g., missing Statement).
        InvalidActionPatternError: If any action pattern within the policy is invalid
                                    and the corresponding invalid_handling is RAISE_ERROR.
        TypeError: If Statement or its elements are not of the expected type.
    """
    if not isinstance(policy_data, dict):
        raise TypeError("Policy data must be a dictionary.")

    policy_copy = deepcopy(policy_data)

    statements = policy_copy.get("Statement")

    if statements is None:
        raise ValueError("Policy does not contain a 'Statement' key.")

    if not isinstance(statements, list):
        raise TypeError("'Statement' value must be a list.")

    for i, statement in enumerate(statements):
        if not isinstance(statement, dict):
            raise TypeError(f"Statement at index {i} is not a dictionary.")

        try:
            if "Action" in statement:
                original_action = statement["Action"]
                patterns_to_expand: List[str] = []
                if isinstance(original_action, str):
                    patterns_to_expand = [original_action.strip()]
                elif isinstance(original_action, list):
                    patterns_to_expand = [
                        str(p).strip()
                        for p in original_action
                        if isinstance(p, str) and p.strip()
                    ]  # Filter non-strings/empty
                else:
                    raise TypeError(
                        f"Statement {i}: 'Action' must be a string or list of strings."
                    )

                if patterns_to_expand:
                    expanded = expand_actions(
                        patterns_to_expand, invalid_handling_action
                    )
                    statement["Action"] = expanded
                elif not isinstance(original_action, list):
                    statement["Action"] = []

            if "NotAction" in statement:
                original_not_action = statement["NotAction"]
                patterns_to_expand: List[str] = []
                if isinstance(original_not_action, str):
                    patterns_to_expand = [original_not_action.strip()]
                elif isinstance(original_not_action, list):
                    patterns_to_expand = [
                        str(p).strip()
                        for p in original_not_action
                        if isinstance(p, str) and p.strip()
                    ]
                else:
                    raise TypeError(
                        f"Statement {i}: 'NotAction' must be a string or list of strings."
                    )

                if patterns_to_expand:
                    expanded = expand_actions(
                        patterns_to_expand, invalid_handling_notaction
                    )
                    statement["NotAction"] = expanded
                elif not isinstance(original_not_action, list):
                    statement["NotAction"] = []

        except InvalidActionPatternError as e:
            raise InvalidActionPatternError(
                pattern=e.pattern, message=f"Statement {i}: {e.message}"
            ) from e
        except (TypeError, ValueError) as e:
            raise type(e)(f"Statement {i}: {e}") from e

    return policy_copy
