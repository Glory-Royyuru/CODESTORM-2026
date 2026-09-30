from typing import Any, Dict, Optional, Tuple

from app.gateway.registry import RegisteredTool

LINE_BREAKS = ("\r", "\n", " ", " ")


def _matches_type(value: Any, type_name: str) -> bool:
    if type_name == "string":
        return isinstance(value, str)
    if type_name == "boolean":
        return isinstance(value, bool)
    # bool is a subclass of int in Python; JSON true/false is not a number.
    if isinstance(value, bool):
        return False
    if type_name == "integer":
        return isinstance(value, int)
    if type_name == "number":
        return isinstance(value, (int, float))
    return False


def validate_parameters(tool: RegisteredTool, parameters: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """Check canonical parameters against the tool manifest's schema.

    Returns None if valid, or a (rule_id, reason) tuple for the first
    violation found. Parameters not declared in the manifest are rejected.
    """
    for name, spec in tool.parameters.items():
        if name not in parameters:
            if spec.required:
                return "PARAM-001", f"Required parameter '{name}' is missing"
            continue

        value = parameters[name]
        if not _matches_type(value, spec.type):
            return "PARAM-002", f"Parameter '{name}' must be a {spec.type}"

        if spec.type == "string":
            if value.strip() == "":
                prefix = "Required parameter" if spec.required else "Parameter"
                return "PARAM-004", f"{prefix} '{name}' cannot be empty"
            if spec.single_line and any(brk in value for brk in LINE_BREAKS):
                return "PARAM-005", f"Parameter '{name}' must not contain line breaks"

    for key in parameters:
        if key not in tool.parameters:
            return "PARAM-003", f"Unexpected parameter '{key}'"

    return None
