from typing import Any, Dict, Optional, Tuple

# Each tool's required parameters and their expected Python type.
# Any parameter not listed here is considered unexpected.
TOOL_PARAMETER_SCHEMAS: Dict[str, Dict[str, type]] = {
    "send_email": {"to": str, "subject": str, "body": str},
    "search_customer": {"customer_id": str},
    "get_weather": {"city": str},
    "delete_database": {"database_name": str},
}

TYPE_NAMES = {str: "string", int: "integer", float: "number", bool: "boolean"}


def validate_parameters(tool_name: str, parameters: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """Check parameters against the tool's schema.

    Returns None if valid, or a (rule_id, reason) tuple for the first
    violation found.
    """
    schema = TOOL_PARAMETER_SCHEMAS.get(tool_name, {})

    for name, expected_type in schema.items():
        if name not in parameters:
            return "PARAM-001", f"Required parameter '{name}' is missing"

        value = parameters[name]
        if not isinstance(value, expected_type):
            type_name = TYPE_NAMES.get(expected_type, expected_type.__name__)
            return "PARAM-002", f"Parameter '{name}' must be a {type_name}"

        if expected_type is str and value.strip() == "":
            return "PARAM-004", f"Required parameter '{name}' cannot be empty"

    for key in parameters:
        if key not in schema:
            return "PARAM-003", f"Unexpected parameter '{key}'"

    return None
