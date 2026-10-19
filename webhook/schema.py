"""Minimal JSON Schema validator (stdlib only), used to check MCP tool call arguments against a tool's inputSchema,
and a tool result's structuredContent against its outputSchema.

Supported keywords: type (string or list of JSON types: object, array, string, number, integer, boolean, null;
a bool is never a number or integer, and a whole-number float like 1.0 counts as an integer), required, properties,
additionalProperties (bool or schema), enum, const, items (a single schema, not tuple-form), minItems, maxItems,
minLength, maxLength, minimum, maximum, exclusiveMinimum, exclusiveMaximum (numeric form), pattern (re.search).
Annotation-only keywords (title, description, default, examples, $schema, $id, $comment, format, deprecated,
readOnly, writeOnly) are accepted and silently ignored.

Everything else -- $ref, $defs, definitions, oneOf, anyOf, allOf, not, if/then/else, patternProperties,
dependentRequired, prefixItems, uniqueItems, multipleOf, propertyNames, minProperties, maxProperties, contains, and
any keyword not listed above -- is collected into `unsupported` instead of being silently skipped or raising: a
schema this validator can't fully check is a decision for the caller (the webhook), not something to pass or fail
quietly.

A `pattern` Python's re can't compile is reported as unsupported. Never raises: other malformed schema values (e.g. a string where a number is expected) are ignored rather than crashing
the guardrail, and recursion is capped so a pathologically nested instance can't blow the stack.
"""

import json
import re

JSON_TYPES = ("object", "array", "string", "number", "integer", "boolean", "null")

ANNOTATION_KEYWORDS = {"title", "description", "default", "examples", "$schema", "$id", "$comment", "format",
                       "deprecated", "readOnly", "writeOnly"}

KNOWN_KEYWORDS = {"type", "required", "properties", "additionalProperties", "enum", "const", "items", "minItems",
                  "maxItems", "minLength", "maxLength", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
                  "pattern"} | ANNOTATION_KEYWORDS

MAX_ERRORS = 20
MAX_DEPTH = 64


def _is_int(n):
    return isinstance(n, int) and not isinstance(n, bool)


def _is_num(n):
    return isinstance(n, (int, float)) and not isinstance(n, bool)


def _types(value):
    """JSON type names `value` satisfies, for `type` checking."""
    if isinstance(value, bool):
        return {"boolean"}
    if isinstance(value, int):
        return {"integer", "number"}
    if isinstance(value, float):
        return {"number", "integer"} if value.is_integer() else {"number"}
    if value is None:
        return {"null"}
    if isinstance(value, str):
        return {"string"}
    if isinstance(value, list):
        return {"array"}
    if isinstance(value, dict):
        return {"object"}
    return set()


def _type_name(value):
    """A single JSON type name for `value`, for error messages."""
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "integer" if value.is_integer() else "number"
    if value is None:
        return "null"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def _eq(a, b):
    """JSON equality: unlike Python, True/False are never equal to a number."""
    if isinstance(a, bool) != isinstance(b, bool):
        return False
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_eq(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_eq(a[k], b[k]) for k in a)
    return type(a) is type(b) and a == b


def _fmt(value):
    try:
        s = json.dumps(value, ensure_ascii=False)
    except TypeError:
        s = str(value)
    return s if len(s) <= 80 else s[:77] + "..."


def validate(instance, schema):
    """Return (errors, unsupported). errors: human-readable strings with a JSON-pointer-ish path, e.g.
    "$.text: expected string, got integer", "$: missing required property 'text'", "$.extra: additional property
    not allowed". unsupported: the schema keywords encountered that this validator doesn't implement (e.g.
    {"$ref", "oneOf"})."""
    errors = []
    unsupported = set()
    _check(instance, schema, "$", 0, errors, unsupported)
    return errors, unsupported


def _add_error(errors, msg):
    if len(errors) < MAX_ERRORS:
        errors.append(msg)


def _check(instance, schema, path, depth, errors, unsupported):
    if len(errors) >= MAX_ERRORS:
        return
    if depth > MAX_DEPTH:
        _add_error(errors, f"{path}: max nesting depth exceeded")
        return
    if isinstance(schema, bool):
        if not schema:
            _add_error(errors, f"{path}: schema is false, nothing is valid")
        return
    if not isinstance(schema, dict):
        unsupported.add("<non-object schema>")
        return

    for key in schema:
        if key not in KNOWN_KEYWORDS:
            unsupported.add(key)

    if "type" in schema:
        _check_type(instance, schema["type"], path, errors)
    if "enum" in schema and isinstance(schema["enum"], list):
        if not any(_eq(instance, v) for v in schema["enum"]):
            _add_error(errors, f"{path}: {_fmt(instance)} is not one of the enum values")
    if "const" in schema and not _eq(instance, schema["const"]):
        _add_error(errors, f"{path}: {_fmt(instance)} does not equal the const value")

    if isinstance(instance, str):
        _check_string(instance, schema, path, errors, unsupported)
    elif isinstance(instance, bool):
        pass
    elif isinstance(instance, (int, float)):
        _check_number(instance, schema, path, errors)
    elif isinstance(instance, list):
        _check_array(instance, schema, path, depth, errors, unsupported)
    elif isinstance(instance, dict):
        _check_object(instance, schema, path, depth, errors, unsupported)


def _check_type(instance, declared, path, errors):
    if isinstance(declared, str):
        wanted = [declared]
    elif isinstance(declared, list) and all(isinstance(t, str) for t in declared):
        wanted = declared
    else:
        return  # malformed `type`: ignore rather than crash or guess
    if not wanted or not any(t in _types(instance) for t in wanted):
        _add_error(errors, f"{path}: expected {' or '.join(wanted)}, got {_type_name(instance)}")


def _check_string(instance, schema, path, errors, unsupported):
    if _is_int(schema.get("minLength")) and len(instance) < schema["minLength"]:
        _add_error(errors, f"{path}: length {len(instance)} is less than minLength {schema['minLength']}")
    if _is_int(schema.get("maxLength")) and len(instance) > schema["maxLength"]:
        _add_error(errors, f"{path}: length {len(instance)} is more than maxLength {schema['maxLength']}")
    pattern = schema.get("pattern")
    if isinstance(pattern, str):
        try:
            matched = re.search(pattern, instance) is not None
        except re.error:
            matched = True  # not a Python regex: report it, the caller decides
            unsupported.add("pattern")
        if not matched:
            _add_error(errors, f"{path}: does not match pattern '{pattern}'")


def _check_number(instance, schema, path, errors):
    for key, bad, word in (("minimum", lambda v, n: v < n, "less than"),
                           ("maximum", lambda v, n: v > n, "more than")):
        n = schema.get(key)
        if _is_num(n) and bad(instance, n):
            _add_error(errors, f"{path}: {instance} is {word} {key} {n}")
    n = schema.get("exclusiveMinimum")
    if _is_num(n) and instance <= n:
        _add_error(errors, f"{path}: {instance} is not greater than exclusiveMinimum {n}")
    n = schema.get("exclusiveMaximum")
    if _is_num(n) and instance >= n:
        _add_error(errors, f"{path}: {instance} is not less than exclusiveMaximum {n}")


def _check_array(instance, schema, path, depth, errors, unsupported):
    if _is_int(schema.get("minItems")) and len(instance) < schema["minItems"]:
        _add_error(errors, f"{path}: has {len(instance)} items, fewer than minItems {schema['minItems']}")
    if _is_int(schema.get("maxItems")) and len(instance) > schema["maxItems"]:
        _add_error(errors, f"{path}: has {len(instance)} items, more than maxItems {schema['maxItems']}")
    if "items" in schema:
        item_schema = schema["items"]
        if isinstance(item_schema, list):
            unsupported.add("items")  # tuple-form items: not supported
            return
        for i, item in enumerate(instance):
            if len(errors) >= MAX_ERRORS:
                break
            _check(item, item_schema, f"{path}[{i}]", depth + 1, errors, unsupported)


def _check_object(instance, schema, path, depth, errors, unsupported):
    required = schema.get("required")
    if isinstance(required, list):
        for name in required:
            if isinstance(name, str) and name not in instance:
                _add_error(errors, f"{path}: missing required property '{name}'")

    properties = schema.get("properties")
    props = properties if isinstance(properties, dict) else {}
    for name, value in instance.items():
        if len(errors) >= MAX_ERRORS:
            break
        if name in props:
            _check(value, props[name], f"{path}.{name}", depth + 1, errors, unsupported)

    if "additionalProperties" in schema:
        ap = schema["additionalProperties"]
        extra = [n for n in instance if n not in props]
        if ap is False:
            for name in extra:
                if len(errors) >= MAX_ERRORS:
                    break
                _add_error(errors, f"{path}.{name}: additional property not allowed")
        elif isinstance(ap, dict) or ap is True:
            sub = ap if isinstance(ap, dict) else True
            for name in extra:
                if len(errors) >= MAX_ERRORS:
                    break
                _check(instance[name], sub, f"{path}.{name}", depth + 1, errors, unsupported)
        # else malformed (not bool/dict): ignore
