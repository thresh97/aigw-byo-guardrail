import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "webhook"))
import schema  # noqa: E402


class TypeKeyword(unittest.TestCase):
    def test_string_pass_fail(self):
        self.assertEqual(schema.validate("hi", {"type": "string"}), ([], set()))
        errs, unsup = schema.validate(5, {"type": "string"})
        self.assertEqual(errs, ["$: expected string, got integer"])
        self.assertEqual(unsup, set())

    def test_list_of_types(self):
        self.assertEqual(schema.validate(5, {"type": ["string", "number"]}), ([], set()))
        self.assertEqual(schema.validate(None, {"type": ["string", "number"]}),
                         (["$: expected string or number, got null"], set()))

    def test_bool_is_not_integer_or_number(self):
        errs, _ = schema.validate(True, {"type": "integer"})
        self.assertEqual(errs, ["$: expected integer, got boolean"])
        errs, _ = schema.validate(True, {"type": "number"})
        self.assertEqual(errs, ["$: expected number, got boolean"])
        self.assertEqual(schema.validate(True, {"type": "boolean"}), ([], set()))

    def test_whole_float_counts_as_integer(self):
        self.assertEqual(schema.validate(1.0, {"type": "integer"}), ([], set()))
        self.assertEqual(schema.validate(1.5, {"type": "integer"}),
                         (["$: expected integer, got number"], set()))

    def test_all_json_types(self):
        cases = [("object", {}), ("array", []), ("string", "x"), ("number", 1.5), ("integer", 3),
                 ("boolean", False), ("null", None)]
        for t, v in cases:
            self.assertEqual(schema.validate(v, {"type": t}), ([], set()), t)

    def test_malformed_type_ignored(self):
        self.assertEqual(schema.validate("x", {"type": 5}), ([], set()))
        self.assertEqual(schema.validate("x", {"type": ["string", 5]}), ([], set()))


class RequiredProperties(unittest.TestCase):
    def test_missing_required(self):
        errs, _ = schema.validate({}, {"type": "object", "required": ["text"]})
        self.assertEqual(errs, ["$: missing required property 'text'"])

    def test_required_present(self):
        self.assertEqual(schema.validate({"text": "x"}, {"required": ["text"]}), ([], set()))

    def test_nested_property_path(self):
        s = {"type": "object", "properties": {"a": {"type": "object", "properties": {"b": {"type": "string"}}}}}
        errs, _ = schema.validate({"a": {"b": 5}}, s)
        self.assertEqual(errs, ["$.a.b: expected string, got integer"])

    def test_additional_properties_false(self):
        s = {"type": "object", "properties": {"text": {"type": "string"}}, "additionalProperties": False}
        errs, _ = schema.validate({"text": "x", "extra": 1}, s)
        self.assertEqual(errs, ["$.extra: additional property not allowed"])

    def test_additional_properties_schema(self):
        s = {"properties": {"text": {"type": "string"}}, "additionalProperties": {"type": "number"}}
        self.assertEqual(schema.validate({"text": "x", "extra": 1}, s), ([], set()))
        errs, _ = schema.validate({"extra": "nope"}, s)
        self.assertEqual(errs, ["$.extra: expected number, got string"])

    def test_additional_properties_true_default(self):
        self.assertEqual(schema.validate({"anything": 1}, {"properties": {}, "additionalProperties": True}),
                         ([], set()))
        self.assertEqual(schema.validate({"anything": 1}, {"properties": {}}), ([], set()))


class EnumConst(unittest.TestCase):
    def test_enum_pass_fail(self):
        s = {"enum": ["a", "b"]}
        self.assertEqual(schema.validate("a", s), ([], set()))
        errs, _ = schema.validate("c", s)
        self.assertEqual(errs, ['$: "c" is not one of the enum values'])

    def test_const_pass_fail(self):
        s = {"const": 42}
        self.assertEqual(schema.validate(42, s), ([], set()))
        errs, _ = schema.validate(43, s)
        self.assertEqual(errs, ["$: 43 does not equal the const value"])

    def test_enum_bool_vs_number_distinct(self):
        errs, _ = schema.validate(True, {"enum": [1, 0]})
        self.assertEqual(len(errs), 1)
        self.assertEqual(schema.validate(1, {"enum": [1, 0]}), ([], set()))


class StringConstraints(unittest.TestCase):
    def test_min_max_length(self):
        s = {"minLength": 2, "maxLength": 4}
        self.assertEqual(schema.validate("abc", s), ([], set()))
        self.assertIn("minLength", schema.validate("a", s)[0][0])
        self.assertIn("maxLength", schema.validate("abcde", s)[0][0])

    def test_pattern(self):
        s = {"pattern": "^[a-z]+$"}
        self.assertEqual(schema.validate("abc", s), ([], set()))
        errs, _ = schema.validate("ABC", s)
        self.assertEqual(errs, ["$: does not match pattern '^[a-z]+$'"])

    def test_malformed_pattern_does_not_crash(self):
        errs, unsup = schema.validate("abc", {"pattern": "("})
        self.assertEqual(errs, [])
        self.assertEqual(unsup, {"pattern"})


class NumberConstraints(unittest.TestCase):
    def test_minimum_maximum(self):
        s = {"minimum": 0, "maximum": 10}
        self.assertEqual(schema.validate(5, s), ([], set()))
        self.assertTrue(schema.validate(-1, s)[0])
        self.assertTrue(schema.validate(11, s)[0])

    def test_exclusive(self):
        s = {"exclusiveMinimum": 0, "exclusiveMaximum": 10}
        self.assertEqual(schema.validate(5, s), ([], set()))
        self.assertTrue(schema.validate(0, s)[0])
        self.assertTrue(schema.validate(10, s)[0])


class ArrayConstraints(unittest.TestCase):
    def test_min_max_items(self):
        s = {"minItems": 1, "maxItems": 2}
        self.assertEqual(schema.validate([1], s), ([], set()))
        self.assertTrue(schema.validate([], s)[0])
        self.assertTrue(schema.validate([1, 2, 3], s)[0])

    def test_items_schema_nested_paths(self):
        s = {"items": {"type": "string"}}
        errs, _ = schema.validate(["a", 1, "c", 2], s)
        self.assertEqual(errs, ["$[1]: expected string, got integer", "$[3]: expected string, got integer"])

    def test_tuple_items_unsupported(self):
        errs, unsup = schema.validate([1, "x"], {"items": [{"type": "integer"}, {"type": "string"}]})
        self.assertEqual(unsup, {"items"})


class Unsupported(unittest.TestCase):
    def test_unsupported_collected(self):
        errs, unsup = schema.validate({"a": 1}, {"$ref": "#/foo", "oneOf": [{"type": "string"}]})
        self.assertEqual(unsup, {"$ref", "oneOf"})

    def test_unsupported_nested(self):
        s = {"type": "object", "properties": {"a": {"allOf": [{"type": "string"}]}}}
        errs, unsup = schema.validate({"a": "x"}, s)
        self.assertEqual(unsup, {"allOf"})

    def test_defs_as_container_is_unsupported(self):
        errs, unsup = schema.validate({}, {"$defs": {"x": {"type": "string"}}, "definitions": {}})
        self.assertEqual(unsup, {"$defs", "definitions"})

    def test_many_unsupported_keywords(self):
        s = {"not": {}, "if": {}, "then": {}, "else": {}, "patternProperties": {}, "dependentRequired": {},
             "prefixItems": [], "uniqueItems": True, "multipleOf": 2, "propertyNames": {}, "minProperties": 1,
             "maxProperties": 5, "contains": {}}
        _, unsup = schema.validate({}, s)
        self.assertEqual(unsup, set(s))


class AnnotationsIgnored(unittest.TestCase):
    def test_annotations_not_reported(self):
        s = {"title": "t", "description": "d", "default": 1, "examples": [1], "$schema": "x", "$id": "y",
             "$comment": "z", "format": "email", "deprecated": True, "readOnly": True, "writeOnly": True,
             "type": "string"}
        errs, unsup = schema.validate("hi", s)
        self.assertEqual((errs, unsup), ([], set()))


class TrivialSchemas(unittest.TestCase):
    def test_true_and_empty_accept_anything(self):
        for s in (True, {}):
            self.assertEqual(schema.validate("anything", s), ([], set()))
            self.assertEqual(schema.validate(None, s), ([], set()))
            self.assertEqual(schema.validate({"a": 1}, s), ([], set()))

    def test_false_rejects_everything(self):
        errs, unsup = schema.validate("x", False)
        self.assertEqual(errs, ["$: schema is false, nothing is valid"])
        self.assertEqual(unsup, set())

    def test_non_dict_non_bool_schema_is_unsupported_and_accepts(self):
        errs, unsup = schema.validate("x", 5)
        self.assertEqual(errs, [])
        self.assertEqual(unsup, {"<non-object schema>"})


class ErrorCap(unittest.TestCase):
    def test_cap_at_twenty(self):
        s = {"type": "object", "properties": {f"k{i}": {"type": "string"} for i in range(30)}}
        instance = {f"k{i}": 1 for i in range(30)}
        errs, _ = schema.validate(instance, s)
        self.assertEqual(len(errs), 20)


class MalformedSchemaDoesNotCrash(unittest.TestCase):
    def test_bad_constraint_values(self):
        s = {"minLength": "two", "maxLength": None, "minItems": "x", "maxItems": [], "minimum": "a",
             "maximum": {}, "exclusiveMinimum": "b", "exclusiveMaximum": None, "pattern": 5,
             "required": "text", "properties": "oops", "additionalProperties": "oops", "enum": "oops",
             "items": "oops"}
        try:
            errs, unsup = schema.validate({"a": "x", "b": [1, 2]}, s)
        except Exception as e:  # pragma: no cover - the point of the test is that this never happens
            self.fail(f"validate() raised {e!r}")

    def test_deep_nesting_capped(self):
        instance = []
        node = instance
        for _ in range(200):
            node.append([])
            node = node[0]
        s = {"items": {"items": True}}
        try:
            errs, unsup = schema.validate(instance, {"items": s})
        except RecursionError:
            self.fail("validate() recursed without a depth cap")


class RealisticMcpSchema(unittest.TestCase):
    INPUT_SCHEMA = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "search text"},
            "mode": {"type": "string", "enum": ["fast", "thorough"]},
        },
        "required": ["query"],
        "additionalProperties": False,
    }

    def test_valid_call(self):
        self.assertEqual(schema.validate({"query": "hi", "mode": "fast"}, self.INPUT_SCHEMA), ([], set()))

    def test_missing_required(self):
        errs, unsup = schema.validate({"mode": "fast"}, self.INPUT_SCHEMA)
        self.assertEqual(errs, ["$: missing required property 'query'"])
        self.assertEqual(unsup, set())

    def test_bad_enum_value(self):
        errs, _ = schema.validate({"query": "hi", "mode": "slow"}, self.INPUT_SCHEMA)
        self.assertEqual(errs, ['$.mode: "slow" is not one of the enum values'])

    def test_additional_property_denied(self):
        errs, _ = schema.validate({"query": "hi", "extra": 1}, self.INPUT_SCHEMA)
        self.assertEqual(errs, ["$.extra: additional property not allowed"])


if __name__ == "__main__":
    unittest.main()
