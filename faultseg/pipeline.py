"""Parse -> validate -> execute pipeline for one input document."""

import json

from .engine import execute
from .errors import InputError
from .validate import validate


class _DuplicateMember(Exception):
    pass


def _object_no_duplicates(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise _DuplicateMember(key)
        obj[key] = value
    return obj


def _reject_constant(_value):
    # NaN / Infinity / -Infinity are not valid JSON
    raise ValueError("non-standard JSON constant")


def run_text(text):
    """Run one input document; return the output array.

    Raises :class:`InputError` with a JSON path on any invalid input
    (``$`` for syntax errors).
    """
    try:
        root = json.loads(
            text,
            object_pairs_hook=_object_no_duplicates,
            parse_constant=_reject_constant,
        )
    except (ValueError, _DuplicateMember, RecursionError):
        raise InputError("$")
    try:
        span, pattern, ops = validate(root)
    except RecursionError:
        raise InputError("$.pattern")
    return execute(span, pattern, ops)
