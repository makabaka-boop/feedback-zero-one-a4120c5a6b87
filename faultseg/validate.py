"""Validation of the decoded JSON document and conversion to a typed IR.

Everything here is hand-written; only the stdlib ``json`` module is used
elsewhere for decoding/encoding.

Pattern IR produced by :func:`validate`::

    ("leaf", type)
    ("or",   P, Q)
    ("seq",  P, Q, (g_lo, g_hi), frozenset(blockers))
    ("rep",  P, m, n, (g_lo, g_hi), frozenset(blockers))

Ops IR::

    ("event", id, key, type, t)
    ("wm",    w)
"""

import json
import re

from .errors import InputError

_IDENT = re.compile(r"[A-Za-z0-9]+")
_OPERATORS = ("or", "seq", "rep")
_KNOWN_MEMBERS = ("span", "pattern", "ops")


def _is_int(value):
    """JSON integer (booleans are explicitly rejected)."""
    return isinstance(value, int) and not isinstance(value, bool)


def _ident(value, path):
    """Non-empty ASCII alphanumeric identifier."""
    if not (isinstance(value, str) and _IDENT.fullmatch(value)):
        raise InputError(path)
    return value


def _member_path(name):
    if _IDENT.fullmatch(name):
        return "$." + name
    return "$[" + json.dumps(name) + "]"


def _interval(node, path):
    """g: closed interval of non-negative integers [lo, hi], lo <= hi."""
    if not (isinstance(node, list) and len(node) == 2):
        raise InputError(path)
    lo, hi = node
    if not (_is_int(lo) and lo >= 0):
        raise InputError(path + "[0]")
    if not (_is_int(hi) and hi >= 0):
        raise InputError(path + "[1]")
    if lo > hi:
        raise InputError(path)
    return (lo, hi)


def _blockers(node, path):
    """b: array of type strings without duplicates."""
    if not isinstance(node, list):
        raise InputError(path)
    seen = set()
    out = []
    for i, value in enumerate(node):
        _ident(value, "%s[%d]" % (path, i))
        if value in seen:
            raise InputError("%s[%d]" % (path, i))
        seen.add(value)
        out.append(value)
    return frozenset(out)


def _pattern(node, path):
    if isinstance(node, str):
        _ident(node, path)
        return ("leaf", node)
    if isinstance(node, list):
        if not node:
            raise InputError(path)
        head = node[0]
        if not isinstance(head, str) or head not in _OPERATORS:
            raise InputError(path + "[0]")
        if head == "or":
            if len(node) != 3:
                raise InputError(path)
            return ("or",
                    _pattern(node[1], path + "[1]"),
                    _pattern(node[2], path + "[2]"))
        if head == "seq":
            if len(node) != 5:
                raise InputError(path)
            return ("seq",
                    _pattern(node[1], path + "[1]"),
                    _pattern(node[2], path + "[2]"),
                    _interval(node[3], path + "[3]"),
                    _blockers(node[4], path + "[4]"))
        # head == "rep"
        if len(node) != 6:
            raise InputError(path)
        m, n = node[2], node[3]
        if not (_is_int(m) and m >= 1):
            raise InputError(path + "[2]")
        if not (_is_int(n) and n >= 1):
            raise InputError(path + "[3]")
        if m > n:
            raise InputError(path + "[3]")
        return ("rep",
                _pattern(node[1], path + "[1]"),
                m, n,
                _interval(node[4], path + "[4]"),
                _blockers(node[5], path + "[5]"))
    raise InputError(path)


def _ops(node, path):
    if not isinstance(node, list):
        raise InputError(path)
    out = []
    watermark = -1
    ids = set()
    for i, element in enumerate(node):
        ep = "%s[%d]" % (path, i)
        if isinstance(element, list):
            if len(element) != 4:
                raise InputError(ep)
            eid = _ident(element[0], ep + "[0]")
            key = _ident(element[1], ep + "[1]")
            etype = _ident(element[2], ep + "[2]")
            t = element[3]
            if not (_is_int(t) and t >= 0):
                raise InputError(ep + "[3]")
            if eid in ids:
                raise InputError(ep + "[0]")
            ids.add(eid)
            if t <= watermark:
                raise InputError(ep + "[3]")
            out.append(("event", eid, key, etype, t))
        elif _is_int(element):
            if element < watermark:
                raise InputError(ep)
            watermark = element
            out.append(("wm", element))
        else:
            raise InputError(ep)
    return out


def validate(root):
    """Validate the decoded document; return ``(span, pattern_ir, ops_ir)``."""
    if not isinstance(root, dict):
        raise InputError("$")
    for name in root:
        if name not in _KNOWN_MEMBERS:
            raise InputError(_member_path(name))
    for name in _KNOWN_MEMBERS:
        if name not in root:
            raise InputError("$")
    span = root["span"]
    if not (_is_int(span) and span >= 1):
        raise InputError("$.span")
    pattern = _pattern(root["pattern"], "$.pattern")
    ops = _ops(root["ops"], "$.ops")
    return span, pattern, ops
