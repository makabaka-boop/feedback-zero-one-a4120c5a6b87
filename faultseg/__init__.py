"""Fault-segment extraction backend."""

from .errors import InputError
from .pipeline import run_text

__all__ = ["InputError", "run_text"]
