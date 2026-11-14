"""Error type carrying the JSON path of one offending value."""


class InputError(Exception):
    """Raised when the input document is invalid.

    ``path`` is a JSON path with zero-based array indices locating one
    offending value (e.g. ``$.ops[2][3]``); ``"$"`` is used for JSON
    syntax errors and whole-document problems.
    """

    def __init__(self, path):
        self.path = path
        super().__init__(path)
