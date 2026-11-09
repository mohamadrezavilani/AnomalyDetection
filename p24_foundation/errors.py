"""Public errors carry fixed codes, never source payloads or credentials."""

class FoundationError(Exception):
    def __init__(self, code):
        if not isinstance(code, str) or not code.replace('_', '').isalnum():
            code = "foundation_error"
        self.code = code
        super().__init__(code)

