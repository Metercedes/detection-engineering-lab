class SigmaError(Exception):
    """Base class for problems with a rule rather than with the event being tested."""


class RuleParseError(SigmaError):
    pass


class UnsupportedFeatureError(SigmaError):
    """Raised for Sigma syntax this evaluator deliberately does not implement."""
