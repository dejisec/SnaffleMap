"""SnaffleMap — Parse, filter, sort, and export Snaffler output."""

from snafflemap.filters import FilterChain
from snafflemap.models import DirResult, FileResult, ResultSet, Severity, ShareResult
from snafflemap.parsers import ParseError, deduplicate, parse, parse_iter

__all__ = [
    "DirResult",
    "FileResult",
    "FilterChain",
    "ParseError",
    "ResultSet",
    "Severity",
    "ShareResult",
    "deduplicate",
    "parse",
    "parse_iter",
]
