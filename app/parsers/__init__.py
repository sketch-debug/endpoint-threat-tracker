"""Read-only log/inventory parsers. Entry point: parse_file(path, settings)."""
from .base import ParseError, dedup_key
from .dispatch import parse_file

__all__ = ["parse_file", "ParseError", "dedup_key"]
