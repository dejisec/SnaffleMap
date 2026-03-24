"""Shared utilities for export modules."""


def human_size(size: int) -> str:
    """Convert bytes to human-readable string."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024**2:
        return f"{size / 1024:.1f} KB"
    elif size < 1024**3:
        return f"{size / 1024**2:.1f} MB"
    else:
        return f"{size / 1024**3:.1f} GB"
