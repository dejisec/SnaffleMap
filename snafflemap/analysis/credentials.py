"""Extract structured credentials from a file finding's text."""

from __future__ import annotations

import re

from snafflemap.analysis.models import Credential


def extract_credentials(finding, extractors) -> list[Credential]:
    """Return credentials found in *finding* (FileResults only).

    Each extractor's regex must define a named group ``secret`` and may define a
    named group ``user``. Matches are gathered from both match_context and
    matched_string, then de-duplicated by (type, secret).
    """
    if not hasattr(finding, "match_context"):
        return []

    texts = [
        getattr(finding, "match_context", "") or "",
        getattr(finding, "matched_string", "") or "",
    ]
    finding_id = finding.finding_id
    sources = getattr(finding, "sources", ())
    source = sources[0] if sources else ""

    seen: set[tuple[str, str]] = set()
    creds: list[Credential] = []
    for ex in extractors:
        pattern = re.compile(ex.regex)
        for text in texts:
            for m in pattern.finditer(text):
                groups = m.groupdict()
                secret = groups.get("secret")
                if not secret:
                    continue
                key = (ex.type, secret)
                if key in seen:
                    continue
                seen.add(key)
                creds.append(
                    Credential(
                        type=ex.type,
                        secret=secret,
                        username=groups.get("user"),
                        raw_context=m.group(0),
                        crackable=ex.crackable,
                        finding_id=finding_id,
                        source=source,
                        hashcat_mode=ex.hashcat_mode,
                    )
                )
    return creds
