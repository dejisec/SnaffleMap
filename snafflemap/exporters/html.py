from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, PackageLoader

from snafflemap.exporters._utils import human_size
from snafflemap.models import ResultSet, Severity


def export(result_set: ResultSet, path: str | Path) -> None:
    path = Path(path)
    env = Environment(loader=PackageLoader("snafflemap", "templates"), autoescape=True)
    env.filters["human_size"] = human_size
    template = env.get_template("static.html.j2")
    html = template.render(result_set=result_set, severities=list(Severity))
    path.write_text(html, encoding="utf-8")
