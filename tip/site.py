"""Build the static dashboard published to GitHub Pages."""
from __future__ import annotations

import pathlib

from jinja2 import Environment, FileSystemLoader, select_autoescape


def build_site(
    context: dict, out_dir: str | pathlib.Path, templates_dir: str | pathlib.Path
) -> list[pathlib.Path]:
    out_dir = pathlib.Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=select_autoescape(enabled_extensions=("html", "htm", "xml", "j2")),
        keep_trailing_newline=True,
    )
    index_html = env.get_template("index.html.j2").render(**context)
    report_html = env.get_template("report.html.j2").render(**context)
    (out_dir / "index.html").write_text(index_html, encoding="utf-8")
    (out_dir / "report.html").write_text(report_html, encoding="utf-8")
    return [out_dir / "index.html", out_dir / "report.html"]
