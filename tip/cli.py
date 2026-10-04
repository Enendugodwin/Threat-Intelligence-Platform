"""Command line interface.

Usage: python -m tip <sync|report|export|site|stats|push> [options]
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import pathlib
import sys

from . import __version__
from .attack import load_attack_map
from .pipeline import load_config, run_sync
from .store import Store


def load_dotenv(path: str = ".env") -> None:
    """Minimal .env loader (no python-dotenv dependency)."""
    dotenv = pathlib.Path(path)
    if not dotenv.is_file():
        return
    for line in dotenv.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", default="config/config.yaml")
    parser.add_argument("--data-dir", default="data")
    parser.add_argument("--templates", default="templates")
    parser.add_argument("--attack-map", default="config/attack_map.yaml")
    parser.add_argument("-v", "--verbose", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tip", description="Threat intel pipeline")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    commands = (
        ("sync", "fetch enabled feeds and update the local database"),
        ("report", "render Markdown report(s) from the database"),
        ("export", "write STIX, Sigma, Suricata and CSV exports"),
        ("site", "build the static dashboard"),
        ("stats", "print database statistics"),
        ("push", "push indicators to MISP and/or OpenCTI (optional connectors)"),
    )
    for name, help_text in commands:
        _add_common(sub.add_parser(name, help=help_text))

    sub.choices["report"].add_argument("--out", default="reports")
    sub.choices["export"].add_argument("--out", default="dist")
    sub.choices["site"].add_argument("--out", default="site")
    sub.choices["push"].add_argument("--misp", action="store_true", help="push to MISP")
    sub.choices["push"].add_argument("--opencti", action="store_true", help="push to OpenCTI")
    sub.choices["push"].add_argument("--days", type=int, default=7)
    return parser


def main(argv=None) -> int:
    load_dotenv()
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    data_dir = pathlib.Path(args.data_dir)

    if args.command == "sync":
        from .reportfeed import fetch_reports

        config = load_config(args.config)
        stats = run_sync(config, data_dir)
        report_stats = fetch_reports(config, data_dir)
        if not report_stats.get("skipped"):
            sources = ", ".join(f"{k}: {v}" for k, v in report_stats["sources"].items())
            print(
                f"report feed: {report_stats['total']} reports "
                f"({report_stats['curated']} curated)" + (f" [{sources}]" if sources else "")
            )
            if report_stats.get("errors"):
                print(f"report feed errors: {report_stats['errors']}", file=sys.stderr)
        if stats.get("fatal"):
            print("all feeds failed - see log above", file=sys.stderr)
            return 1
        return 0

    if args.command == "stats":
        with Store(data_dir / "iocs.sqlite") as store:
            print(json.dumps(store.stats(), indent=2, sort_keys=True))
        return 0

    if args.command == "report":
        from . import report as report_mod

        config = load_config(args.config)
        attack = load_attack_map(args.attack_map)
        with Store(data_dir / "iocs.sqlite") as store:
            context = report_mod.build_context(store, config, attack)
        paths = report_mod.write_report(context, args.out, args.templates)
        print(f"wrote {paths[0]}")
        return 0

    if args.command == "export":
        from .exports import csv_export
        from .exports import sigma as sigma_mod
        from .exports import stix as stix_mod
        from .exports import suricata as suricata_mod
        from .exports import tor as tor_export

        config = load_config(args.config)
        attack = load_attack_map(args.attack_map)
        exports_cfg = config.get("exports") or {}
        window_days = int(exports_cfg.get("window_days", 30))
        max_rows = int(exports_cfg.get("max_rows", 30000))
        min_confidence = int(exports_cfg.get("min_confidence", 0))

        exclude_sources = [str(s) for s in (exports_cfg.get("exclude_sources") or [])]

        with Store(data_dir / "iocs.sqlite") as store:
            rows = store.rows_for_export(
                window_days, max_rows, min_confidence, exclude_sources=exclude_sources
            )
            tor_rows = store.source_rows("tor")

        out = pathlib.Path(args.out)
        bundle = stix_mod.build_bundle(rows)
        stix_path = stix_mod.write_bundle(bundle, out / "stix" / "bundle.json")
        csv_path = csv_export.write_csv(rows, out / "iocs.csv")

        sigma_cfg = exports_cfg.get("sigma") or {}
        sigma_rules = sigma_mod.build_rules(
            rows,
            attack,
            max_values_per_rule=int(sigma_cfg.get("max_values_per_rule", 200)),
            min_confidence=min_confidence,
        )
        sigma_mod.write_rules(sigma_rules, out / "sigma")

        suricata_cfg = exports_cfg.get("suricata") or {}
        suricata_lines = suricata_mod.build_rules(
            rows,
            max_rules=int(suricata_cfg.get("max_rules", 1500)),
            sid_base=int(suricata_cfg.get("sid_base", 9_100_000)),
            min_confidence=min_confidence,
        )
        suricata_path = suricata_mod.write_rules(suricata_lines, out / "suricata" / "ti.rules")
        tor_path, tor_count = tor_export.write_nodes(tor_rows, out / "tor" / "tor_nodes.txt")

        print(
            f"wrote {stix_path} ({bundle['_meta']['indicator_count']} indicators), {csv_path}, "
            f"{len(sigma_rules)} sigma rule(s), {suricata_path} ({len(suricata_lines)} rule(s)), "
            f"{tor_path} ({tor_count} Tor nodes)"
        )
        return 0

    if args.command == "site":
        from . import report as report_mod
        from . import site as site_mod
        from .reportfeed import load_reports

        config = load_config(args.config)
        attack = load_attack_map(args.attack_map)
        with Store(data_dir / "iocs.sqlite") as store:
            context = report_mod.build_context(store, config, attack)
        reports_doc = load_reports(data_dir)
        paths = site_mod.build_site(context, args.out, args.templates, reports=reports_doc or None)
        print(f"wrote {paths[0]}")
        if reports_doc:
            print(f"wrote report feed + {len(reports_doc.get('reports') or [])} report page(s)")
        return 0

    if args.command == "push":
        if not (args.misp or args.opencti):
            print("choose at least one of --misp / --opencti", file=sys.stderr)
            return 2
        with Store(data_dir / "iocs.sqlite") as store:
            rows = store.new_since(args.days)
            if args.misp:
                from .connectors import misp as misp_mod

                print(f"MISP: {misp_mod.push_new(rows)}")
            if args.opencti:
                from .connectors import opencti as opencti_mod

                print(f"OpenCTI: {opencti_mod.push_new(rows)}")
        return 0

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
