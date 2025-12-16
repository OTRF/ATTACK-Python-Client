"""Command-line interface for attackcti.

This is intentionally small and dependency-light (stdlib only). It provides a thin wrapper
over `attackcti.utils.downloader.STIXDownloader`.
"""

from __future__ import annotations

import argparse
import sys


def _build_parser() -> argparse.ArgumentParser:
    """Build the top-level CLI parser."""
    parser = argparse.ArgumentParser(prog="attackcti", description="Utilities for working with MITRE ATT&CK CTI data.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    download = subparsers.add_parser("download", help="Download ATT&CK STIX bundles from upstream sources.")
    download.add_argument("--download-dir", "-d", required=True, help="Directory to write downloaded files into.")
    download.add_argument(
        "--stix-version",
        choices=("2.0", "2.1"),
        default="2.1",
        help="STIX version to download.",
    )
    download.add_argument(
        "--domain",
        choices=("enterprise", "mobile", "ics"),
        help="Domain to download (omit to use --all-domains).",
    )
    download.add_argument("--release", help="Specific ATT&CK release (omit for latest).")
    download.add_argument("--pretty-print", action="store_true", help="Pretty-print JSON after download.")
    download.add_argument("--all-domains", action="store_true", help="Download enterprise, mobile, and ics.")

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for the `attackcti` command."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "download":
        from .utils.downloader import STIXDownloader

        if not args.all_domains and not args.domain:
            parser.error("Provide --domain or use --all-domains.")
        if args.all_domains and args.domain:
            parser.error("--domain and --all-domains are mutually exclusive.")

        downloader = STIXDownloader(download_dir=args.download_dir)
        if args.all_domains:
            downloader.download_all_domains(
                stix_version=args.stix_version,
                release=args.release,
                pretty_print=args.pretty_print,
            )
        else:
            downloader.download_attack_data(
                stix_version=args.stix_version,
                domain=args.domain,
                release=args.release,
                pretty_print=args.pretty_print,
            )
        return 0

    parser.error(f"Unknown command: {args.command}")
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
