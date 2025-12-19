"""Download utilities for ATT&CK STIX bundles."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Union

import requests


class STIXDownloader:
    """Download ATT&CK STIX bundles from upstream repositories."""

    def __init__(self, download_dir: str, domain: Optional[str] = None, stix_version: Optional[str] = None, use_session: bool = False):
        """Initialize the downloader with optional defaults.

        Args:
            download_dir (str): Directory to download the STIX files to.
            domain (Optional[str]): Default ATT&CK domain from the following list ["enterprise", "mobile", "ics"].
            stix_version (Optional[str]): Default version of STIX to download. Options are "2.0" or "2.1".
            use_session (bool): Whether to use a persistent session for HTTP requests. Defaults to False.
        """
        self.download_dir = download_dir
        self.domain = domain
        self.stix_version = stix_version
        self.use_session = use_session
        self.cti_base_url = "https://raw.githubusercontent.com/mitre/cti/"
        self.stix_data_base_url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
        self.session = requests.Session() if use_session else None  # Use a session if specified
        self.downloaded_file_paths: Dict[str, str] = {}  # Attribute to store the full paths of the downloaded files

    @staticmethod
    def fetch_attack_stix2_0_versions() -> List[str]:
        """Fetch available ATT&CK versions in STIX 2.0 format.

        Returns
        -------
            List[str]: A list of available ATT&CK versions in STIX 2.0 format.
        """
        ref_to_tag = re.compile(r"ATT&CK-v(.*)")
        resp = requests.get("https://api.github.com/repos/mitre/cti/git/refs/tags", timeout=30)
        resp.raise_for_status()
        tags = resp.json()
        versions = [ref_to_tag.search(tag["ref"]).groups()[0] for tag in tags if "ATT&CK-v" in tag["ref"]]
        return versions

    @staticmethod
    def fetch_attack_stix2_1_versions() -> List[str]:
        """Fetch available ATT&CK versions in STIX 2.1 format.

        Returns
        -------
            List[str]: A list of available ATT&CK versions in STIX 2.1 format.
        """
        index_url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
        resp = requests.get(index_url, timeout=30)
        resp.raise_for_status()
        index_data = resp.json()
        versions = [v["version"] for v in index_data["collections"][0]["versions"]]
        return versions

    @staticmethod
    def _version_key(version: str) -> tuple[int, ...]:
        """Return a comparable key for dotted ATT&CK versions (e.g., '18.1')."""
        parts: list[int] = []
        for part in str(version).split("."):
            try:
                parts.append(int(part))
            except ValueError:
                # Fallback: treat non-numeric segments as 0.
                parts.append(0)
        return tuple(parts)

    def download_file(self, url: str, dest_path: Union[str, Path]) -> None:
        """Download a file from `url` to `dest_path`.

        Args:
            url (str): URL of the file to download.
            dest_path (str | Path): Destination file path to save the downloaded file.

        Raises
        ------
            requests.HTTPError: If the download request fails.
        """
        if self.session:
            response = self.session.get(url, stream=True, timeout=60)  # Use session if available
        else:
            response = requests.get(url, stream=True, timeout=60)  # Otherwise, use a regular request
        
        response.raise_for_status()
        with open(dest_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

    def is_pretty_printed(self, file_path: Union[str, Path]) -> bool:
        """Heuristically detect whether a JSON file is already pretty-printed.

        This is a best-effort check to avoid reformatting files that already have
        indentation and newlines. It intentionally only inspects a small prefix
        of the file for performance.
        """
        path = Path(file_path)
        with path.open("rb") as f:
            prefix = f.read(8192)

        # If the file contains no newlines at all, it's almost certainly compact/minified.
        if b"\n" not in prefix and b"\r" not in prefix:
            return False

        # Detect an indentation pattern on a subsequent line.
        # Example: '\n    "objects": ...'
        return re.search(rb"\r?\n[ \t]{2,}\"", prefix) is not None

    def pretty_print_json(self, file_path: Union[str, Path]) -> None:
        """Rewrite a JSON file with indentation (atomic write)."""
        path = Path(file_path)
        data = json.loads(path.read_text(encoding="utf-8"))

        tmp_path = path.with_suffix(path.suffix + ".tmp")
        tmp_path.write_text(
            json.dumps(data, indent=4, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        os.replace(tmp_path, path)

    def download_attack_data(
        self,
        stix_version: Optional[str] = None,
        domain: Optional[str] = None,
        release: Optional[str] = None,
        pretty_print: Optional[bool] = None,
        *,
        force: bool = True,
    ):
        """Download an ATT&CK STIX release file.

        Args:
            stix_version (Optional[str]): Version of STIX to download. Options are "2.0" or "2.1". If not specified, uses the default.
            domain (Optional[str]): An ATT&CK domain from the following list ["enterprise", "mobile", "ics"]. If not specified, uses the default.
            release (Optional[str]): ATT&CK release to download. If not specified, downloads the latest release.
            pretty_print (Optional[bool]): Whether to pretty-print the JSON file after downloading. If None, do not pretty-print.
            force (bool): When `False`, skip downloading if the destination file already exists.

        Raises
        ------
            ValueError: If the STIX version is invalid or the release version does not exist.
        """
        stix_version = stix_version or self.stix_version
        domain = domain or self.domain

        if stix_version not in ["2.0", "2.1"]:
            raise ValueError("Invalid STIX version. Choose '2.0' or '2.1'.")

        resolved_release: str | None = release
        if stix_version == "2.0":
            base_url = self.cti_base_url
            if release is None:
                release_dir = "master"
            else:
                versions = self.fetch_attack_stix2_0_versions()
                if release not in versions:
                    raise ValueError(f"Release {release} not found in cti repository.")
                release_dir = f"ATT%26CK-v{release}"
            url_path = f"{release_dir}/{domain}-attack/{domain}-attack.json"
        else:
            base_url = self.stix_data_base_url
            if release is None:
                # Prefer a versioned file so we can name the directory by the actual version.
                # This requires a versions lookup from the upstream index.json.
                try:
                    versions = self.fetch_attack_stix2_1_versions()
                    resolved_release = max(versions, key=self._version_key) if versions else None
                except Exception:
                    resolved_release = None

                if resolved_release:
                    url_path = f"{domain}-attack/{domain}-attack-{resolved_release}.json"
                else:
                    # Fallback to the unversioned latest bundle if index lookup fails.
                    url_path = f"{domain}-attack/{domain}-attack.json"
            else:
                versions = self.fetch_attack_stix2_1_versions()
                if release not in versions:
                    raise ValueError(f"Release {release} not found in attack-stix-data repository.")
                url_path = f"{domain}-attack/{domain}-attack-{release}.json"

        download_url = f"{base_url}{url_path}"
        
        release_folder = f"v{resolved_release}" if resolved_release else "latest"
        release_download_dir = Path(self.download_dir) / release_folder
        release_download_dir.mkdir(parents=True, exist_ok=True)

        dest_path = release_download_dir / f"{domain}-attack.json"
        if not force and dest_path.exists():
            self.downloaded_file_path = str(dest_path)
            self.downloaded_file_paths[domain] = str(dest_path)
            return

        self.download_file(download_url, dest_path)

        self.downloaded_file_path = str(dest_path)  # Store the full path of the downloaded file
        self.downloaded_file_paths[domain] = str(dest_path)  # Store the path for the specific domain

        if pretty_print:
            if not self.is_pretty_printed(dest_path):
                self.pretty_print_json(dest_path)

        print(f"Downloaded {domain}-attack.json to {release_download_dir}")

    def download_all_domains(
        self,
        stix_version: Optional[str] = None,
        release: Optional[str] = None,
        pretty_print: Optional[bool] = None,
        *,
        force: bool = True,
    ):
        """Download ATT&CK STIX release files for all domains.

        Args:
            stix_version (Optional[str]): Version of STIX to download. Options are "2.0" or "2.1". If not specified, uses the default.
            release (Optional[str]): ATT&CK release to download. If not specified, downloads the latest release.
            pretty_print (Optional[bool]): Whether to pretty-print the JSON file after downloading. If None, do not pretty-print.
            force (bool): When `False`, skip downloading files that already exist.
        """
        domains = ["enterprise", "mobile", "ics"]
        for domain in domains:
            self.download_attack_data(
                stix_version=stix_version,
                domain=domain,
                release=release,
                pretty_print=pretty_print,
                force=force,
            )

        return self.downloaded_file_paths
