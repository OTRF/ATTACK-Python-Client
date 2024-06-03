import requests
from pathlib import Path
from typing import Optional, List, Dict
import re
import json

class STIXDownloader:
    def __init__(self, download_dir: str, domain: Optional[str] = None, stix_version: Optional[str] = None, use_session: bool = False):
        """
        Initializes the STIXDownloader with optional default settings.

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
        """
        Fetches available ATT&CK versions in STIX 2.0 format from the cti GitHub repository.

        Returns:
            List[str]: A list of available ATT&CK versions in STIX 2.0 format.
        """
        ref_to_tag = re.compile(r"ATT&CK-v(.*)")
        tags = requests.get("https://api.github.com/repos/mitre/cti/git/refs/tags").json()
        versions = [ref_to_tag.search(tag["ref"]).groups()[0] for tag in tags if "ATT&CK-v" in tag["ref"]]
        return versions

    @staticmethod
    def fetch_attack_stix2_1_versions() -> List[str]:
        """
        Fetches available ATT&CK versions in STIX 2.1 format from the attack-stix-data repository.

        Returns:
            List[str]: A list of available ATT&CK versions in STIX 2.1 format.
        """
        index_url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
        index_data = requests.get(index_url).json()
        versions = [v["version"] for v in index_data["collections"][0]["versions"]]
        return versions

    def download_file(self, url: str, dest_path: str) -> None:
        """
        Downloads a file from the given URL to the specified destination path.

        Args:
            url (str): URL of the file to download.
            dest_path (str): Destination file path to save the downloaded file.

        Raises:
            requests.HTTPError: If the download request fails.
        """
        if self.session:
            response = self.session.get(url, stream=True)  # Use session if available
        else:
            response = requests.get(url, stream=True)  # Otherwise, use a regular request
        
        response.raise_for_status()
        with open(dest_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

    def is_pretty_printed(self, file_path: str) -> bool:
        """
        Checks if the JSON file is already pretty-printed.

        Args:
            file_path (str): Path to the JSON file to check.

        Returns:
            bool: True if the file is pretty-printed, False otherwise.
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                if i > 10:  # Check only the first few lines for efficiency
                    break
                if len(line.strip()) == 0:
                    continue
                if line.strip().startswith('{') or line.strip().startswith('['):
                    continue
                return True
        return False

    def pretty_print_json(self, file_path: str) -> None:
        """
        Converts a compact JSON file to a pretty-printed format.

        Args:
            file_path (str): Path to the JSON file to be pretty-printed.
        """
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

    def download_attack_data(self, stix_version: Optional[str] = None, domain: Optional[str] = None, release: Optional[str] = None, pretty_print: Optional[bool] = None):
        """
        Downloads the ATT&CK STIX release file. If release is not specified, downloads the latest release.

        Args:
            stix_version (Optional[str]): Version of STIX to download. Options are "2.0" or "2.1". If not specified, uses the default.
            domain (Optional[str]): An ATT&CK domain from the following list ["enterprise", "mobile", "ics"]. If not specified, uses the default.
            release (Optional[str]): ATT&CK release to download. If not specified, downloads the latest release.
            pretty_print (Optional[bool]): Whether to pretty-print the JSON file after downloading. If None, do not pretty-print.

        Raises:
            ValueError: If the STIX version is invalid or the release version does not exist.
        """
        stix_version = stix_version or self.stix_version
        domain = domain or self.domain

        if stix_version not in ["2.0", "2.1"]:
            raise ValueError("Invalid STIX version. Choose '2.0' or '2.1'.")

        if stix_version == "2.0":
            versions = self.fetch_attack_stix2_0_versions()
            base_url = self.cti_base_url
            if release is None:
                release_dir = "master"
            elif release not in versions:
                raise ValueError(f"Release {release} not found in cti repository.")
            else:
                release_dir = f"ATT%26CK-v{release}"
            url_path = f"{release_dir}/{domain}-attack/{domain}-attack.json"
        else:
            versions = self.fetch_attack_stix2_1_versions()
            base_url = self.stix_data_base_url
            if release is None:
                release_dir = "master"
            elif release not in versions:
                raise ValueError(f"Release {release} not found in attack-stix-data repository.")
            else:
                url_path = f"{domain}-attack/{domain}-attack-{release}.json"

        download_url = f"{base_url}{url_path}"
        
        release_folder = "latest" if release is None else f"v{release}"
        release_download_dir = Path(self.download_dir) / release_folder
        release_download_dir.mkdir(parents=True, exist_ok=True)

        dest_path = release_download_dir / f"{domain}-attack.json"
        self.download_file(download_url, dest_path)

        self.downloaded_file_path = str(dest_path)  # Store the full path of the downloaded file
        self.downloaded_file_paths[domain] = str(dest_path)  # Store the path for the specific domain

        if pretty_print:
            if self.is_pretty_printed(self.downloaded_file_path):
                print("Warning: The file appears to be already pretty-printed.")
            self.pretty_print_json(self.downloaded_file_path)

        print(f"Downloaded {domain}-attack.json to {release_download_dir}")

    def download_all_domains(self, stix_version: Optional[str] = None, release: Optional[str] = None, pretty_print: Optional[bool] = None):
        """
        Downloads the ATT&CK STIX release files for all domains (enterprise, mobile, ics).

        Args:
            stix_version (Optional[str]): Version of STIX to download. Options are "2.0" or "2.1". If not specified, uses the default.
            release (Optional[str]): ATT&CK release to download. If not specified, downloads the latest release.
            pretty_print (Optional[bool]): Whether to pretty-print the JSON file after downloading. If None, do not pretty-print.
        """
        domains = ["enterprise", "mobile", "ics"]
        for domain in domains:
            self.download_attack_data(stix_version=stix_version, domain=domain, release=release, pretty_print=pretty_print)

        return self.downloaded_file_paths