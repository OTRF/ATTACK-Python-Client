"""Local STIX bundle loading helpers."""

from pathlib import Path

from stix2 import MemorySource

from .stix import find_json_files, load_stix_json_files


class STIXStore:
    """Load a STIX bundle from a directory or JSON file."""

    def __init__(self, path: str, auto_load: bool = True):
        """Initialize the store wrapper.

        Args:
            path (str): Path to the source directory or JSON file.
            auto_load (bool): Flag indicating whether to automatically load data during initialization. Defaults to True.
        """
        self.path = Path(path)
        self.source = None
        self.spec_version: str | None = None
        
        if auto_load:
            self.load_data()

    def load_data(self):
        """Load STIX objects from the configured path.
        
        Raises
        ------
            ValueError: If the path is invalid or not specified correctly.
        """
        if self.path.is_dir():
            json_files = find_json_files(self.path)
            if not json_files:
                raise ValueError(f"The specified path {self.path} contains no JSON files.")
            loaded = load_stix_json_files(json_files)
            self.source = MemorySource(stix_data=loaded.objects)
            self.spec_version = loaded.spec_version
        elif self.path.is_file() and self.path.suffix == '.json':
            loaded = load_stix_json_files([self.path])
            self.source = MemorySource(stix_data=loaded.objects)
            self.spec_version = loaded.spec_version
        else:
            raise ValueError(f"The specified path {self.path} is not a valid directory or JSON file.")

    def get_store(self):
        """Return the loaded data store.

        Returns
        -------
            The loaded data store (FileSystemSource or MemorySource).
        """
        if self.source is None:
            raise ValueError("Data has not been loaded yet. Call load_data() first.")
        return self.source
