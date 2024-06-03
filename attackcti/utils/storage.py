from stix2 import FileSystemSource, MemorySource
from pathlib import Path

class STIXStore:
    def __init__(self, path: str, auto_load: bool = True):
        """
        Initializes the STIXStore.

        Args:
            path (str): Path to the source directory or JSON file.
            auto_load (bool): Flag indicating whether to automatically load data during initialization. Defaults to True.
        """
        self.path = Path(path)
        self.source = None
        
        if auto_load:
            self.load_data()

    def load_data(self):
        """
        Loads data from the specified path, determining if it's a directory or a file.
        
        Raises:
            ValueError: If the path is invalid or not specified correctly.
        """
        if self.path.is_dir():
            self.source = FileSystemSource(str(self.path))
        elif self.path.is_file() and self.path.suffix == '.json':
            self.source = MemorySource()
            self.source.load_from_file(str(self.path))
        else:
            raise ValueError(f"The specified path {self.path} is not a valid directory or JSON file.")

    def get_store(self):
        """
        Returns the loaded data store.

        Returns:
            The loaded data store (FileSystemSource or MemoryStore).
        """
        if self.source is None:
            raise ValueError("Data has not been loaded yet. Call load_data() first.")
        return self.source