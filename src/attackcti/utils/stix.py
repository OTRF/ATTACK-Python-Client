"""STIX utility helpers."""

from __future__ import annotations

import json
from collections.abc import Callable
from itertools import islice
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

import stix2
from pydantic import BaseModel, TypeAdapter
from stix2 import CompositeDataSource, Filter, MemorySource, TAXIICollectionSource
from stix2.datastore.filters import apply_common_filters

from ..models import LoadedStix, pydantic_model_mapping


def as_dict(obj: Any) -> dict[str, Any]:
    """Return a dictionary view of a STIX object or raw mapping."""
    if isinstance(obj, dict):
        return obj

    try:
        return json.loads(obj.serialize())
    except Exception:
        inner = getattr(obj, "_inner", None)
        if isinstance(inner, dict):
            return inner
        try:
            return dict(obj)
        except Exception:
            return {}


def stix_id(obj: Any) -> str | None:
    """Return the STIX `id` from a dict or python-stix2 object."""
    if isinstance(obj, dict):
        value = obj.get("id")
        return value if isinstance(value, str) and value else None
    value = getattr(obj, "id", None)
    return value if isinstance(value, str) and value else None


def stix_type(obj: Any) -> str | None:
    """Return the STIX `type` from a dict or python-stix2 object."""
    if isinstance(obj, dict):
        value = obj.get("type")
        return value if isinstance(value, str) and value else None
    value = getattr(obj, "type", None)
    return value if isinstance(value, str) and value else None


def relationship_ref(obj: Any, key: str) -> str | None:
    """Extract a STIX relationship reference field from dicts or python-stix2 objects."""
    if isinstance(obj, dict):
        value = obj.get(key)
        return value if isinstance(value, str) and value else None
    value = getattr(obj, key, None)
    return value if isinstance(value, str) and value else None


def relationship_source_ref(obj: Any) -> str | None:
    """Return `source_ref` from a relationship object/dict."""
    return relationship_ref(obj, "source_ref")


def relationship_target_ref(obj: Any) -> str | None:
    """Return `target_ref` from a relationship object/dict."""
    return relationship_ref(obj, "target_ref")


def get_stix_objects(
    *,
    source: TAXIICollectionSource | MemorySource,
    filter_objects: dict[str, Filter | Callable[[], Any]],
    stix_format: bool = True,
) -> dict[str, list[Any]]:
    """
    Retrieve STIX objects from the specified TAXII or MemorySource collection source based on the given filters or methods.

    Depending on the 'stix_format' flag, this function returns the STIX objects in their original format or 
    as parsed objects based on Pydantic models.

    Args:
        source (TAXIICollectionSource): The TAXII collection source to query for STIX objects.
        filter_objects (Dict[str, Union[Filter, Callable]]): A mapping of object types to their respective
                        TAXII filters or custom methods that return STIX objects.
        stix_format (bool, optional): If True, returns STIX objects in their original format. If False, returns the results
                            as parsed objects based on Pydantic models, providing a user-friendly representation.

    Returns
    -------
        Dict[str, List]: A dictionary categorizing STIX objects by their types. Each key represents an object
        type (e.g., 'techniques', 'campaigns'), and each value is a list of STIX objects in their original format
        or parsed objects based on Pydantic models, depending on the 'stix_format' flag.
    """
    stix_objects_result: dict[str, list[Any]] = {}
    for key, method_or_filter in filter_objects.items():
        if isinstance(method_or_filter, Filter):
            objects = source.query(method_or_filter)
        else:
            objects = method_or_filter()

        if not stix_format and pydantic_model_mapping is not None:
            pydantic_model = pydantic_model_mapping.get(key)
            if pydantic_model is not None:
                objects = parse_stix_objects(objects, pydantic_model)

        stix_objects_result[key] = objects

    return stix_objects_result


def parse_stix_objects(stix_objects: list[Any], model: type[BaseModel]) -> list[dict[str, Any]]:
    """
    Convert a list of STIX objects to dictionaries and parse them into the specified Pydantic model.

    Args:
        stix_objects (List): The list of STIX objects to parse.
        model (Type[BaseModel]): The Pydantic model class to use for parsing.

    Returns
    -------
        List[Dict[str, Any]]: A list of dictionaries.
    """
    objects_as_dicts = [json.loads(obj.serialize()) if not isinstance(obj, dict) else obj for obj in stix_objects]
    type_adapter = TypeAdapter(list[model])
    parsed_objects = type_adapter.validate_python(objects_as_dicts)
    return [obj.model_dump() for obj in parsed_objects]


def remove_revoked_deprecated(stix_objects: list[Any]) -> list[Any]:
    """
    Remove any revoked or deprecated objects from queries made to the data source.

    References
    ----------
    - https://github.com/mitre/cti/issues/127
    - https://github.com/mitre/cti/blob/master/USAGE.md#removing-revoked-and-deprecated-objects

    Args:
        stix_objects (List): List of STIX objects.

    Returns
    -------
        List: List of STIX objects excluding revoked and deprecated ones.
    """

    def _field(value: Any, key: str, default: Any = False) -> Any:
        if isinstance(value, dict):
            return value.get(key, default)
        getter = getattr(value, "get", None)
        if callable(getter):
            try:
                return getter(key, default)
            except Exception:
                pass
        try:
            return value[key]  # type: ignore[index]
        except Exception:
            return getattr(value, key, default)

    filtered: list[Any] = []
    for obj in stix_objects:
        if _field(obj, "x_mitre_deprecated", False) is True:
            continue
        if _field(obj, "revoked", False) is True:
            continue
        filtered.append(obj)
    return filtered


def extract_revoked(stix_objects: list[Any]) -> list[Any]:
    """
    Extract revoked objects from STIX objects.

    Reference:
    - https://stix2.readthedocs.io/en/latest/api/datastore/stix2.datastore.filters.html

    Args:
        stix_objects (List): List of STIX objects.

    Returns
    -------
        List: List of revoked STIX objects.
    """
    return list(apply_common_filters(stix_objects, [Filter("revoked", "=", True)]))


def extract_deprecated(stix_objects: list[Any]) -> list[Any]:
    """
    Extract deprecated objects from STIX objects.

    Reference:
    - https://stix2.readthedocs.io/en/latest/api/datastore/stix2.datastore.filters.html

    Args:
        stix_objects (List): List of STIX objects.

    Returns
    -------
        List: List of deprecated STIX objects.
    """
    return list(apply_common_filters(stix_objects, [Filter("x_mitre_deprecated", "=", True)]))


CHUNK_SIZE = 500


def chunked_iterable(iterable: Iterable[Any], size: int = CHUNK_SIZE) -> Iterator[list[Any]]:
    """Yield consecutive chunks from an iterable."""
    it = iter(iterable)
    while True:
        chunk = list(islice(it, size))
        if not chunk:
            break
        yield chunk


def query_stix_objects_by_ids(
    data_source: CompositeDataSource,
    stix_type: str,
    ids: Iterable[str],
    chunk_size: int = CHUNK_SIZE,
) -> list[Any]:
    """Batch-query STIX objects by type and id."""
    id_list = [iid for iid in ids if isinstance(iid, str) and iid]
    if not id_list:
        return []

    collected: list[Any] = []
    for chunk in chunked_iterable(id_list, size=chunk_size):
        collected.extend(
            data_source.query(
                [
                    Filter("type", "=", stix_type),
                    Filter("id", "in", list(chunk)),
                ]
            )
        )
    return collected


# STIX JSON loading helpers

def detect_bundle_spec_version(payload: dict[str, Any]) -> str | None:
    """Detect STIX `spec_version` from a bundle/object dict."""
    spec_version = payload.get("spec_version")
    if isinstance(spec_version, str):
        return spec_version
    if payload.get("type") == "bundle" and isinstance(payload.get("objects"), list):
        for obj in payload["objects"]:
            if isinstance(obj, dict):
                inner = obj.get("spec_version")
                if isinstance(inner, str):
                    return inner
    # Some STIX 2.0 content may omit spec_version; stix2 will infer.
    return None


def iter_stix_dicts_from_json(payload: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield STIX object dictionaries from either a bundle or a single object."""
    if payload.get("type") == "bundle" and isinstance(payload.get("objects"), list):
        for obj in payload["objects"]:
            if isinstance(obj, dict):
                yield obj
        return
    yield payload


def parse_stix_dicts_to_objects(
    stix_dicts: Iterable[dict[str, Any]],
    *,
    allow_custom: bool = True,
    version: str | None = None,
) -> list[Any]:
    """Parse STIX dictionaries into python-stix2 objects."""
    parsed: list[Any] = []
    for obj in stix_dicts:
        parsed.append(stix2.parse(obj, allow_custom=allow_custom, version=version))
    return parsed


def load_stix_json_file(path: str | Path, *, allow_custom: bool = True) -> LoadedStix:
    """Load a STIX JSON file (bundle or single object) into STIX objects."""
    file_path = Path(path)
    payload = json.loads(file_path.read_text(encoding="utf-8"))
    spec_version = detect_bundle_spec_version(payload)
    stix_dicts = list(iter_stix_dicts_from_json(payload))
    objects = parse_stix_dicts_to_objects(stix_dicts, allow_custom=allow_custom, version=spec_version)
    return LoadedStix(spec_version=spec_version, objects=objects)


def load_stix_json_files(paths: Sequence[str | Path], *, allow_custom: bool = True) -> LoadedStix:
    """Load multiple STIX JSON files and merge their objects."""
    merged_objects: list[Any] = []
    spec_version: str | None = None
    for p in paths:
        loaded = load_stix_json_file(p, allow_custom=allow_custom)
        merged_objects.extend(loaded.objects)
        spec_version = spec_version or loaded.spec_version
    return LoadedStix(spec_version=spec_version, objects=merged_objects)


def find_json_files(root: str | Path) -> list[Path]:
    """Find JSON files under a directory (recursively)."""
    base = Path(root)
    return sorted([p for p in base.rglob("*.json") if p.is_file()])
