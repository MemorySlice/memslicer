"""Shared region-name vectors (byte-identical copy of MemDiver's fixture).

``tests/data/region_name_vectors.json`` is copied verbatim from MemDiver's
``tests/fixtures/region_name_vectors.json``. Each row pins the memslicer
classification (``memslicer_category``, ``memslicer_region_type``) of one
mapping name; MemDiver asserts its own ``memdiver_category`` column.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from memslicer.acquirer.region_classify import (
    RegionCategory, classify_name, region_type_for_category,
)
from memslicer.msl.constants import RegionType

_VECTORS = Path(__file__).resolve().parent / "data" / "region_name_vectors.json"
_MEMDIVER_COPY = (
    Path(__file__).resolve().parents[2]
    / "MemDiver" / "tests" / "fixtures" / "region_name_vectors.json"
)
_COLUMNS = {"name", "memslicer_category", "memslicer_region_type",
            "memdiver_category", "note"}


def _load_vectors() -> list[dict]:
    return json.loads(_VECTORS.read_text(encoding="utf-8"))


VECTORS = _load_vectors()


def _ids(row: dict) -> str:
    return row["name"] or "<empty>"


class TestVectorFile:
    def test_rows_have_expected_columns(self):
        assert VECTORS
        for row in VECTORS:
            assert set(row) == _COLUMNS

    def test_names_unique(self):
        names = [r["name"] for r in VECTORS]
        assert len(names) == len(set(names))

    def test_byte_identical_to_memdiver_copy(self):
        if not _MEMDIVER_COPY.exists():
            pytest.skip("MemDiver checkout not found next to memslicer")
        assert _VECTORS.read_bytes() == _MEMDIVER_COPY.read_bytes()


@pytest.mark.parametrize("row", VECTORS, ids=_ids)
def test_classify_name_matches_vector(row: dict):
    assert classify_name(row["name"]) is RegionCategory[row["memslicer_category"]]


@pytest.mark.parametrize("row", VECTORS, ids=_ids)
def test_region_type_matches_vector(row: dict):
    category = RegionCategory[row["memslicer_category"]]
    assert region_type_for_category(category) is RegionType[row["memslicer_region_type"]]
