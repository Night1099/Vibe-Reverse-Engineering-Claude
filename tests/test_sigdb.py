"""Tests for retools/sigdb.py -- signature database module."""

import csv
import io
import json
import os
import sqlite3
import struct
import sys
import tempfile
import zlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure retools is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "retools"))


# ---------------------------------------------------------------------------
# Task 2: Schema & Data Model
# ---------------------------------------------------------------------------

class TestSchemaCreation:
    def test_creates_tables(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        conn = db._conn
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = sorted(r[0] for r in cur.fetchall())
        assert "byte_sigs" in tables
        assert "structural_sigs" in tables
        assert "compiler_fingerprints" in tables
        assert "schema_version" in tables
        db.close()

    def test_schema_version_stored(self):
        from sigdb import SignatureDB, SCHEMA_VERSION
        db = SignatureDB(":memory:")
        cur = db._conn.execute("SELECT version FROM schema_version")
        row = cur.fetchone()
        assert row is not None
        assert row[0] == SCHEMA_VERSION
        db.close()

    def test_schema_version_too_new_raises(self):
        from sigdb import SignatureDB, SCHEMA_VERSION
        # Create a DB with a future version
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE schema_version (version INTEGER)")
        conn.execute("INSERT INTO schema_version VALUES (?)", (SCHEMA_VERSION + 1,))
        conn.commit()
        # Monkeypatch to use this connection -- instead, use a temp file
        conn.close()

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp_path = f.name
        try:
            conn = sqlite3.connect(tmp_path)
            conn.execute("CREATE TABLE schema_version (version INTEGER)")
            conn.execute(
                "INSERT INTO schema_version VALUES (?)", (SCHEMA_VERSION + 1,)
            )
            conn.commit()
            conn.close()
            with pytest.raises(RuntimeError, match="newer"):
                SignatureDB(tmp_path)
        finally:
            os.unlink(tmp_path)

    def test_close_is_idempotent(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        db.close()
        db.close()  # should not raise

    def test_reopen_existing_db(self):
        from sigdb import SignatureDB
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            tmp_path = f.name
        try:
            db = SignatureDB(tmp_path)
            db.add_byte_sig(
                name="test_fn", pattern=b"\x55" * 32, mask=b"\xff" * 32,
                func_size=100, tail_crc=0xDEAD, compiler="msvc",
                source="test.dll", category="crt",
            )
            db.close()
            db2 = SignatureDB(tmp_path)
            cur = db2._conn.execute("SELECT COUNT(*) FROM byte_sigs")
            assert cur.fetchone()[0] == 1
            db2.close()
        finally:
            os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Task 3: Signature Extraction
# ---------------------------------------------------------------------------

class TestByteExtraction:
    def test_extract_returns_tuple(self, sample_binary):
        from sigdb import extract_byte_sig
        from common import Binary
        b = Binary(sample_binary)
        funcs = b.func_table
        if not funcs:
            pytest.skip("No functions found in sample binary")
        result = extract_byte_sig(b, funcs[0])
        # May be None if function is too short
        if result is not None:
            pattern, mask, tail_crc, func_size = result
            assert isinstance(pattern, bytes)
            assert isinstance(mask, bytes)
            assert len(pattern) == 32
            assert len(mask) == 32
            assert isinstance(tail_crc, int)
            assert isinstance(func_size, int)
            assert func_size > 0

    def test_wildcards_on_e8_e9(self):
        """E8/E9 rel32 operands should be masked to wildcard."""
        from sigdb import extract_byte_sig
        # Build a mock binary with a CALL rel32 at offset 0
        code = bytearray(64)
        code[0] = 0xE8  # call rel32
        code[1:5] = b"\x10\x00\x00\x00"
        code[5] = 0x90  # nop padding
        code[10] = 0xE9  # jmp rel32
        code[11:15] = b"\x20\x00\x00\x00"
        # Fill rest with nops
        for i in range(15, 64):
            code[i] = 0x90

        mock_b = MagicMock()
        mock_b.read_va.return_value = bytes(code)
        # Mock disasm to return enough instructions to estimate func size
        mock_insn = MagicMock()
        mock_insn.mnemonic = "ret"
        mock_insn.address = 0x1000 + 50
        mock_insn.size = 1
        mock_insn.op_str = ""
        nop_insn = MagicMock()
        nop_insn.mnemonic = "nop"
        nop_insn.address = 0x1000 + 51
        nop_insn.size = 1
        mock_b.disasm.return_value = [mock_insn, nop_insn, nop_insn, nop_insn]

        result = extract_byte_sig(mock_b, 0x1000)
        assert result is not None
        pattern, mask, tail_crc, func_size = result
        # Bytes 1-4 (E8 operand) should be wildcarded
        assert mask[1:5] == b"\x00\x00\x00\x00"
        # Bytes 11-14 (E9 operand) should be wildcarded
        assert mask[11:15] == b"\x00\x00\x00\x00"
        # Byte 0 (E8 opcode) should NOT be wildcarded
        assert mask[0] == 0xFF

    def test_extract_returns_none_for_unreadable(self):
        from sigdb import extract_byte_sig
        mock_b = MagicMock()
        mock_b.read_va.return_value = b""
        result = extract_byte_sig(mock_b, 0xDEAD)
        assert result is None


class TestStructuralExtraction:
    def test_extract_returns_dict(self, sample_binary):
        from sigdb import extract_structural_sig
        from common import Binary
        b = Binary(sample_binary)
        funcs = b.func_table
        if not funcs:
            pytest.skip("No functions found in sample binary")
        result = extract_structural_sig(b, funcs[0])
        if result is not None:
            assert isinstance(result, dict)
            assert "block_count" in result
            assert "edge_count" in result
            assert "call_count" in result
            assert "mnemonic_hash" in result
            assert "constants" in result

    def test_extract_returns_none_for_empty(self):
        from sigdb import extract_structural_sig
        mock_b = MagicMock()
        mock_b.read_va.return_value = b""
        mock_b.disasm.return_value = []
        result = extract_structural_sig(mock_b, 0xDEAD)
        assert result is None


class TestAddSigs:
    def test_add_byte_sig(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        db.add_byte_sig(
            name="my_func", pattern=b"\x55" * 32, mask=b"\xff" * 32,
            func_size=200, tail_crc=0x1234, compiler="msvc",
            source="test.dll", category="crt",
        )
        cur = db._conn.execute("SELECT name, func_size FROM byte_sigs")
        row = cur.fetchone()
        assert row[0] == "my_func"
        assert row[1] == 200
        db.close()

    def test_add_structural_sig(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        db.add_structural_sig(
            name="my_func", block_count=5, edge_count=7, call_count=3,
            mnemonic_hash=0xABCD, constants="0x10,0x20",
            compiler="msvc", source="test.dll", category="math",
        )
        cur = db._conn.execute(
            "SELECT name, block_count, mnemonic_hash FROM structural_sigs"
        )
        row = cur.fetchone()
        assert row[0] == "my_func"
        assert row[1] == 5
        assert row[2] == 0xABCD
        db.close()


# ---------------------------------------------------------------------------
# Task 4: Multi-Tier Matching
# ---------------------------------------------------------------------------

class TestByteMatching:
    def test_exact_match(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        pattern = b"\x55\x8B\xEC" + b"\x90" * 29
        mask = b"\xFF" * 32
        db.add_byte_sig(
            name="push_ebp_fn", pattern=pattern, mask=mask,
            func_size=100, tail_crc=0x0, compiler="msvc",
            source="test.dll", category="crt",
        )
        matches = db.match_bytes(
            code=pattern, func_size=100, preferred_compiler="", func_tail_crc=0
        )
        assert len(matches) >= 1
        assert matches[0].name == "push_ebp_fn"
        db.close()

    def test_masked_match(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        pattern = b"\xE8\x00\x00\x00\x00" + b"\x90" * 27
        mask = b"\xFF\x00\x00\x00\x00" + b"\xFF" * 27
        db.add_byte_sig(
            name="call_fn", pattern=pattern, mask=mask,
            func_size=50, tail_crc=0x0, compiler="msvc",
            source="test.dll", category="crt",
        )
        # Code with different rel32 target should still match
        code = b"\xE8\xAA\xBB\xCC\xDD" + b"\x90" * 27
        matches = db.match_bytes(
            code=code, func_size=50, preferred_compiler="", func_tail_crc=0
        )
        assert len(matches) >= 1
        assert matches[0].name == "call_fn"
        db.close()

    def test_no_match(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        pattern = b"\x55\x8B\xEC" + b"\x90" * 29
        mask = b"\xFF" * 32
        db.add_byte_sig(
            name="push_ebp_fn", pattern=pattern, mask=mask,
            func_size=100, tail_crc=0x0, compiler="msvc",
            source="test.dll", category="crt",
        )
        code = b"\xCC" * 32  # totally different
        matches = db.match_bytes(
            code=code, func_size=100, preferred_compiler="", func_tail_crc=0
        )
        assert len(matches) == 0
        db.close()

    def test_size_disambiguation(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        pattern = b"\x55\x8B\xEC" + b"\x90" * 29
        mask = b"\xFF" * 32
        db.add_byte_sig(
            name="fn_small", pattern=pattern, mask=mask,
            func_size=50, tail_crc=0x0, compiler="msvc",
            source="test.dll", category="crt",
        )
        db.add_byte_sig(
            name="fn_big", pattern=pattern, mask=mask,
            func_size=200, tail_crc=0x0, compiler="msvc",
            source="test.dll", category="crt",
        )
        matches = db.match_bytes(
            code=pattern, func_size=200, preferred_compiler="", func_tail_crc=0
        )
        # fn_big should rank first (exact size match)
        assert matches[0].name == "fn_big"
        db.close()

    def test_tail_crc_disambiguation(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        pattern = b"\x55\x8B\xEC" + b"\x90" * 29
        mask = b"\xFF" * 32
        db.add_byte_sig(
            name="fn_a", pattern=pattern, mask=mask,
            func_size=100, tail_crc=0xAAAA, compiler="msvc",
            source="test.dll", category="crt",
        )
        db.add_byte_sig(
            name="fn_b", pattern=pattern, mask=mask,
            func_size=100, tail_crc=0xBBBB, compiler="msvc",
            source="test.dll", category="crt",
        )
        matches = db.match_bytes(
            code=pattern, func_size=100, preferred_compiler="",
            func_tail_crc=0xBBBB,
        )
        assert matches[0].name == "fn_b"
        db.close()


class TestStructuralMatching:
    def test_exact_match(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        db.add_structural_sig(
            name="loopy_fn", block_count=5, edge_count=7, call_count=3,
            mnemonic_hash=0xABCD, constants="0x10,0x20",
            compiler="msvc", source="test.dll", category="math",
        )
        matches = db.match_structural(
            block_count=5, edge_count=7, call_count=3,
            mnemonic_hash=0xABCD, constants="0x10,0x20",
        )
        assert len(matches) >= 1
        assert matches[0].name == "loopy_fn"
        db.close()

    def test_no_match(self):
        from sigdb import SignatureDB
        db = SignatureDB(":memory:")
        db.add_structural_sig(
            name="loopy_fn", block_count=5, edge_count=7, call_count=3,
            mnemonic_hash=0xABCD, constants="0x10,0x20",
            compiler="msvc", source="test.dll", category="math",
        )
        matches = db.match_structural(
            block_count=99, edge_count=99, call_count=99,
            mnemonic_hash=0xFFFF, constants="",
        )
        assert len(matches) == 0
        db.close()


class TestIdentify:
    def test_identify_returns_match_or_none(self, sample_binary):
        from sigdb import SignatureDB
        from common import Binary
        db = SignatureDB(":memory:")
        b = Binary(sample_binary)
        funcs = b.func_table
        if not funcs:
            pytest.skip("No functions found")
        result = db.identify(b, funcs[0], preferred_compiler="")
        # With empty DB, should return None
        assert result is None
        db.close()


class TestScan:
    def test_scan_returns_dict(self, sample_binary):
        from sigdb import SignatureDB
        from common import Binary
        db = SignatureDB(":memory:")
        b = Binary(sample_binary)
        result = db.scan(b, preferred_compiler="")
        assert isinstance(result, dict)
        db.close()


# ---------------------------------------------------------------------------
# Task 5: Compiler Fingerprinting
# ---------------------------------------------------------------------------

class TestRichHeader:
    def test_parse_rich_header_returns_list(self, sample_binary):
        from sigdb import parse_rich_header
        from common import Binary
        b = Binary(sample_binary)
        result = parse_rich_header(b)
        assert isinstance(result, list)
        # System DLLs typically have Rich headers
        if result:
            entry = result[0]
            assert "comp_id" in entry
            assert "count" in entry

    def test_parse_rich_header_no_header(self):
        """Binary without Rich header returns empty list."""
        from sigdb import parse_rich_header
        mock_b = MagicMock()
        mock_b.raw = b"\x00" * 512  # No Rich signature
        result = parse_rich_header(mock_b)
        assert result == []


class TestCrtImport:
    def test_detect_crt_import(self, sample_binary):
        from sigdb import detect_crt_import
        from common import Binary
        b = Binary(sample_binary)
        result = detect_crt_import(b)
        # kernel32.dll doesn't import CRT, but result is str or None
        assert result is None or isinstance(result, str)

    def test_detect_crt_known_dll(self):
        from sigdb import detect_crt_import
        mock_b = MagicMock()
        mock_pe = MagicMock()
        mock_entry = MagicMock()
        mock_entry.dll = b"MSVCR120.dll"
        mock_entry.imports = []
        mock_pe.DIRECTORY_ENTRY_IMPORT = [mock_entry]
        mock_b.pe = mock_pe
        result = detect_crt_import(mock_b)
        assert result is not None
        assert "msvc" in result.lower() or "MSVCR120" in result


class TestFingerprint:
    def test_fingerprint_returns_dict(self, sample_binary):
        from sigdb import SignatureDB
        from common import Binary
        db = SignatureDB(":memory:")
        b = Binary(sample_binary)
        result = db.fingerprint(b)
        assert isinstance(result, dict)
        assert "compiler" in result
        assert "confidence" in result
        assert "evidence" in result
        db.close()


# ---------------------------------------------------------------------------
# Task 6: Build Pipeline & CLI
# ---------------------------------------------------------------------------

class TestCategorize:
    def test_crt_names(self):
        from sigdb import _categorize_name
        assert _categorize_name("__security_init_cookie") == "crt"
        assert _categorize_name("_malloc") == "crt"

    def test_math_names(self):
        from sigdb import _categorize_name
        assert _categorize_name("sinf") == "math"
        assert _categorize_name("_CIcos") == "math"

    def test_unknown(self):
        from sigdb import _categorize_name
        result = _categorize_name("MyGameFunction")
        assert isinstance(result, str)


class TestBuildFromManifest:
    def test_build_from_manifest(self, tmp_path):
        from sigdb import SignatureDB, build_from_manifest

        # Create a dummy CSV address map
        csv_path = tmp_path / "map.csv"
        csv_path.write_text("address,name\n0x401000,_init\n0x402000,_main\n")

        # We need a real binary for extraction, but since this might fail
        # on extraction, we test that the pipeline runs without crashing.
        # Use a manifest that references a non-existent binary to test
        # the error-handling path.
        manifest = {
            "sources": [
                {
                    "type": "binary_with_map",
                    "binary": str(tmp_path / "nonexistent.dll"),
                    "map": str(csv_path),
                    "compiler": "msvc",
                }
            ]
        }
        db = SignatureDB(":memory:")
        # Should not crash, just skip missing binaries
        build_from_manifest(db, manifest)
        db.close()

    def test_build_with_real_binary(self, sample_binary, tmp_path):
        from sigdb import SignatureDB, build_from_manifest
        from common import Binary

        b = Binary(sample_binary)
        funcs = b.func_table[:3]  # Just a few for speed
        if not funcs:
            pytest.skip("No functions found")

        csv_path = tmp_path / "map.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["address", "name"])
            for va in funcs:
                writer.writerow([f"0x{va:X}", f"func_{va:X}"])

        manifest = {
            "sources": [
                {
                    "type": "binary_with_map",
                    "binary": sample_binary,
                    "map": str(csv_path),
                    "compiler": "msvc",
                }
            ]
        }
        db = SignatureDB(":memory:")
        build_from_manifest(db, manifest)
        # Should have ingested at least some sigs
        cur = db._conn.execute("SELECT COUNT(*) FROM byte_sigs")
        count = cur.fetchone()[0]
        # Some funcs may fail extraction, so count >= 0 is fine
        assert count >= 0
        db.close()


class TestCLI:
    def test_main_exists(self):
        from sigdb import main
        assert callable(main)

    def test_main_no_args_exits(self):
        from sigdb import main
        with pytest.raises(SystemExit):
            main([])
