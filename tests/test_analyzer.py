"""Synthetic metadata regressions and forbidden-capability checks."""

from contextlib import ExitStack
import json
import struct
from unittest import TestCase
from unittest.mock import patch
import warnings

from archive_lab import analyze, serialize_report
from archive_lab.analyzer import MAX_INPUT_BYTES, MAX_OUTPUT_BYTES
from archive_lab.fixtures import demo_cases, make_zip, patch_central, unicode_override


class AnalyzerTests(TestCase):
    def findings(self, report):
        return set().union(*(set(entry["findings"]) for entry in report["entries"]))

    def test_ordinary_and_empty_zip(self):
        for raw, count in ((make_zip(), 1), (make_zip(()), 0)):
            report = analyze(raw)
            self.assertEqual(report["status"], "complete_metadata")
            self.assertTrue(report["metadata_complete"])
            self.assertEqual(report["entry_count"], count)
            self.assertFalse(self.findings(report))
            self.assertIn("extraction_safety", report["not_verified"])
            self.assertNotIn("safe_to_extract", report)

    def test_input_limit_precedes_parser_construction(self):
        with patch("archive_lab.analyzer.zipfile.ZipFile", side_effect=AssertionError("parser called")):
            for raw in (b"x" * (MAX_INPUT_BYTES + 1), b"x" * 100_000):
                report = analyze(raw)
                self.assertEqual(report["status"], "over_limit")
                self.assertEqual(report["reason"], "input_limit")
            self.assertEqual(analyze("not bytes")["reason"], "invalid_input_type")

    def test_entry_count_is_postparse_and_never_prefix_success(self):
        report = analyze(make_zip(tuple(f"f{i}" for i in range(17))))
        self.assertEqual(report["status"], "over_limit")
        self.assertEqual(report["entry_count"], 17)
        self.assertFalse(report["metadata_complete"])
        self.assertEqual(report["entries"], [])
        self.assertEqual(analyze(make_zip(tuple(f"f{i}" for i in range(16))))["entry_count"], 16)

    def test_paths_and_reserved_names(self):
        cases = [("../x", "relative_path_component"), ("a/./b", "relative_path_component"),
                 ("/absolute", "absolute_or_unc_name"), ("\\\\server\\share", "absolute_or_unc_name"),
                 ("C:relative", "drive_name"),
                 ("note:stream", "windows_special_character"), ("NUL.txt", "windows_reserved_name"),
                 ("COM¹.txt", "windows_reserved_name"), ("folder/aux", "windows_reserved_name"),
                 ("note. ", "trailing_dot_or_space"), ("a//b", "empty_path_component"),
                 ("note\n.txt", "control_or_format_character"), ("a\u202eb", "control_or_format_character")]
        for name, reason in cases:
            with self.subTest(name=name):
                self.assertIn(reason, self.findings(analyze(make_zip((name,)))))
        # Windows ZipInfo sanitizes backslashes when writing; patch the inert
        # central-directory name so the reader actually receives the test input.
        raw = patch_central(make_zip(("a_b",)), name=b"a\\b")
        self.assertIn("backslash_ambiguity", self.findings(analyze(raw)))

    def test_nul_original_not_hidden_by_effective_filename(self):
        report = analyze(patch_central(make_zip(("base.txt",)), name=b"ba\x00e.txt"))
        entry = report["entries"][0]
        self.assertEqual(entry["original_name"]["text"], "ba\x00e.txt")
        self.assertEqual(entry["effective_name"]["text"], "ba")
        self.assertIn("control_or_format_character", entry["findings"])
        self.assertIn("parser_changed_name", entry["findings"])
        encoded = serialize_report(report)
        self.assertNotIn(b"\x00", encoded)
        self.assertIn(b"\\u0000", encoded)

    def test_aliases_mark_both_entries(self):
        for names in (("Notes.txt", "notes.txt"), ("café.txt", "cafe\u0301.txt"),
                      ("note", "note.")):
            with self.subTest(names=names):
                entries = analyze(make_zip(names))["entries"]
                self.assertTrue(all("name_collision" in entry["findings"] for entry in entries))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            self.assertIn("name_collision", self.findings(analyze(make_zip(("same", "same")))))

    def test_unicode_extra_rejected_and_both_names_inspected(self):
        report = analyze(unicode_override())
        self.assertEqual(report["status"], "unsupported")
        self.assertFalse(report["metadata_complete"])
        self.assertEqual(report["entries"][0]["original_name"]["text"], "base.txt")
        self.assertEqual(report["entries"][0]["effective_name"]["text"], "../outside.txt")
        self.assertIn("unsupported_extra", self.findings(report))
        self.assertIn("relative_path_component", self.findings(report))

    def test_unknown_extra_and_zip64_shape(self):
        for extra in (struct.pack("<HH", 0x1234, 0), struct.pack("<HHI", 1, 4, 0)):
            report = analyze(make_zip(extra=extra))
            self.assertEqual(report["status"], "unsupported")
            self.assertFalse(report["metadata_complete"])

    def test_wellformed_zip64_decoded_by_stdlib(self):
        extra = struct.pack("<HHQ", 1, 8, 2**40)
        report = analyze(patch_central(make_zip(extra=extra), size=0xFFFFFFFF))
        self.assertEqual(report["status"], "complete_metadata")
        self.assertEqual(report["entries"][0]["declared_size"], 2**40)
        self.assertIn("declared_entry_size_limit", self.findings(report))
        self.assertIn("declared_ratio_limit", self.findings(report))

    def test_malformed_extras_and_encoding(self):
        extras = [b"\x01", struct.pack("<HH", 1, 20) + b"x", struct.pack("<HHQHHQ", 1, 8, 1, 1, 8, 1)]
        for extra in extras:
            with self.subTest(extra=extra):
                self.assertEqual(analyze(make_zip(extra=extra))["status"], "malformed")
        raw = patch_central(make_zip(("base.txt",)), name=b"\xffase.txt", flags=1 << 11)
        self.assertEqual(analyze(raw)["status"], "malformed")

    def test_declared_limits_and_zero_ratio_denominator(self):
        for size, compressed, reason in [(262_145, 10, "declared_entry_size_limit"),
                                         (1, 0, "declared_ratio_limit"),
                                         (1, 65_536, "declared_compressed_size_exceeds_input")]:
            report = analyze(patch_central(make_zip(), size=size, compressed=compressed))
            self.assertIn(reason, self.findings(report))
        self.assertNotIn("declared_ratio_limit", self.findings(analyze(patch_central(make_zip(), size=0, compressed=0))))
        self.assertIn("declared_total_size_limit", self.findings(analyze(patch_central(make_zip(), size=1_048_577))))

    def test_unsupported_flags_compression_multidisk_and_symlink(self):
        for raw in (patch_central(make_zip(), flags=1), patch_central(make_zip(), flags=1 << 6),
                    patch_central(make_zip(), method=99), patch_central(make_zip(), volume=1)):
            self.assertEqual(analyze(raw)["status"], "unsupported")
        self.assertIn("symlink_attribute", self.findings(analyze(make_zip(symlink=True))))

    def test_no_member_access_decompression_or_file_open(self):
        # Construct inert fixtures before prohibiting member open, which ZipFile
        # itself legitimately uses while WRITING fixtures into memory.
        cases = demo_cases() + [("declared large", patch_central(make_zip(), size=2**31), "complete_metadata")]
        with ExitStack() as stack:
            for target in ("zipfile.ZipFile.open", "zipfile.ZipFile.read", "zipfile.ZipFile.extract",
                           "zipfile.ZipFile.extractall", "zipfile.ZipFile.testzip",
                           "zipfile._get_decompressor", "zlib.decompress", "zlib.decompressobj", "builtins.open"):
                stack.enter_context(patch(target, side_effect=AssertionError("forbidden capability")))
            for name, raw, expected in cases:
                with self.subTest(case=name):
                    self.assertEqual(analyze(raw)["status"], expected)

    def test_malformed_inputs_and_unsupported_version(self):
        for raw in (b"", b"PK", b"inert", make_zip()[:-20]):
            self.assertEqual(analyze(raw)["status"], "malformed")
        with patch("archive_lab.analyzer.zipfile.ZipFile", side_effect=NotImplementedError("inert")):
            self.assertEqual(analyze(b"inert")["status"], "unsupported")

    def test_preview_truncation_does_not_hide_risk(self):
        name = "a" * 300 + "/../outside"
        report = analyze(make_zip((name,)))
        self.assertTrue(report["entries"][0]["original_name"]["truncated"])
        self.assertLessEqual(len(report["entries"][0]["original_name"]["text"]), 128)
        self.assertIn("relative_path_component", self.findings(report))

    def test_output_cap_and_determinism(self):
        for _, raw, _ in demo_cases():
            encoded = serialize_report(analyze(raw))
            self.assertLessEqual(len(encoded), MAX_OUTPUT_BYTES)
            self.assertEqual(encoded, serialize_report(analyze(raw)))
        fallback = json.loads(serialize_report({"synthetic_test": "x" * MAX_OUTPUT_BYTES}))
        self.assertEqual(fallback["status"], "over_limit")
        self.assertFalse(fallback["metadata_complete"])
