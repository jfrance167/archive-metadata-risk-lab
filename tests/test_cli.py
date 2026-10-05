"""Exercise exit statuses and bounded I/O with inert in-memory streams."""

from io import BytesIO, StringIO
import json
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from archive_lab.__main__ import main
from archive_lab.analyzer import MAX_INPUT_BYTES
from archive_lab.fixtures import make_zip


class CliTests(TestCase):
    def invoke(self, raw=b"", command="analyze", output=None, input_stream=None):
        output = BytesIO() if output is None else output
        errors = StringIO()
        with patch("sys.argv", ["archive_lab", command]), \
             patch("sys.stdin", SimpleNamespace(buffer=input_stream or BytesIO(raw))), \
             patch("sys.stdout", SimpleNamespace(buffer=output)), patch("sys.stderr", errors):
            code = main()
        return code, output, errors.getvalue()

    def test_exit_outcomes(self):
        for raw, expected in ((make_zip(), 0), (make_zip(("../outside",)), 1),
                              (b"invalid", 2), (b"x" * (MAX_INPUT_BYTES + 1), 2)):
            with self.subTest(expected=expected):
                code, output, errors = self.invoke(raw)
                self.assertEqual(code, expected)
                self.assertIsInstance(json.loads(output.getvalue()), dict)
                self.assertFalse(errors)

    def test_demo(self):
        code, output, _ = self.invoke(command="demo")
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(output.getvalue())["passed"])

    def test_input_read_is_bounded(self):
        class Reader:
            def read(self, size):
                self.requested = size
                return b"x" * size
        stream = Reader()
        self.assertEqual(self.invoke(input_stream=stream)[0], 2)
        self.assertEqual(stream.requested, MAX_INPUT_BYTES + 1)

    def test_failed_read_write_flush_and_short_write(self):
        class FailedRead:
            def read(self, size):
                raise OSError("inert")
        class FailedWrite(BytesIO):
            def write(self, data):
                raise BrokenPipeError("inert")
        class FailedFlush(BytesIO):
            def flush(self):
                raise OSError("inert")
        class ShortWrite(BytesIO):
            def write(self, data):
                return 0
        self.assertEqual(self.invoke(input_stream=FailedRead())[0], 3)
        for output in (FailedWrite(), FailedFlush(), ShortWrite()):
            code, _, errors = self.invoke(make_zip(), output=output)
            self.assertEqual(code, 3)
            self.assertEqual(json.loads(errors), {"error": "input_or_output_failure"})

    def test_output_limit_is_incomplete_exit_even_in_demo(self):
        payload = b'{"status":"over_limit","metadata_complete":false}\n'
        with patch("archive_lab.__main__.serialize_report", return_value=payload):
            self.assertEqual(self.invoke(make_zip())[0], 2)
            self.assertEqual(self.invoke(command="demo")[0], 2)
