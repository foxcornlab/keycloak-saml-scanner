#!/usr/bin/env python3
"""Tests for keycloak_saml_scanner.py. Run: python3 -m unittest discover -s tests -v"""

import io
import json
import os
import sys
import tempfile
import threading
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import keycloak_saml_scanner as kss


def grade_only(version):
    parsed, kind, _ = kss.parse_version(version)
    return kss.grade(parsed, kind)


class TestParseVersion(unittest.TestCase):
    def test_plain_release(self):
        v, kind, _ = kss.parse_version("26.8.1")
        self.assertEqual((v, kind), ((26, 8, 1), "release"))

    def test_kc_sh_output(self):
        v, kind, _ = kss.parse_version("Keycloak 26.8.1 (WildFly Core 21.0.0.Final)")
        self.assertEqual((v, kind), ((26, 8, 1), "release"))

    def test_rhbk(self):
        v, kind, _ = kss.parse_version("26.4.2.redhat-00001")
        self.assertEqual((v, kind), ((26, 4, 2), "rhbk"))

    def test_snapshot(self):
        v, kind, _ = kss.parse_version("26.9.0-SNAPSHOT")
        self.assertEqual((v, kind), ((26, 9, 0), "snapshot"))

    def test_snapshot_resources_version(self):
        # What the welcome page prints for a snapshot build.
        v, kind, _ = kss.parse_version("26.9.0-20261106120000")
        self.assertEqual((v, kind), ((26, 9, 0), "snapshot"))

    def test_version_properties(self):
        v, kind, _ = kss.parse_version("version=26.8.2")
        self.assertEqual((v, kind), ((26, 8, 2), "release"))

    def test_old_final_suffix(self):
        v, kind, _ = kss.parse_version("1.6.1.Final")
        self.assertEqual((v, kind), ((1, 6, 1), "release"))

    def test_unparseable(self):
        v, kind, note = kss.parse_version("no-version-here")
        self.assertIsNone(v)
        self.assertIsNone(kind)
        self.assertIn("no x.y.z", note)

    def test_empty(self):
        v, kind, _ = kss.parse_version("")
        self.assertIsNone(v)


class TestGrade(unittest.TestCase):
    def test_patched_release(self):
        self.assertEqual(grade_only("26.8.2")[0], "PATCHED")

    def test_patched_newer_minor(self):
        self.assertEqual(grade_only("26.9.0")[0], "PATCHED")

    def test_vulnerable_2681(self):
        verdict, detail = grade_only("26.8.1")
        self.assertEqual(verdict, "VULNERABLE")
        self.assertIn("26.8.2", detail)

    def test_vulnerable_2680_notes_semicolon_variant(self):
        verdict, detail = grade_only("26.8.0")
        self.assertEqual(verdict, "VULNERABLE")
        self.assertIn(";", detail)

    def test_vulnerable_267(self):
        self.assertEqual(grade_only("26.7.5")[0], "VULNERABLE")

    def test_vulnerable_2669_backport_trap(self):
        verdict, detail = grade_only("26.6.9")
        self.assertEqual(verdict, "VULNERABLE")
        self.assertIn("26.6.9", detail)

    def test_vulnerable_26418_backport_trap(self):
        verdict, detail = grade_only("26.4.18")
        self.assertEqual(verdict, "VULNERABLE")
        self.assertIn("26.4.18", detail)

    def test_unknown_265(self):
        verdict, detail = grade_only("26.5.0")
        self.assertEqual(verdict, "UNKNOWN")
        self.assertIn("no affected-version data", detail)

    def test_unknown_older_lines(self):
        for v in ("26.3.5", "25.0.6", "24.0.11", "22.0.5"):
            self.assertEqual(grade_only(v)[0], "UNKNOWN", v)

    def test_snapshot_unknown(self):
        verdict, detail = grade_only("26.9.0-SNAPSHOT")
        self.assertEqual(verdict, "UNKNOWN")
        self.assertIn("build date", detail)

    def test_rhbk_graded_on_base_version(self):
        self.assertEqual(grade_only("26.4.2.redhat-00001")[0], "VULNERABLE")
        self.assertEqual(grade_only("26.8.2.redhat-00001")[0], "PATCHED")


class TestSamlUsage(unittest.TestCase):
    def test_no_saml_makes_not_exposed(self):
        result = kss.scan_version("26.8.1", "t", "no")
        self.assertEqual(result["verdict"], "NOT-EXPOSED")
        self.assertIn("not reachable", result["detail"])

    def test_no_saml_keeps_patched(self):
        result = kss.scan_version("26.8.2", "t", "no")
        self.assertEqual(result["verdict"], "PATCHED")

    def test_unknown_saml_adds_caveat(self):
        result = kss.scan_version("26.8.1", "t", "unknown")
        self.assertEqual(result["verdict"], "VULNERABLE")
        self.assertIn("OIDC-only", result["detail"])

    def test_yes_saml_vulnerable(self):
        result = kss.scan_version("26.6.9", "t", "yes")
        self.assertEqual(result["verdict"], "VULNERABLE")


class TestHtmlExtraction(unittest.TestCase):
    def test_welcome_page(self):
        html = ('<link href="resources/26.8.1/welcome/keycloak/css/welcome.css">')
        self.assertEqual(kss.extract_version_from_html(html), "26.8.1")

    def test_login_page(self):
        html = ('<link rel="stylesheet" href="/resources/26.8.2/login/keycloak'
                '/css/login.css">')
        self.assertEqual(kss.extract_version_from_html(html), "26.8.2")

    def test_snapshot_resources(self):
        html = '<script src="resources/26.9.0-20261106120000/common/keycloak/js/keycloak.js">'
        self.assertEqual(kss.extract_version_from_html(html),
                         "26.9.0-20261106120000")

    def test_no_version(self):
        self.assertIsNone(kss.extract_version_from_html("<html>hello</html>"))


WELCOME_VULN = """<html><head><link href="resources/26.8.1/welcome/keycloak/css/welcome.css"></head>
<body>Keycloak</body></html>"""
LOGIN_PATCHED = """<html><head><link href="/resources/26.8.2/login/keycloak/css/login.css"></head>
<body>login</body></html>"""
DISCOVERY = {"issuer": "https://id.example.com/realms/master"}


def make_handler(pages):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body, code, ctype = pages.get(self.path.split("?")[0],
                                          ("not found", 404, "text/plain"))
            data = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
    return Handler


class MockServer:
    def __init__(self, pages):
        self.server = HTTPServer(("127.0.0.1", 0), make_handler(pages))
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)

    def __enter__(self):
        self.thread.start()
        return "http://127.0.0.1:%d" % self.server.server_address[1]

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


class TestProbeUrl(unittest.TestCase):
    def test_vulnerable_welcome_page(self):
        pages = {
            "/": (WELCOME_VULN, 200, "text/html"),
            "/realms/master/.well-known/openid-configuration":
                (json.dumps(DISCOVERY), 200, "application/json"),
        }
        with MockServer(pages) as base:
            raw, method, warnings, confirmed = kss.probe_url(base)
        self.assertEqual(raw, "26.8.1")
        self.assertIn("welcome page", method)
        self.assertTrue(confirmed)

    def test_patched_login_page(self):
        pages = {
            "/": ("<html>no version here</html>", 200, "text/html"),
            "/realms/master/protocol/openid-connect/auth":
                (LOGIN_PATCHED, 200, "text/html"),
            "/realms/master/.well-known/openid-configuration":
                (json.dumps(DISCOVERY), 200, "application/json"),
        }
        with MockServer(pages) as base:
            raw, method, _, _ = kss.probe_url(base)
        self.assertEqual(raw, "26.8.2")
        self.assertIn("login page", method)

    def test_no_version_anywhere(self):
        pages = {
            "/": ("<html>custom theme, no version</html>", 200, "text/html"),
            "/realms/master/protocol/openid-connect/auth":
                ("<html>custom login</html>", 200, "text/html"),
            "/realms/master/.well-known/openid-configuration":
                (json.dumps(DISCOVERY), 200, "application/json"),
        }
        with MockServer(pages) as base:
            with self.assertRaises(ValueError):
                kss.probe_url(base)

    def test_cli_url_exit_codes(self):
        pages = {
            "/": (WELCOME_VULN, 200, "text/html"),
            "/realms/master/.well-known/openid-configuration":
                (json.dumps(DISCOVERY), 200, "application/json"),
        }
        with MockServer(pages) as base:
            self.assertEqual(kss.main(["--url", base]), 2)
        pages["/"] = (LOGIN_PATCHED.replace("login", "welcome"), 200, "text/html")
        with MockServer(pages) as base:
            self.assertEqual(kss.main(["--url", base]), 0)


class TestDetectLocal(unittest.TestCase):
    def _install(self, files):
        tmp = tempfile.mkdtemp()
        for rel, content in files.items():
            p = Path(tmp) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                p.write_bytes(content)
            else:
                p.write_text(content)
                if rel.endswith("kc.sh"):
                    p.chmod(0o755)
        return tmp

    def test_kc_sh_version(self):
        root = self._install({
            "bin/kc.sh": "#!/bin/sh\necho 'Keycloak 26.8.1'\n",
        })
        raw, method, _ = kss.detect_local(root)
        self.assertEqual(raw, "26.8.1")
        self.assertIn("kc.sh", method)

    def test_jar_properties(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("keycloak-version.properties",
                        "version=26.8.1\nbuild-time=2026-10-13 10:00:00\n")
        root = self._install({
            "lib/lib/main/org.keycloak.keycloak-common-26.8.1.jar": buf.getvalue(),
        })
        raw, method, _ = kss.detect_local(root)
        self.assertEqual(raw, "26.8.1")
        self.assertIn("keycloak-version.properties", method)

    def test_jar_filename_fallback(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        root = self._install({
            "lib/lib/main/org.keycloak.keycloak-services-26.6.9.jar": buf.getvalue(),
        })
        raw, _, _ = kss.detect_local(root)
        self.assertEqual(raw, "26.6.9")

    def test_directory_name(self):
        tmp = tempfile.mkdtemp()
        root = os.path.join(tmp, "keycloak-26.8.2")
        os.makedirs(root)
        raw, method, _ = kss.detect_local(root)
        self.assertEqual(raw, "26.8.2")
        self.assertIn("directory name", method)

    def test_disagreement_is_unknown(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("keycloak-version.properties", "version=26.8.1\n")
        root = self._install({
            "lib/lib/main/org.keycloak.keycloak-common-26.8.1.jar": buf.getvalue(),
            "bin/kc.sh": "#!/bin/sh\necho 'Keycloak 26.8.2'\n",
        })
        with self.assertRaises(ValueError) as ctx:
            kss.detect_local(root)
        self.assertIn("disagree", str(ctx.exception))

    def test_nothing_found(self):
        root = tempfile.mkdtemp()
        with self.assertRaises(ValueError):
            kss.detect_local(root)


class TestCli(unittest.TestCase):
    def test_version_vulnerable_exit_2(self):
        self.assertEqual(kss.main(["--version", "26.8.1"]), 2)

    def test_version_patched_exit_0(self):
        self.assertEqual(kss.main(["--version", "26.8.2"]), 0)

    def test_version_unknown_exit_0(self):
        self.assertEqual(kss.main(["--version", "25.0.6"]), 0)

    def test_version_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt",
                                         delete=False) as fh:
            fh.write("26.6.9\n")
            name = fh.name
        try:
            self.assertEqual(kss.main(["--version-file", name]), 2)
        finally:
            os.unlink(name)

    def test_version_file_properties(self):
        with tempfile.NamedTemporaryFile("w", suffix=".properties",
                                         delete=False) as fh:
            fh.write("version=26.8.2\nbuild-time=2026-11-05\n")
            name = fh.name
        try:
            self.assertEqual(kss.main(["--version-file", name]), 0)
        finally:
            os.unlink(name)

    def test_json_output(self):
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            code = kss.main(["--version", "26.8.1", "--json"])
        self.assertEqual(code, 2)
        doc = json.loads(out.getvalue())
        self.assertEqual(doc[0]["verdict"], "VULNERABLE")

    def test_inventory_json(self):
        entries = [
            {"label": "prod", "version": "26.8.1"},
            {"label": "staging", "version": "26.8.2"},
            {"label": "legacy", "version": "24.0.11"},
            {"label": "no-saml", "version": "26.8.1", "saml": "no"},
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as fh:
            json.dump(entries, fh)
            name = fh.name
        try:
            with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
                code = kss.main(["--inventory-json", name])
            self.assertEqual(code, 2)
            text = out.getvalue()
            self.assertIn("VULNERABLE", text)
            self.assertIn("NOT-EXPOSED", text)
            self.assertIn("UNKNOWN", text)
        finally:
            os.unlink(name)

    def test_list(self):
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            code = kss.main(["--list"])
        self.assertEqual(code, 0)
        self.assertIn("CVE-2026-117691", out.getvalue())

    def test_no_args_errors(self):
        with mock.patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(kss.main([]), 1)


if __name__ == "__main__":
    unittest.main()
