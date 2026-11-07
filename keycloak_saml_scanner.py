#!/usr/bin/env python3
"""Detection-only local triage for CVE-2026-117691 in Keycloak.

The flaw is a signature bypass in Keycloak's SAML HTTP-Redirect binding
(CWE-347, CVSS 9.1, AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N). Keycloak
processes percent-encoded query parameter names (``%53AMLResponse``) while
its signature verification only checks literal parameter names. An
unauthenticated attacker supplies a crafted, unsigned SAML message and the
server acts on it instead of the legitimately signed one, so a federated
user's account can be taken over: the attacker logs in as any user and
gets their roles and data. The unsigned parameter has to be placed before
the legitimately signed one in the request. Only realms that use SAML are
exposed: identity-provider brokering or a SAML client over the
HTTP-Redirect binding. OIDC-only realms are not.

The fix is Keycloak 26.8.2, released 5 November 2026. It is the only
release carrying the fix. The 26.6 and 26.4 backports tagged afterwards
(26.6.8/26.6.9 and 26.4.17/26.4.18) do not include it, and 26.7 is end
of life with no fix. This is the second bypass in the same code path in
two releases: 26.8.1 fixed the variant that abused ``;`` as a parameter
separator, so 26.8.0 carries both. The GitHub advisory carries no
affected-version data, so versions below 26.4 are graded UNKNOWN, not
clean: the flaw may or may not be present in those lines, and no fix
exists for them either way. Upgrade to 26.8.2.

Red Hat Build of Keycloak is affected too (Red Hat rates it Important,
same 9.1 vector, reported by Mayssen Aidoudi of Think-it GmbH). Red Hat
had no fixed RHBK build and no usable mitigation as of 6 November 2026.
RHBK version strings (``26.4.2.redhat-00001``) are graded on their
upstream base version and flagged as RHBK.

This tool sends no payloads, no crafted SAML, and no exploit traffic.
The only network it ever touches is a plain unauthenticated GET of public
pages (the welcome page, the realm login page) when you pass --url, to
read the version Keycloak itself prints in its theme resource URLs. It
never logs in, never submits a form, never sends a SAML message. A
VULNERABLE grade means the version is below the fixed release; it does
not mean the server was compromised, and a PATCHED grade does not prove
the server was never attacked. If compromise is suspected, preserve
evidence and rotate credentials before upgrading, because an upgrade
alone does not undo stolen sessions or planted backdoors.

Usage:
    python3 keycloak_saml_scanner.py --version 26.8.1
    python3 keycloak_saml_scanner.py --version 26.8.2
    python3 keycloak_saml_scanner.py --version-file version.txt
    python3 keycloak_saml_scanner.py --local /opt/keycloak
    python3 keycloak_saml_scanner.py --url https://id.example.com
    python3 keycloak_saml_scanner.py --inventory-json keycloak.json
    python3 keycloak_saml_scanner.py --list

Exit codes: 0 = nothing vulnerable found, 2 = vulnerable finding,
1 = scan error (missing argument, bad input, no version found).
UNKNOWN does not change the exit code, but it is not clean: an
unparseable, snapshot, or unmapped version has not been cleared, it has
simply not been graded.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

CVE_ID = "CVE-2026-117691"
# Fixed release, per the Keycloak 26.8.2 release notes of 5 November 2026.
# The advisory (GHSA-c85j-3hq2-q6wj) carries no affected-version data.
FIXED = (26, 8, 2)
FIXED_STR = "26.8.2"

# Lines with a positive statement that no fix exists for them. 26.6.9 and
# 26.4.18 are the newest backports and both lack the fix (phasetwo,
# 6 November 2026). 26.7 is end of life with no fix at all.
VULNERABLE_LINES = (
    ((26, 8, 0), (26, 8, 2), "26.8.0/26.8.1: fix only in 26.8.2"),
    ((26, 7, 0), (26, 8, 0), "26.7.x: end of life, no fix released"),
    ((26, 6, 0), (26, 7, 0), "26.6.x: backports 26.6.8/26.6.9 lack the fix"),
    ((26, 4, 0), (26, 5, 0), "26.4.x: backports 26.4.17/26.4.18 lack the fix"),
)

VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
# Keycloak puts its own version in theme resource URLs, e.g.
# resources/26.8.1/login/keycloak/css/login.css (WelcomeResource.java
# builds resourcesPath as "resources/" + Version.RESOURCES_VERSION, and
# Version.RESOURCES_VERSION is the version lowercased, snapshots with the
# build time appended). The welcome page and the login page both carry it.
RESOURCES_RE = re.compile(r"resources/(\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?)/")


def parse_version(raw):
    """Parse a Keycloak version string.

    Returns (tuple, kind, note) where kind is one of "release", "rhbk",
    "snapshot", "line" (bare major.minor, no patch level), or None when
    nothing parseable is found. RHBK strings like 26.4.2.redhat-00001
    are graded on their upstream base version.
    """
    if raw is None:
        return None, None, "no version string supplied"
    text = str(raw).strip()
    if not text:
        return None, None, "empty version string"
    match = VERSION_RE.search(text)
    if not match:
        return None, None, "no x.y.z version in %r" % text
    version = tuple(int(match.group(i)) for i in (1, 2, 3))
    rest = text[match.end():]
    if "redhat" in text.lower():
        return version, "rhbk", "Red Hat Build of Keycloak build"
    if "-snapshot" in text.lower() or re.search(r"-\d{8,}", rest):
        return version, "snapshot", "snapshot build, fix presence depends on build date"
    if rest and rest[0] not in (".", "-", "_"):
        return version, "release", ""
    if rest.startswith(".") and not rest[1:2].isdigit() and "redhat" not in rest.lower():
        # e.g. 26.8.1.Final (WildFly-era suffix): still the same release.
        return version, "release", ""
    return version, "release", ""


def grade(version, kind):
    """Grade a parsed version against the 26.8.2 fix.

    Returns (verdict, detail). Verdict is PATCHED, VULNERABLE, or UNKNOWN.
    """
    if version is None:
        return "UNKNOWN", "no version to grade"
    if kind == "snapshot":
        return ("UNKNOWN",
                "snapshot build of %s: the fix landed in main before 26.8.2, "
                "so whether this build has it depends on its build date. "
                "Check the build time and treat it as unpatched until confirmed."
                % ".".join(str(x) for x in version))
    if version >= FIXED:
        return "PATCHED", "at or above the 26.8.2 fix"
    for low, high, reason in VULNERABLE_LINES:
        if low <= version < high:
            detail = reason
            if version == (26, 8, 0):
                detail += (" (26.8.0 also carries the `;` separator variant "
                           "fixed in 26.8.1)")
            return "VULNERABLE", detail
    return ("UNKNOWN",
            "advisory carries no affected-version data below 26.4, and no "
            "fix exists for this line. If the deployment uses SAML "
            "redirect binding, assume exposure until confirmed and "
            "upgrade to 26.8.2")


def apply_saml_usage(verdict, detail, saml_usage):
    """Fold the operator's SAML usage into the verdict.

    The flaw only matters where SAML is actually used (IdP brokering or a
    SAML client on the HTTP-Redirect binding). OIDC-only realms are not
    exposed, so a vulnerable version with no SAML in use is NOT-EXPOSED,
    not VULNERABLE. The version grade is still shown; only the final
    verdict changes.
    """
    if saml_usage == "no" and verdict == "VULNERABLE":
        return ("NOT-EXPOSED",
                detail + ". No SAML redirect binding in use, so this flaw "
                "is not reachable here. The version is still behind the "
                "fix: upgrade to 26.8.2 on your normal cycle.")
    if saml_usage == "unknown" and verdict == "VULNERABLE":
        return (verdict,
                detail + ". Confirm whether any realm brokers SAML or has a "
                "SAML client on the HTTP-Redirect binding; OIDC-only "
                "realms are not exposed.")
    return verdict, detail


def extract_version_from_html(html):
    """Pull the Keycloak version out of a welcome/login page.

    Returns the raw version segment (e.g. "26.8.1") or None. Only the
    first resources/<version>/ match is used; pages are consistent about
    it, and a mismatch would show up as a snapshot or an ungradeable
    string rather than a wrong grade.
    """
    match = RESOURCES_RE.search(html or "")
    return match.group(1) if match else None


def probe_url(base, timeout=10):
    """Read the version off a live Keycloak over plain unauthenticated GETs.

    Fetches the welcome page and the master-realm login page and reads the
    version Keycloak prints in its own theme resource URLs. Also checks
    the OIDC discovery document to confirm the target is Keycloak.
    Returns (version_raw, method, warnings). Raises ValueError on failure.
    """
    base = base.rstrip("/")
    headers = {"User-Agent": "keycloak-saml-scanner/1.0 (detection-only)"}
    html_pages = []
    warnings = []
    confirmed = False
    try:
        req = urllib.request.Request(
            base + "/realms/master/.well-known/openid-configuration",
            headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            doc = json.loads(resp.read().decode("utf-8", "replace"))
        issuer = doc.get("issuer", "")
        if "/realms/master" in issuer:
            confirmed = True
        else:
            warnings.append("discovery document issuer %r does not look "
                            "like Keycloak master realm" % issuer)
    except (urllib.error.URLError, ValueError, json.JSONDecodeError) as exc:
        warnings.append("could not read OIDC discovery document: %s" % exc)
    for path, label in (("/", "welcome page"),
                        ("/realms/master/protocol/openid-connect/auth"
                         "?client_id=account-console&response_type=code",
                         "login page")):
        try:
            req = urllib.request.Request(base + path, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                html_pages.append((label, resp.read().decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            # An error page is still a Keycloak page: the login theme is
            # rendered for error responses too, so its body may still
            # carry the versioned resource URLs. A 302 to /admin/ is
            # normal on a bootstrapped server and is followed by urllib.
            try:
                html_pages.append((label, exc.read().decode("utf-8", "replace")))
            except Exception:
                warnings.append("%s returned HTTP %s" % (label, exc.code))
        except urllib.error.URLError as exc:
            warnings.append("%s unreachable: %s" % (label, exc.reason))
    for label, html in html_pages:
        raw = extract_version_from_html(html)
        if raw:
            return raw, "theme resource URL on %s" % label, warnings, confirmed
    raise ValueError("no Keycloak version found in welcome or login page; "
                     "the deployment may use a custom theme that hides the "
                     "versioned resource URLs. Use --version or --local.")


def detect_local(path):
    """Detect the Keycloak version of a local install directory.

    Tries, in order: bin/kc.sh --version, keycloak-version.properties
    inside the keycloak-common jar, versioned jar filenames under lib/,
    the directory name. Collects every version found; if they disagree
    the result is UNKNOWN with the conflict listed, never a silent pick.
    Returns (version_raw, method, warnings).
    """
    root = Path(path)
    if not root.is_dir():
        raise ValueError("not a directory: %s" % path)
    found = {}  # raw version string -> method
    warnings = []

    kc_sh = root / "bin" / "kc.sh"
    if kc_sh.is_file():
        try:
            out = subprocess.run(
                [str(kc_sh), "--version"], capture_output=True, text=True,
                timeout=30, cwd=str(root)).stdout
            match = VERSION_RE.search(out or "")
            if match:
                found[match.group(0)] = "bin/kc.sh --version"
        except (OSError, subprocess.SubprocessError) as exc:
            warnings.append("kc.sh --version failed: %s" % exc)

    lib = root / "lib"
    if lib.is_dir():
        # Jar files carry the Maven group prefix, e.g.
        # org.keycloak.keycloak-common-26.8.1.jar
        jars = sorted(lib.rglob("*keycloak-common-*.jar"))
        jars += sorted(lib.rglob("*keycloak-services-*.jar"))
        for jar in jars:
            try:
                with zipfile.ZipFile(jar) as zf:
                    try:
                        props = zf.read("keycloak-version.properties").decode()
                    except KeyError:
                        props = ""
                for line in props.splitlines():
                    if line.startswith("version="):
                        found[line.split("=", 1)[1].strip()] = (
                            "keycloak-version.properties in %s" % jar.name)
                        break
                else:
                    match = re.search(r"keycloak-(?:common|services)-(\d+\.\d+\.\d+)",
                                      jar.name)
                    if match:
                        found.setdefault(match.group(1),
                                         "jar filename %s" % jar.name)
            except (zipfile.BadZipFile, OSError) as exc:
                warnings.append("could not read %s: %s" % (jar.name, exc))
        if not jars:
            # No jars at all: fall back to any versioned keycloak jar name.
            for jar in sorted(lib.rglob("*keycloak-*.jar")):
                match = re.search(r"keycloak-[A-Za-z-]+-(\d+\.\d+\.\d+)", jar.name)
                if match:
                    found.setdefault(match.group(1), "jar filename %s" % jar.name)

    if not found:
        match = VERSION_RE.search(root.name)
        if match:
            found[match.group(0)] = "directory name %s" % root.name

    if not found:
        raise ValueError("no Keycloak version found under %s: no kc.sh, no "
                         "versioned jars, no version in the directory name"
                         % path)
    if len(found) > 1:
        raise ValueError("version sources disagree under %s: %s"
                         % (path, "; ".join("%s (%s)" % (v, m)
                                            for v, m in found.items())))
    raw, method = next(iter(found.items()))
    return raw, method, warnings


def scan_version(raw, label, saml_usage="unknown"):
    """Grade one version string. Returns a result dict."""
    version, kind, note = parse_version(raw)
    if version is None:
        return {"label": label, "version": raw, "verdict": "UNKNOWN",
                "detail": note, "kind": kind}
    verdict, detail = grade(version, kind)
    if kind == "rhbk":
        detail += (". RHBK build: Red Hat had no fixed RHBK build as of "
                   "6 November 2026, graded on the upstream base version")
    verdict, detail = apply_saml_usage(verdict, detail, saml_usage)
    return {"label": label, "version": raw, "parsed": ".".join(str(x) for x in version),
            "kind": kind, "verdict": verdict, "detail": detail}


def print_result(result, as_json=False):
    if as_json:
        print(json.dumps(result, indent=2))
        return
    print("[%s] %s" % (result["verdict"], result["label"]))
    print("  version: %s" % result["version"])
    if result.get("parsed"):
        print("  parsed:  %s (%s)" % (result["parsed"], result["kind"]))
    print("  detail:  %s" % result["detail"])


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Detection-only triage for CVE-2026-117691 (Keycloak "
                    "SAML HTTP-Redirect binding signature bypass, fixed in "
                    "26.8.2).")
    parser.add_argument("--version", help="Keycloak version, e.g. 26.8.1")
    parser.add_argument("--version-file",
                        help="file holding a version string, or a "
                             "keycloak-version.properties file")
    parser.add_argument("--local", nargs="?", const=".",
                        help="local Keycloak install directory "
                             "(default: current directory)")
    parser.add_argument("--url",
                        help="base URL of a Keycloak you own, e.g. "
                             "https://id.example.com")
    parser.add_argument("--inventory-json",
                        help="JSON list of {label, version} or "
                             "{label, path} entries for a fleet")
    parser.add_argument("--saml-usage", choices=["yes", "no", "unknown"],
                        default="unknown",
                        help="whether any realm uses SAML IdP brokering or "
                             "a SAML client on the HTTP-Redirect binding "
                             "(default: unknown)")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    parser.add_argument("--list", action="store_true",
                        help="show the CVE summary and exit")
    args = parser.parse_args(argv)

    if args.list:
        print("%s: Keycloak SAML HTTP-Redirect binding signature bypass" % CVE_ID)
        print("  CVSS 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N), CWE-347")
        print("  Published 5 November 2026, fixed in Keycloak 26.8.2")
        print("  Percent-encoded parameter names (%53AMLResponse) are acted on")
        print("  while signature verification only checks literal names:")
        print("  unauthenticated full account takeover of federated users.")
        print("  26.6.9 and 26.4.18 backports lack the fix; 26.7 is EOL.")
        print("  26.8.2 also fixes 32 other CVEs, including the Brotli4j")
        print("  dependency flaw CVE-2026-111497 (see node2shell-inventory-scanner).")
        return 0

    results = []
    if args.version:
        results.append(scan_version(args.version, "version %s" % args.version,
                                    args.saml_usage))
    if args.version_file:
        try:
            text = Path(args.version_file).read_text().strip()
        except OSError as exc:
            print("error: cannot read %s: %s" % (args.version_file, exc),
                  file=sys.stderr)
            return 1
        raw = text
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("version="):
                raw = line.split("=", 1)[1].strip()
                break
        else:
            raw = text.splitlines()[0].strip() if text.splitlines() else ""
        results.append(scan_version(raw, "file %s" % args.version_file,
                                    args.saml_usage))
    if args.local is not None:
        try:
            raw, method, warnings = detect_local(args.local)
        except ValueError as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 1
        for warning in warnings:
            print("warning: %s" % warning, file=sys.stderr)
        result = scan_version(raw, "local install %s (%s)" % (args.local, method),
                              args.saml_usage)
        results.append(result)
    if args.url:
        try:
            raw, method, warnings, confirmed = probe_url(args.url)
        except ValueError as exc:
            print("error: %s" % exc, file=sys.stderr)
            return 1
        for warning in warnings:
            print("warning: %s" % warning, file=sys.stderr)
        if not confirmed:
            print("warning: could not confirm the target is Keycloak via "
                  "OIDC discovery; version taken from page content",
                  file=sys.stderr)
        results.append(scan_version(raw, "remote %s (%s)" % (args.url, method),
                                    args.saml_usage))
    if args.inventory_json:
        try:
            entries = json.loads(Path(args.inventory_json).read_text())
        except (OSError, ValueError) as exc:
            print("error: cannot read inventory %s: %s"
                  % (args.inventory_json, exc), file=sys.stderr)
            return 1
        if not isinstance(entries, list):
            print("error: inventory must be a JSON list", file=sys.stderr)
            return 1
        for entry in entries:
            label = entry.get("label", entry.get("host", "?"))
            usage = entry.get("saml", entry.get("saml_usage", args.saml_usage))
            if "version" in entry:
                results.append(scan_version(entry["version"], label, usage))
            elif "path" in entry:
                try:
                    raw, method, _ = detect_local(entry["path"])
                except ValueError as exc:
                    results.append({"label": label, "version": None,
                                    "verdict": "UNKNOWN", "detail": str(exc)})
                    continue
                results.append(scan_version(
                    raw, "%s (%s)" % (label, method), usage))
            else:
                results.append({"label": label, "version": None,
                                "verdict": "UNKNOWN",
                                "detail": "entry has neither version nor path"})

    if not results:
        parser.print_usage(sys.stderr)
        print("error: give one of --version, --version-file, --local, --url, "
              "--inventory-json, or --list", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for result in results:
            print_result(result)
    vulnerable = any(r["verdict"] == "VULNERABLE" for r in results)
    return 2 if vulnerable else 0


if __name__ == "__main__":
    sys.exit(main())
