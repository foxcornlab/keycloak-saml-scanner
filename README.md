# `keycloak-saml-scanner`

Local triage for `CVE-2026-117691` (`CVSS 9.1`), a signature bypass in `Keycloak`'s `SAML HTTP-Redirect` binding. Give it a `Keycloak` version you own, point it at an install directory, or point it at a `Keycloak` base `URL`, and it tells you whether that install is still open. It never sends a `SAML` message, never sends a crafted request, never logs in.

## `The flaw`

`CVE-2026-117691` is improper verification of cryptographic signature (`CWE-347`) in `Keycloak`'s `SAML HTTP-Redirect` binding. `Keycloak` processes percent-encoded query parameter names (`%53AMLResponse`) while its signature verification only checks literal parameter names. An unauthenticated attacker supplies a crafted, unsigned `SAML` message, placed before the legitimately signed one in the request, and the server acts on the unsigned message instead. The result is full account takeover of federated users: log in as any user, get their roles and data, no credentials, no user interaction.

Only `SAML` is exposed. A realm that brokers `SAML` identity providers, or serves a `SAML` client over the `HTTP-Redirect` binding, is in scope. `OIDC`-only realms are not. Use `--saml-usage no` if you know no `SAML` is in use: a vulnerable version then grades `NOT-EXPOSED` instead of `VULNERABLE`, and the version grade is still shown.

The fix is `Keycloak 26.8.2`, released `5 November 2026`. It is the only release carrying the fix, and it fixes `33 CVEs` in one release, including the `Brotli4j` dependency flaw `CVE-2026-111497` (graded separately by `node2shell-inventory-scanner`).

## `The traps: backports without the fix, and a dead line`

| `Signal` | `Grade` | `Why` |
| --- | --- | --- |
| `26.8.2` or newer | `PATCHED` | The only release carrying the fix |
| `26.8.0`, `26.8.1` | `VULNERABLE` | Fix only in `26.8.2`. `26.8.0` also carries the `;` separator variant fixed in `26.8.1`, so it has two bypasses in the same code path |
| `26.7.x` | `VULNERABLE` | End of life, no fix released at all |
| `26.6.x` up to `26.6.9` | `VULNERABLE` | The `26.6.9` backport does not include the fix. Taking the backport is not enough |
| `26.4.x` up to `26.4.18` | `VULNERABLE` | The `26.4.18` backport does not include the fix either |
| `26.5.x` and older | `UNKNOWN` | The advisory carries no affected-version data below `26.4`, and no fix exists for those lines. Assume exposure if you use `SAML` redirect binding, and upgrade to `26.8.2`. `UNKNOWN` is not clean |
| `26.9.0-SNAPSHOT` or any snapshot | `UNKNOWN` | A snapshot built before the fix commit is still vulnerable, so a snapshot cannot be graded as a release |
| `26.4.2.redhat-00001` (`RHBK`) | graded on the base version | `Red Hat Build of Keycloak` is affected too. `Red Hat` had no fixed `RHBK` build and no usable mitigation as of `6 November 2026` |

## `What it checks`

- `A version you supply` (`--version 26.8.1`): graded against the `26.8.2` fix
- `A version from a file` (`--version-file version.txt`): reads the first line, or the `version=` line of a `keycloak-version.properties` file
- `An install directory` (`--local /opt/keycloak`): detects the version from `bin/kc.sh --version`, from `keycloak-version.properties` inside the `keycloak-common` jar, from versioned jar filenames under `lib/`, or from the directory name. If the sources disagree it reports `UNKNOWN` with the conflict, never a silent pick
- `A live Keycloak you own` (`--url https://id.example.com`): two plain unauthenticated `GET`s, the welcome page and the master-realm login page, and reads the version `Keycloak` itself prints in its theme resource URLs (`resources/26.8.1/...`). Verified against the `Keycloak` source: the welcome page builds that path from `Version.RESOURCES_VERSION`, which is the running version. It also reads the `OIDC` discovery document to confirm the target is `Keycloak`. It never logs in, never submits a form, never sends `SAML`
- `An offline inventory` (`--inventory-json keycloak.json`): a `JSON` list of `{label, version}` or `{label, path}` entries, for a fleet of installs. Entries can carry their own `"saml": "yes|no|unknown"`
- `SAML usage` (`--saml-usage yes|no|unknown`): `no` turns a vulnerable version into `NOT-EXPOSED`, because the flaw is not reachable without `SAML`. Default is `unknown`, which keeps the `VULNERABLE` grade and tells you to confirm
- `The CVE summary` (`--list`): the flaw, the fix, and the backport situation

## `Usage`

```sh
# vulnerable: one patch behind the fix
python3 keycloak_saml_scanner.py --version 26.8.1

# fixed
python3 keycloak_saml_scanner.py --version 26.8.2

# the backport trap: newest 26.6, still open
python3 keycloak_saml_scanner.py --version 26.6.9

# Red Hat build, graded on its upstream base version
python3 keycloak_saml_scanner.py --version 26.4.2.redhat-00001

# OIDC-only deployment: vulnerable code, not reachable
python3 keycloak_saml_scanner.py --version 26.8.1 --saml-usage no

# from an install directory (kc.sh, jars, or directory name)
python3 keycloak_saml_scanner.py --local /opt/keycloak

# from a live Keycloak you own (reads the version off its own pages)
python3 keycloak_saml_scanner.py --url https://id.example.com

# a fleet, from a file you own
python3 keycloak_saml_scanner.py --inventory-json keycloak.json

# machine-readable output
python3 keycloak_saml_scanner.py --version 26.8.1 --json

# the CVE summary
python3 keycloak_saml_scanner.py --list
```

Exit codes: `0` = nothing vulnerable found, `2` = vulnerable finding, `1` = scan error. `UNKNOWN` does not change the exit code, but it is not clean. An unparseable version, a snapshot build, or a version below `26.4` has not been cleared. It has simply not been graded.

## `Tests`

```sh
python3 -m unittest discover -s tests -v
```

`47` tests, all passing: patched and vulnerable grades across the `26.8`, `26.7`, `26.6` and `26.4` lines, the backport traps, `UNKNOWN` grades below `26.4` and for snapshots, `RHBK` suffix handling, the `--saml-usage` verdicts, version extraction from welcome and login page `HTML`, `kc.sh` / jar / directory-name detection including a source-disagreement case, and `CLI` exit codes, `JSON` output, inventory grading, and live probes against a mock `Keycloak` server.

## `Sources`

- `Keycloak 26.8.2` release notes, `keycloak.org`, `5 November 2026`: the fix, issue `#54714`, `33 CVEs` in the release
- `Red Hat` `CVE-2026-117691` page: `CVSS 9.1` (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`), the percent-encoding mechanism, no mitigation, reporter `Mayssen Aidoudi` (`Think-it GmbH`)
- `GHSA-c85j-3hq2-q6wj`: published `5 November 2026`, `CVSS 9.1`, no affected or patched version data
- `phasetwo.io`, `Keycloak 26.8.2: 33 CVEs and a Critical SAML Bypass`, updated `6 November 2026`: the `;` separator variant fixed in `26.8.1`, and the `26.6.8`/`26.6.9` and `26.4.17`/`26.4.18` backports lacking the fix, with `26.7` end of life
- `Keycloak` source, `WelcomeResource.java` and `Version.java` (current `main`): the welcome page builds `resourcesPath` as `resources/` + `Version.RESOURCES_VERSION`, and `RESOURCES_VERSION` is the running version lowercased, which is what `--url` reads

Two disagreements to note. First, the advisory says nothing about which versions are affected, so this tool grades `26.4` through `26.8.1` as vulnerable on the strength of the fix release and the backport analysis, and everything below `26.4` as `UNKNOWN` rather than guessing. Second, the `Red Hat` page carries an `AI`-generated mitigation block claiming fixed `RHBK` builds exist; the same page's own statement says `Red Hat` currently offers no mitigation meeting its criteria, so this tool follows the `Red Hat` statement and flags `RHBK` versions as having no confirmed fixed build as of `6 November 2026`. `phasetwo` counts `33` fixes while `36 CVE` IDs appear in the release notes; three are cited only as earlier issues the release repairs, so this tool says `33`.

No public scanner for this `CVE` was found at publication time: no `nuclei` template exists for `CVE-2026-117691`, and no `foxcornlab` repo covered `Keycloak` or `SAML` before this one.

## `Disclaimer`

Defensive triage only, for systems you own or are authorized to assess. This tool detects exposure from version strings you supply or from version information a `Keycloak` server publishes about itself. It does not exploit anything, and it is not a substitute for the vendor update.

## `Thanks to`

- The `Keycloak` team for the advisory and the `26.8.2` release
- `Mayssen Aidoudi` (`Think-it GmbH`) for reporting the flaw
- `phasetwo` for the backport analysis that caught the `26.6`/`26.4` trap

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
