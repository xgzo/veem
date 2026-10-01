# veem

```text
 __     __   ________   ________   __       __
/  |   /  | /        | /        | /  \     /  |
$$ |   $$ | $$$$$$$$/  $$$$$$$$/  $$  \   /$$ |
$$ |   $$ | $$ |__     $$ |__     $$$  \ /$$$ |
$$  \ /$$/  $$    |    $$    |    $$$$  /$$$$ |
 $$  /$$/   $$$$$/     $$$$$/     $$ $$ $$/$$ |
  $$ $$/    $$ |_____  $$ |_____  $$ |$$$/ $$ |
   $$$/     $$       | $$       | $$ | $/  $$ |
    $/      $$$$$$$$/  $$$$$$$$/  $$/      $$/
```

HTTP config checks straight from your terminal. Blood red, white text, actual findings.
No pip shopping list. Just **Python 3.10+**, standard library only.

## run it

On Windows, unzip the whole folder and double-click **start.bat**. It keeps errors visible.
Do not run the file from inside the ZIP. Or open a terminal in this folder:

```bash
python veem.py
```

Windows: `py -3 veem.py` works too. Linux/macOS might need `python3`.
The menu lets you pick a URL or target list, enable CORS probes and save a report.

```bash
python veem.py https://example.com
python veem.py https://example.com --cors -o reports/check.json
python veem.py -f targets.txt -o reports/check.md
python veem.py https://example.com --json > report.json
python veem.py https://example.com --fail-on medium --no-color
```

Use your own systems or targets you have permission to assess. Keep the scope tight.

## what's inside

- HTTP/HTTPS, redirect trail, downgrade detection, status codes and timings.
- Verified TLS certificate chain/hostname, negotiated TLS version, cipher and expiry.
- HSTS presence, disabled/short lifetime and syntax checks.
- HTML CSP checks: missing enforcement, broad scripts, inline/eval hints, object-src, base-uri.
- Framing policy, MIME/nosniff, referrer policy, permissions policy, server disclosure.
- Separate parsing of each Set-Cookie: Secure, HttpOnly, SameSite and prefix checks.
- Passive CORS checks; optional two-Origin reflection probes.
- Batch input, JSON/text/Markdown reports, CI exit codes.
- Terminal colors, Windows ANSI support, clean redirected output and NO_COLOR support.

## flags

| Flag | What it does |
| --- | --- |
| `URL ...` | One or more targets. Missing scheme means HTTPS. |
| `-f, --file PATH` | UTF-8 list, one target per line. Blank lines and # comments ignored. |
| `--timeout SECONDS` | Positive socket timeout, default 10; not a whole-scan deadline. |
| `--max-redirects N` | Default 5, allowed 0 through 20. |
| `--allow-host HOST` | Extra redirect hostname in scope; repeatable, no scheme/port. |
| `--ca-file PATH` | Trusted PEM CA bundle for private TLS labs. |
| `--cors` | Two extra GET requests with reserved test origins. |
| `-o, --output PATH` | Save .json, .txt or .md. Existing file is replaced. |
| `--format FORMAT` | Override extension: json, txt or md. |
| `--json` | JSON stdout; no banner or menu. |
| `--no-color` | Disable ANSI color. |
| `--fail-on low\|medium` | Exit 1 at this finding severity or above. |
| `--version` | Print version. |

Target file:

```text
# your authorized targets
https://example.com/
https://example.com/login
```

Redirects stay on the starting hostname by default (ports may change).

```bash
python veem.py https://example.com --allow-host www.example.com
```

HTTPS downgrades always stop. No separate HTTPS probe is made for HTTP targets.
Start with HTTP to inspect its upgrade redirect, or HTTPS to inspect TLS directly.

## read the evidence

`medium` is a meaningful hardening concern or candidate issue. `low` is a narrower concern.
`info` is context or a manual review hint. These are heuristics, not CVSS and not proof of
exploitation. No fake security grade here.

A missing header is not automatically a vulnerability. Public APIs can use wildcard CORS.
Some cookies need JavaScript access. Browser referrer defaults already provide protection.
CORS reflection needs browser validation and sensitive data before you claim account impact.
Wildcard origin with credentials is rejected by browsers; it is not an automatic data leak.

CSP checks are lightweight. Multiple policies get a manual-review note because their
restrictions combine. This is not a complete browser CSP parser. Meta CSP, mixed content,
HTML resources, preflights and authenticated flows are not inspected. API responses are
not treated like HTML. Error-page findings describe that response, not the entire app.

TLS shows one negotiation under your Python/OpenSSL defaults, not every supported
protocol/cipher. No revocation/OCSP/CT checks. Invalid certificates stop the connection.
No silent insecure retry. Private CA? Use --ca-file.

## traffic and privacy

GET only, sequential targets, no crawler or exploit payloads. One GET per hop plus two
optional CORS GETs. Bodies are not downloaded for analysis. No authentication or cookie
jar. Proxy environment variables are not used. HTTP/1.1 only. DNS may exceed socket timeout.

Reports redact query strings and cookie values and store only selected diagnostic headers.
Paths, cookie names/attributes and selected headers can still contain sensitive information.
Read your reports before posting them publicly. Terminal control characters are removed
from text; JSON escapes them.

Exit codes: **0** complete, **1** finding threshold reached, **2** input/network/output error
or incomplete scan, **130** interrupted. Errors take priority. Findings alone do not fail
unless --fail-on is set.

## local demo

```bash
python examples/demo_server.py
```

Another terminal:

```bash
python veem.py http://127.0.0.1:8765 --cors -o demo.json
```

Intentionally weak config, loopback only. No internet needed. Ctrl+C stops it.
See `examples/sample-report.json` for real demo output.

## tests

```bash
python -m unittest discover -s tests -v
```

Local HTTP fixture and mocked certificate failures; no public target scans.

## files

- `veem.py`: main tool. No framework maze.
- `tests/test_veem.py`: regression tests.
- `examples/demo_server.py`: local demo.
- `examples/sample-report.json`: sample output.

## references

- [Python http.client](https://docs.python.org/3/library/http.client.html)
- [MDN HTTP headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers)
- [MDN Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)
- [MDN HSTS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security)
- [MDN CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy)

Small tool. Read the evidence. Fix what actually matters.

## v1.1 fixes

New block ASCII, framed menu and grouped findings. The menu stays open after audits,
bad choices and missing files. Unexpected errors write `veem-crash.log` beside the script.
That log may contain local paths and response details: review it before sharing.
Windows launcher keeps the console open even when Python fails to start.
The Windows launcher has not been executed on Windows in this build environment.
