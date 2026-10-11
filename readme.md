# veem

http config checks from your terminal. blood red, white text, straight to the point.

checks headers, cookies, redirects and tls. gives you findings and tips on what to fix.

## get it running

grab python 3.10 or newer. no extra packages needed.

unzip everything, then open `start.bat` on windows. or run:

```bash
python veem.py
```

pick a url, run the check, read the results. that's it.

## skip the menu

```bash
python veem.py https://example.com
```

extra cors checks + a saved report:

```bash
python veem.py https://example.com --cors -o report.json
```

a whole list, one url per line:

```bash
python veem.py -f targets.txt -o report.md
```

need more options? `python veem.py --help`

## what it checks

- security headers, including hsts and csp
- cookie flags and scope rules
- https, certificate validity and expiry
- redirects and https downgrades
- cors settings and optional origin reflection checks
- server info exposed in headers

reports come in json, txt or markdown. query strings and cookie values get hidden, but still check your report before posting it.

## try it locally

start the demo:

```bash
python examples/demo_server.py
```

open another terminal:

```bash
python veem.py http://127.0.0.1:8765 --cors
```

that address stays on your own machine. the demo has weak settings on purpose.

## quick heads-up

findings are clues, not confirmed exploits. read the context before calling something a vuln.

redirects to another host stop unless you add `--allow-host hostname`. invalid tls certificates stop the connection too.

use it on your own stuff or where you've got permission.

if it crashes, launch through `start.bat` to keep the error visible. unexpected errors may also leave a `veem-crash.log` beside the script.

## tests

```bash
python -m unittest discover -s tests -v
```
