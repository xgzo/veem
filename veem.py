#!/usr/bin/env python3
"""veem - small HTTP configuration auditor. Python 3.10+, stdlib only."""
import argparse
import collections
import datetime as dt
import http.client
import json
import math
import os
from pathlib import Path
import re
import ssl
import sys
import time
import textwrap
import traceback
from urllib.parse import urlsplit, urlunsplit, urljoin, quote

VERSION = '1.1.0'
BANNER = r"""
 __     __   ________   ________   __       __
/  |   /  | /        | /        | /  \     /  |
$$ |   $$ | $$$$$$$$/  $$$$$$$$/  $$  \   /$$ |
$$ |   $$ | $$ |__     $$ |__     $$$  \ /$$$ |
$$  \ /$$/  $$    |    $$    |    $$$$  /$$$$ |
 $$  /$$/   $$$$$/     $$$$$/     $$ $$ $$/$$ |
  $$ $$/    $$ |_____  $$ |_____  $$ |$$$/ $$ |
   $$$/     $$       | $$       | $$ | $/  $$ |
    $/      $$$$$$$$/  $$$$$$$$/  $$/      $$/
"""
RED = '\033[38;2;150;15;30m'
WHITE = '\033[97m'
RESET = '\033[0m'
REDIRECTS = {301, 302, 303, 307, 308}


def clean(value):
    # Server-controlled strings never get to issue terminal escape sequences.
    return ''.join(c if c.isprintable() or c == '\n' else '?' for c in str(value))


def normalize(value):
    value = value.strip()
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('URL contains control characters')
    if '://' not in value:
        value = 'https://' + value
    p = urlsplit(value)
    if p.scheme not in ('http', 'https') or not p.hostname:
        raise ValueError('Use an http:// or https:// URL')
    if p.username is not None or p.password is not None:
        raise ValueError('Credentials in URLs are not supported')
    host = p.hostname.encode('idna').decode('ascii')
    port = p.port  # validates the range, too
    authority = '[' + host + ']' if ':' in host else host
    if port:
        authority += ':' + str(port)
    return urlunsplit((p.scheme, authority, quote(p.path or '/', safe="/%:@!$&'()*+,;=-._~"),
                       quote(p.query, safe="%/:?@!$&'()*+,;=-._~"), ''))


def display_url(url):
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path, '[redacted]' if p.query else '', ''))


def headers_map(pairs):
    out = collections.defaultdict(list)
    for key, value in pairs:
        out[key.lower()].append(value)
    return out


def request(url, timeout=10, ca_file=None, origin=None):
    p = urlsplit(url)
    conn = None
    start = time.monotonic()
    try:
        if p.scheme == 'https':
            context = ssl.create_default_context(cafile=ca_file)
            conn = http.client.HTTPSConnection(p.hostname, p.port or 443, timeout=timeout, context=context)
        else:
            conn = http.client.HTTPConnection(p.hostname, p.port or 80, timeout=timeout)
        conn.connect()
        tls = None
        if p.scheme == 'https':
            cert = conn.sock.getpeercert()
            expiry = ssl.cert_time_to_seconds(cert['notAfter'])
            tls = {'version': conn.sock.version(), 'cipher': conn.sock.cipher()[0],
                   'verified': True, 'expires': cert['notAfter'],
                   'days_left': int((expiry - time.time()) / 86400)}
        req_headers = {'User-Agent': 'veem/' + VERSION, 'Accept': '*/*', 'Connection': 'close'}
        if origin:
            req_headers['Origin'] = origin
        path = p.path or '/'
        if p.query:
            path += '?' + p.query
        conn.request('GET', path, headers=req_headers)
        response = conn.getresponse()
        # Only headers are needed; no unbounded download or decompression.
        return {'url': display_url(url), 'status': response.status,
                'headers': response.getheaders(), 'tls': tls,
                'elapsed_ms': round((time.monotonic() - start) * 1000)}
    finally:
        if conn:
            conn.close()


def analyze(response):
    h = headers_map(response['headers'])
    get = lambda name: ', '.join(h.get(name, []))
    issues = []
    def add(level, check, detail, fix):
        issues.append({'level': level, 'check': check, 'detail': detail, 'fix': fix,
                       'url': response['url']})
    https = response['url'].startswith('https:')
    html = 'text/html' in get('content-type').lower() or 'application/xhtml+xml' in get('content-type').lower()
    if not https:
        add('medium', 'transport.http', 'Response received over cleartext HTTP.', 'Serve HTTPS and redirect HTTP to HTTPS.')
    else:
        sts = get('strict-transport-security')
        age = re.search(r'(?:^|;)\s*max-age\s*=\s*"?(\d+)"?\s*(?:;|$)', sts, re.I)
        if not sts:
            add('medium', 'hsts.missing', 'No HSTS header on HTTPS.', 'Roll out HSTS after checking HTTPS across the intended scope.')
        elif not age or len(h['strict-transport-security']) > 1:
            add('low', 'hsts.invalid', 'Malformed or repeated HSTS header.', 'Send one valid Strict-Transport-Security header with max-age.')
        elif int(age[1]) == 0:
            add('medium', 'hsts.disabled', 'HSTS max-age is zero.', 'Use a positive max-age after validating HTTPS.')
        elif int(age[1]) < 15552000:
            add('low', 'hsts.short', 'HSTS lifetime is below 180 days.', 'Consider a longer lifetime after a staged rollout.')
    if get('x-content-type-options').lower() != 'nosniff':
        add('low', 'mime.nosniff', 'X-Content-Type-Options is missing or not nosniff.', 'Send X-Content-Type-Options: nosniff.')
    if not get('content-type'):
        add('low', 'mime.missing', 'Content-Type is missing.', 'Set the actual response media type.')
    if html:
        policies = h.get('content-security-policy', [])
        if not policies:
            detail = 'No enforcing CSP header.'
            if get('content-security-policy-report-only'):
                detail += ' Report-only does not enforce restrictions.'
            add('medium', 'csp.missing', detail, 'Build a CSP for this application and test it in report-only first.')
        parsed = []
        for policy in policies:
            directives = {}
            for part in policy.split(';'):
                tokens = part.strip().split()
                if tokens:
                    directives.setdefault(tokens[0].lower(), tokens[1:])
            parsed.append(directives)
        # Multiple policies are intersected by browsers. Do not pretend to evaluate that here.
        if len(parsed) == 1:
            d = parsed[0]
            scripts = d.get('script-src-elem', d.get('script-src', d.get('default-src', [])))
            if not any(k in d for k in ('script-src-elem', 'script-src', 'default-src')):
                add('medium', 'csp.scripts_unrestricted', 'CSP does not restrict script elements.', 'Define script-src, preferably with nonces or hashes.')
            if "'unsafe-inline'" in scripts and not any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in scripts):
                add('medium', 'csp.inline', 'Script policy allows unsafe-inline without a nonce/hash.', 'Use per-response nonces or script hashes.')
            if any("'unsafe-eval'" in values for values in d.values()):
                add('low', 'csp.eval', 'unsafe-eval appears in CSP; review the effective script policy.', 'Remove eval dependencies where possible.')
            if '*' in scripts or 'https:' in scripts or 'http:' in scripts:
                add('medium', 'csp.broad', 'Script sources contain a broad wildcard or scheme.', 'Limit script sources to required origins or nonces/hashes.')
            for directive in ('object-src', 'base-uri'):
                if directive not in d and (directive == 'base-uri' or 'default-src' not in d):
                    add('low', 'csp.' + directive, directive + ' is not restricted.', 'Set ' + directive + " to an application-appropriate value, often 'none' or 'self'.")
        elif len(parsed) > 1:
            add('info', 'csp.multiple', 'Multiple CSP headers need combined-policy review.', 'Review browser-enforced policy intersection manually.')
        framed = any(d.get('frame-ancestors') and '*' not in d['frame-ancestors'] for d in parsed)
        xfo = get('x-frame-options').lower()
        if not framed and xfo not in ('deny', 'sameorigin'):
            add('medium', 'framing.policy', 'No recognized restrictive framing policy.', "Use CSP frame-ancestors 'none' or the required trusted origins.")
        rp = [v.strip().lower() for v in get('referrer-policy').split(',') if v.strip()]
        if not rp:
            add('info', 'referrer.default', 'No explicit Referrer-Policy; browser defaults apply.', 'Consider strict-origin-when-cross-origin or no-referrer.')
        elif rp[-1] in ('unsafe-url', 'no-referrer-when-downgrade'):
            add('low', 'referrer.broad', 'Referrer policy can disclose more URL information.', 'Consider strict-origin-when-cross-origin.')
        if not get('permissions-policy'):
            add('info', 'permissions.review', 'No Permissions-Policy header.', 'Restrict browser features your page does not use.')
    for name in ('server', 'x-powered-by', 'x-aspnet-version'):
        if get(name):
            add('info', 'disclosure.' + name, name + ': ' + clean(get(name)), 'Reduce unnecessary product/version disclosure; this alone is not an exploit.')
    acao = get('access-control-allow-origin')
    if acao == '*':
        add('info', 'cors.wildcard', 'Any origin may read non-credentialed responses; this can be intentional.', 'Check whether the resource is meant to be public.')
        if get('access-control-allow-credentials').lower() == 'true':
            add('low', 'cors.invalid_credentials', 'Wildcard origin plus credentials is rejected by browsers.', 'Use an explicit trusted origin when credentials are required.')
    cookies = []
    for line in h.get('set-cookie', []):
        parts = [p.strip() for p in line.split(';')]
        if '=' not in parts[0]:
            add('low', 'cookie.malformed', 'Unparseable Set-Cookie header.', 'Review cookie syntax.')
            continue
        name = parts[0].split('=', 1)[0]
        attrs = {}
        for item in parts[1:]:
            k, _, v = item.partition('=')
            attrs[k.lower()] = v
        cookies.append({'name': name, 'attributes': attrs, 'value': '[redacted]'})
        for flag in ('secure', 'httponly'):
            if flag not in attrs:
                add('low', 'cookie.' + flag, name + ' has no ' + flag + '.',
                    'Use Secure for HTTPS cookies; use HttpOnly for cookies that JavaScript does not need.')
        same = attrs.get('samesite', '').lower()
        if same not in ('lax', 'strict', 'none'):
            add('low', 'cookie.samesite', name + ' has no recognized explicit SameSite.', 'Choose Lax, Strict, or None to fit the application.')
        if same == 'none' and 'secure' not in attrs:
            add('medium', 'cookie.none_without_secure', name + ': SameSite=None without Secure.', 'Add Secure; browsers reject this combination otherwise.')
        if name.startswith(('__Secure-', '__Host-', '__Http-')) and ('secure' not in attrs or not https):
            add('medium', 'cookie.prefix_secure', name + ' violates secure prefix requirements.', 'Set via HTTPS with Secure.')
        if name.startswith('__Host-') and ('domain' in attrs or attrs.get('path') != '/'):
            add('medium', 'cookie.prefix_host', name + ' violates host prefix scope.', 'Use Path=/ and omit Domain.')
        if name.startswith(('__Http-', '__Host-Http-')) and 'httponly' not in attrs:
            add('medium', 'cookie.prefix_http', name + ' needs HttpOnly.', 'Add HttpOnly.')
    tls = response.get('tls')
    if tls and tls['days_left'] < 30:
        add('low', 'tls.expiry', 'Certificate expires in %s days.' % tls['days_left'], 'Verify automatic certificate renewal.')
    if response['status'] >= 400:
        add('info', 'response.error_page', 'HTTP %s: findings describe this error response.' % response['status'], 'Also inspect a representative successful page.')
    return issues, cookies


def audit(target, args):
    result = {'target': clean(target), 'started': dt.datetime.now(dt.timezone.utc).isoformat(),
              'hops': [], 'findings': [], 'errors': [], 'complete': False}
    try:
        current = normalize(target)
        result['target'] = display_url(current)
        original_host = urlsplit(current).hostname
        allowed = {original_host, *[x.lower() for x in args.allow_host]}
        visited = set()
        for n in range(args.max_redirects + 1):
            if current in visited:
                raise ValueError('Redirect loop detected')
            visited.add(current)
            response = request(current, args.timeout, args.ca_file)
            findings, cookies = analyze(response)
            result['findings'].extend(findings)
            h = headers_map(response['headers'])
            # Deliberately keep only the diagnostic headers; no raw auth tokens/cookies.
            safe_names = {'content-type', 'strict-transport-security', 'content-security-policy',
                          'content-security-policy-report-only', 'x-frame-options', 'x-content-type-options',
                          'referrer-policy', 'permissions-policy', 'server', 'x-powered-by',
                          'access-control-allow-origin', 'access-control-allow-credentials', 'cache-control'}
            response['headers'] = {k: [clean(v) for v in vals] for k, vals in h.items() if k in safe_names}
            response['cookies'] = cookies
            result['hops'].append(response)
            if response['status'] not in REDIRECTS or not h.get('location'):
                result['complete'] = True
                break
            nxt = normalize(urljoin(current, h['location'][0]))
            response['redirect_to'] = display_url(nxt)
            if urlsplit(nxt).hostname not in allowed:
                raise ValueError('Cross-host redirect stopped. Add --allow-host for this host if in scope.')
            if urlsplit(current).scheme == 'https' and urlsplit(nxt).scheme == 'http':
                result['findings'].append({'level': 'medium', 'check': 'redirect.downgrade',
                    'url': response['url'], 'detail': 'HTTPS redirects to HTTP; stopped.', 'fix': 'Keep redirects on HTTPS.'})
                raise ValueError('HTTPS downgrade stopped')
            if n == args.max_redirects:
                raise ValueError('Redirect limit reached')
            current = nxt
        if args.cors and result['complete']:
            for origin in ('https://veem-check.invalid', 'https://veem-other.invalid'):
                try:
                    probe = request(current, args.timeout, args.ca_file, origin)
                    ph = headers_map(probe['headers'])
                    if ph.get('access-control-allow-origin') == [origin]:
                        cred = ph.get('access-control-allow-credentials') == ['true']
                        result['findings'].append({'level': 'medium' if cred else 'low',
                            'check': 'cors.reflection', 'url': display_url(current),
                            'detail': 'Response reflects test origin' + (' with credentials.' if cred else '.'),
                            'fix': 'Validate the origin allowlist. Confirm with a browser and sensitive data before claiming impact.'})
                except (OSError, ValueError, UnicodeError, http.client.HTTPException) as exc:
                    result['errors'].append('CORS probe failed: ' + type(exc).__name__)
    except ssl.SSLCertVerificationError:
        result['errors'].append('TLS certificate verification failed. Check expiry, hostname and trust chain; use --ca-file for a private CA.')
    except (OSError, ValueError, UnicodeError, http.client.HTTPException) as exc:
        # Exception strings from HTTP parsers may contain unredacted response bytes.
        result['errors'].append(clean(str(exc)) if isinstance(exc, ValueError) else type(exc).__name__ + ': connection or protocol failure')
    result['summary'] = dict(collections.Counter(f['level'] for f in result['findings']))
    return result


def render(report):
    lines = ['veem / HTTP configuration report', '']
    for r in report['results']:
        lines += ['Target: ' + r['target'], 'Complete: ' + str(r['complete'])]
        for hop in r['hops']:
            lines.append('  [%s] %s (%s ms)' % (hop['status'], hop['url'], hop['elapsed_ms']))
            if hop['tls']:
                lines.append('  TLS: %s / %s / %s days left' % (hop['tls']['version'], hop['tls']['cipher'], hop['tls']['days_left']))
        for f in r['findings']:
            lines += ['[%s] %s @ %s' % (f['level'].upper(), f['check'], f['url']),
                      '  ' + f['detail'], '  fix: ' + f['fix']]
        lines += ['[ERROR] ' + e for e in r['errors']]
        lines += ['Summary: ' + str(r['summary']), '']
    return clean('\n'.join(lines))


def positive_float(s):
    value = float(s)
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError('must be a finite positive number')
    return value


def parser():
    p = argparse.ArgumentParser(description='veem - HTTP config checks, no extra packages')
    p.add_argument('urls', nargs='*', help='URLs or hostnames (default scheme: HTTPS)')
    p.add_argument('-f', '--file', type=Path, help='target file, one URL per line')
    p.add_argument('--timeout', type=positive_float, default=10, help='socket timeout in seconds (default: 10)')
    p.add_argument('--max-redirects', type=int, choices=range(0, 21), default=5, metavar='0..20')
    p.add_argument('--allow-host', action='append', default=[], help='extra redirect hostname in scope; repeatable')
    p.add_argument('--ca-file', help='trusted PEM CA bundle for private TLS labs')
    p.add_argument('--cors', action='store_true', help='send two additional Origin probes')
    p.add_argument('-o', '--output', type=Path, help='report filename (.json, .txt or .md)')
    p.add_argument('--format', choices=['json', 'txt', 'md'], help='override output format')
    p.add_argument('--json', action='store_true', help='JSON on stdout, no banner/menu')
    p.add_argument('--no-color', action='store_true')
    p.add_argument('--fail-on', choices=['low', 'medium'], help='exit 1 at this severity or above')
    p.add_argument('--version', action='version', version='veem ' + VERSION)
    return p


def palette(disabled=False):
    color = sys.stdout.isatty() and not disabled and 'NO_COLOR' not in os.environ
    if color and os.name == 'nt':
        try:
            import ctypes
            handle = ctypes.windll.kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode))
            color = bool(ctypes.windll.kernel32.SetConsoleMode(handle, mode.value | 4))
        except (AttributeError, OSError):
            color = False
    return color


def say(text='', color=False, accent=False):
    print(((RED if accent else WHITE) if color else '') + clean(text) + (RESET if color else ''))


def heading(color):
    width = 62
    say('\n  .' + '-' * width + '.', color, True)
    say('  |' + '. : : /  V E E M  / : : .'.center(width) + '|', color)
    say('  |' + ' ' * width + '|', color, True)
    art = BANNER.strip('\n').splitlines()
    art_width = max(map(len, art))
    for line in art:
        say('  |' + line.ljust(art_width).center(width) + '|', color, True)
    say('  |' + ' ' * width + '|', color, True)
    say('  |' + ('HTTP CONFIG AUDITOR   //   v' + VERSION).center(width) + '|', color)
    say("  '" + '-' * width + "'", color, True)


def terminal_report(report, color):
    for result in report['results']:
        say('\n  +--[ AUDIT RESULTS ]' + '-' * 43 + '+', color, True)
        for line in textwrap.wrap(result['target'], 62):
            say('  | ' + line, color)
        say('  | State: ' + ('COMPLETE' if result['complete'] else 'INCOMPLETE'), color)
        counts = result['summary']
        say('  | MEDIUM %s    LOW %s    INFO %s' % tuple(counts.get(x, 0) for x in ('medium', 'low', 'info')), color)
        say('  +' + '-' * 62 + '+', color, True)
        for hop in result['hops']:
            say('\n  [%s] %s ms  %s' % (hop['status'], hop['elapsed_ms'], hop['url']), color)
            if hop['tls']:
                tls = hop['tls']
                say('       %s / %s / expires in %s days' % (tls['version'], tls['cipher'], tls['days_left']), color)
        for f in result['findings']:
            say('\n  [%s] %s' % (f['level'].upper(), f['check']), color, f['level'] != 'info')
            for label, value in (('at: ', f['url']), ('', f['detail']), ('fix: ', f['fix'])):
                for line in textwrap.wrap(clean(label + value), 65):
                    say('     ' + line, color)
        for error in result['errors']:
            say('\n  [ERROR] ' + error, color, True)
        say('\n  ' + '.' * 64, color, True)


def menu(args):
    color = palette(args.no_color)
    while True:
        heading(color)
        say('\n       [01]  Audit one URL', color)
        say('       [02]  Audit target file', color)
        say('       [03]  Help / commands', color)
        say('       [00]  Exit\n', color)
        try:
            choice = input('       veem / > ').strip().lstrip('0') or '0'
            if choice == '0':
                return 0
            if choice == '3':
                parser().print_help()
            elif choice in ('1', '2'):
                value = input('       ' + ('URL' if choice == '1' else 'File path') + ' > ').strip().strip('"')
                if not value:
                    say('       [!] Enter a URL or file path.', color, True)
                    continue
                cmd = [value] if choice == '1' else ['--file', value]
                cmd += ['--timeout', str(args.timeout), '--max-redirects', str(args.max_redirects)]
                if args.no_color:
                    cmd.append('--no-color')
                for host in args.allow_host:
                    cmd += ['--allow-host', host]
                if args.ca_file:
                    cmd += ['--ca-file', args.ca_file]
                if input('       Extra CORS checks? [y/N] > ').strip().lower() in ('y', 'yes', 's', 'sim'):
                    cmd.append('--cors')
                dest = input('       Save as (.json/.txt/.md, Enter = skip) > ').strip().strip('"')
                if dest:
                    if not Path(dest).suffix:
                        dest += '.json'
                    if Path(dest).suffix.lower() not in ('.json', '.txt', '.md'):
                        say('       [!] Use .json, .txt or .md.', color, True)
                        continue
                    cmd += ['--output', dest]
                try:
                    code = main(cmd, show_banner=False)
                    if code == 130:
                        say('       Audit stopped.', color)
                except SystemExit as exc:
                    say('       [!] Invalid input (code %s). Try again.' % exc.code, color, True)
                except Exception:
                    crash_note(color)
            else:
                say('       [!] Choose 01, 02, 03 or 00.', color, True)
                continue
            input('\n       Press Enter to return to the menu...')
        except (KeyboardInterrupt, EOFError):
            say('\n       Session closed.', color)
            return 0


def crash_note(color=False):
    path = Path(__file__).resolve().with_name('veem-crash.log')
    try:
        with path.open('a', encoding='utf-8') as log:
            log.write('\n' + dt.datetime.now(dt.timezone.utc).isoformat() + '\n')
            log.write(traceback.format_exc())
        say('  [ERROR] Unexpected error. Details saved to ' + str(path), color, True)
    except OSError:
        say('  [ERROR] Cannot save crash log. Diagnostic details:', color, True)
        traceback.print_exc()


def main(argv=None, show_banner=True):
    p = parser()
    args = p.parse_args(argv)
    if not args.urls and not args.file and not args.json and sys.stdin.isatty():
        return menu(args)
    color = palette(args.no_color)
    if not args.json and show_banner:
        heading(color)
    targets = list(args.urls)
    try:
        if not targets and not args.file:
            p.error('provide a URL or --file')
        if args.file:
            targets.extend(x.strip() for x in args.file.read_text(encoding='utf-8-sig').splitlines()
                           if x.strip() and not x.lstrip().startswith('#'))
        targets = list(dict.fromkeys(targets))
        if not targets:
            p.error('target list is empty')
        report = {'tool': 'veem', 'version': VERSION, 'results': []}
        for i, target in enumerate(targets, 1):
            if not args.json:
                print('  [%d/%d] checking target...' % (i, len(targets)), flush=True)
            report['results'].append(audit(target, args))
        text = render(report)
        if args.json:
            print(json.dumps(report, indent=2, ensure_ascii=True))
        else:
            terminal_report(report, color)
        if args.output:
            fmt = args.format or args.output.suffix.lstrip('.').lower() or 'txt'
            if fmt not in ('json', 'txt', 'md'):
                p.error('output extension must be .json, .txt or .md (or set --format)')
            data = json.dumps(report, indent=2, ensure_ascii=True) if fmt == 'json' else text
            if fmt == 'md':
                fence = '`' * max(3, max((len(m[0]) + 1 for m in re.finditer(r'`+', text)), default=3))
                data = '# veem report\n\n' + fence + 'text\n' + text + '\n' + fence + '\n'
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(data + '\n', encoding='utf-8')
            print('saved: ' + clean(args.output), file=sys.stderr)
        if any(r['errors'] or not r['complete'] for r in report['results']):
            return 2
        ranks = {'info': 0, 'low': 1, 'medium': 2}
        if args.fail_on and any(ranks[f['level']] >= ranks[args.fail_on] for r in report['results'] for f in r['findings']):
            return 1
        return 0
    except (OSError, UnicodeError) as exc:
        print('veem: ' + clean(exc), file=sys.stderr)
        return 2
    except (KeyboardInterrupt, EOFError):
        print('\nveem: stopped', file=sys.stderr)
        return 130


if __name__ == '__main__':
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(errors='replace')
    try:
        sys.exit(main())
    except Exception:
        crash_note()
        if sys.stdin.isatty():
            try:
                input('Press Enter to close...')
            except (EOFError, KeyboardInterrupt):
                pass
        sys.exit(2)
