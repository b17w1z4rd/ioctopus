#!/usr/bin/env python3
"""
ioctopus - extract, refang, enrich and export indicators of compromise (IOCs).

Point it at a threat report, blog post, email, or log dump and it pulls out the
indicators, un-defangs the ones that were neutered for safe sharing
(hxxp://evil[.]com -> http://evil.com), deduplicates with counts, enriches each,
and exports to a table, JSON, CSV, or a STIX 2.1 bundle.

    ioctopus report.txt
    cat report.txt | ioctopus --json
    ioctopus report.txt --stix > iocs.json
    ioctopus report.txt --defang        # re-defang for safe sharing

Standard library only. Defensive / CTI use.
"""
import sys, re, json, csv, argparse, ipaddress, math, uuid, io
from collections import Counter
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Refang: undo the common ways analysts neuter live indicators in reports.
# ---------------------------------------------------------------------------
def refang(text: str) -> str:
    t = text
    t = re.sub(r'h[x_]{2}p(s?)', r'http\1', t, flags=re.I)   # hxxp / hXXp / h__p
    t = re.sub(r'\[\s*(?:\.|dot)\s*\]', '.', t, flags=re.I)   # [.]  [dot]
    t = re.sub(r'\(\s*(?:\.|dot)\s*\)', '.', t, flags=re.I)   # (.)  (dot)
    t = re.sub(r'\{\s*\.\s*\}', '.', t)                       # {.}
    t = re.sub(r'\[\s*(?:@|at)\s*\]', '@', t, flags=re.I)     # [@]  [at]
    t = re.sub(r'\(\s*(?:@|at)\s*\)', '@', t, flags=re.I)     # (@)  (at)
    t = re.sub(r'\[\s*:\s*\]', ':', t)                        # [:]
    t = re.sub(r'\[\s*://\s*\]', '://', t)                    # [://]
    t = re.sub(r'\[\s*/\s*\]', '/', t)                        # [/]
    return t

# ---------------------------------------------------------------------------
# Extraction patterns (run over refanged text).
# ---------------------------------------------------------------------------
OCTET = r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
PATTERNS = {
    'url':     re.compile(r'\b(?:https?|ftp)://[^\s<>"\'\)\]]{4,}', re.I),
    'email':   re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,24}\b'),
    'ipv4':    re.compile(r'\b(?:%s\.){3}%s\b' % (OCTET, OCTET)),
    'ipv6':    re.compile(r'\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b', re.I),
    'sha256':  re.compile(r'\b[a-fA-F0-9]{64}\b'),
    'sha1':    re.compile(r'\b[a-fA-F0-9]{40}\b'),
    'md5':     re.compile(r'\b[a-fA-F0-9]{32}\b'),
    'cve':     re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.I),
    'btc':     re.compile(r'\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b'),
    'domain':  re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b'),
}

# TLD-position tokens that are almost always filenames, not domains.
FILE_EXTS = {
    'exe','dll','sys','bat','ps1','vbs','js','jar','py','rb','php','html','htm',
    'css','json','xml','yaml','yml','txt','md','pdf','doc','docx','xls','xlsx',
    'ppt','pptx','csv','log','conf','cfg','ini','png','jpg','jpeg','gif','bmp',
    'svg','ico','zip','rar','tar','gz','7z','bin','dat','db','sql','sh','c',
    'cpp','h','go','rs','o','tmp','bak','lnk','scr','dmp',
}
# Common benign domains to drop with --no-noise.
BENIGN = {
    'microsoft.com','windows.com','google.com','gstatic.com','github.com',
    'cloudflare.com','amazonaws.com','apple.com','mozilla.org','w3.org',
    'schema.org','example.com','localhost',
}
# TLDs disproportionately abused (informational tag, not a verdict).
SUSPICIOUS_TLDS = {'tk','top','xyz','gq','ml','cf','ga','work','zip','mov','su','cc','pw'}

# ---------------------------------------------------------------------------
# Enrichment.
# ---------------------------------------------------------------------------
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

def registrable(domain: str):
    """Crudely split a domain into (label, tld) for scoring."""
    parts = domain.lower().split('.')
    if len(parts) < 2:
        return domain, ''
    return parts[-2], parts[-1]

def enrich(kind: str, value: str):
    tags = []
    if kind == 'ipv4' or kind == 'ipv6':
        try:
            ip = ipaddress.ip_address(value)
            if ip.is_private:    tags.append('private')
            elif ip.is_loopback: tags.append('loopback')
            elif ip.is_reserved: tags.append('reserved')
            elif ip.is_multicast:tags.append('multicast')
            else:                tags.append('public')
        except ValueError:
            tags.append('invalid')
    elif kind in ('md5', 'sha1', 'sha256'):
        tags.append({'md5': 'MD5', 'sha1': 'SHA-1', 'sha256': 'SHA-256'}[kind])
    elif kind == 'domain':
        label, tld = registrable(value)
        ent = shannon_entropy(label)
        if tld in SUSPICIOUS_TLDS:
            tags.append(f'suspicious-tld(.{tld})')
        if ent >= 3.5 and len(label) >= 10:
            tags.append(f'high-entropy({ent:.1f})-possible-DGA')
    return tags

def valid_domain(d: str) -> bool:
    tld = d.rsplit('.', 1)[-1].lower()
    if tld in FILE_EXTS:
        return False
    if re.fullmatch(r'\d+\.\d+', d):     # looks like a version number
        return False
    return True

# ---------------------------------------------------------------------------
# Core extraction.
# ---------------------------------------------------------------------------
def extract(text: str, drop_noise=False):
    refanged = refang(text)
    results = {}          # kind -> Counter(value -> occurrences)

    for kind, pat in PATTERNS.items():
        c = Counter()
        for m in pat.finditer(refanged):
            v = m.group(0)
            if kind in ('ipv4', 'ipv6'):
                try:
                    ipobj = ipaddress.ip_address(v)     # validates; kills timestamp false-positives
                except ValueError:
                    continue
                if drop_noise and not ipobj.is_global:
                    continue
            elif kind == 'domain':
                v = v.lower().rstrip('.')
                if not valid_domain(v):
                    continue
                if drop_noise and v in BENIGN:
                    continue
            elif kind == 'email':
                v = v.lower()
            c[v] += 1
        if c:
            results[kind] = c
    return results

# ---------------------------------------------------------------------------
# Output formats.
# ---------------------------------------------------------------------------
ORDER = ['ipv4','ipv6','domain','url','email','md5','sha1','sha256','cve','btc']
COLOR = {'ipv4':'\033[36m','ipv6':'\033[36m','domain':'\033[35m','url':'\033[34m',
         'email':'\033[32m','md5':'\033[33m','sha1':'\033[33m','sha256':'\033[33m',
         'cve':'\033[31m','btc':'\033[33m'}

def out_table(results, color=True):
    BOLD = '\033[1m' if color else ''
    DIM  = '\033[2m' if color else ''
    RST  = '\033[0m' if color else ''
    def col(kind): return COLOR.get(kind, '') if color else ''
    total = 0
    for kind in ORDER:
        if kind not in results:
            continue
        items = results[kind]
        total += len(items)
        print(f"\n{BOLD}{kind.upper()}{RST}  ({len(items)})")
        for value, n in items.most_common():
            tags = enrich(kind, value)
            tagstr = ('  ' + ' '.join(f'[{t}]' for t in tags)) if tags else ''
            cnt = f' x{n}' if n > 1 else ''
            print(f"  {col(kind)}{value}{RST}{cnt}{DIM}{tagstr}{RST}")
    print(f"\n{BOLD}summary:{RST} {total} unique indicators across {len(results)} types")

def out_json(results):
    doc = {}
    for kind, items in results.items():
        doc[kind] = [{'value': v, 'count': n, 'tags': enrich(kind, v)}
                     for v, n in items.most_common()]
    print(json.dumps(doc, indent=2))

def out_csv(results):
    w = csv.writer(sys.stdout)
    w.writerow(['type', 'value', 'count', 'tags'])
    for kind in ORDER:
        for v, n in results.get(kind, Counter()).most_common():
            w.writerow([kind, v, n, ';'.join(enrich(kind, v))])

STIX_PATTERN = {
    'ipv4':  lambda v: f"[ipv4-addr:value = '{v}']",
    'ipv6':  lambda v: f"[ipv6-addr:value = '{v}']",
    'domain':lambda v: f"[domain-name:value = '{v}']",
    'url':   lambda v: "[url:value = '%s']" % v.replace("'", "\\'"),
    'email': lambda v: f"[email-addr:value = '{v}']",
    'md5':   lambda v: f"[file:hashes.'MD5' = '{v}']",
    'sha1':  lambda v: f"[file:hashes.'SHA-1' = '{v}']",
    'sha256':lambda v: f"[file:hashes.'SHA-256' = '{v}']",
}

def out_stix(results):
    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')
    objects = []
    for kind, items in results.items():
        if kind not in STIX_PATTERN:
            continue
        for v in items:
            objects.append({
                'type': 'indicator',
                'spec_version': '2.1',
                'id': f'indicator--{uuid.uuid4()}',
                'created': now, 'modified': now,
                'name': f'{kind} {v}',
                'pattern': STIX_PATTERN[kind](v),
                'pattern_type': 'stix',
                'valid_from': now,
                'labels': ['malicious-activity'],
            })
    bundle = {'type': 'bundle', 'id': f'bundle--{uuid.uuid4()}', 'objects': objects}
    print(json.dumps(bundle, indent=2))

def defang_value(kind, v):
    if kind in ('url',):
        v = re.sub(r'^http', 'hxxp', v, flags=re.I)
    v = v.replace('.', '[.]').replace('@', '[at]')
    return v

def out_defanged(results):
    for kind in ORDER:
        for v, _ in results.get(kind, Counter()).most_common():
            print(f'{kind}\t{defang_value(kind, v)}')

# ---------------------------------------------------------------------------
def main():
    # Behave like a normal Unix filter when piped into head/grep/etc.
    try:
        import signal
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except (ImportError, AttributeError):
        pass

    ap = argparse.ArgumentParser(description='Extract, refang and enrich IOCs.')
    ap.add_argument('files', nargs='*', help='input files (default: stdin)')
    ap.add_argument('--json', action='store_true', help='JSON output')
    ap.add_argument('--csv', action='store_true', help='CSV output')
    ap.add_argument('--stix', action='store_true', help='STIX 2.1 bundle output')
    ap.add_argument('--defang', action='store_true', help='re-defang for safe sharing')
    ap.add_argument('--no-noise', action='store_true', help='drop benign/private indicators')
    ap.add_argument('--no-color', action='store_true', help='plain table output')
    args = ap.parse_args()

    if args.files:
        text = ''
        for f in args.files:
            with open(f, 'r', errors='replace') as fh:
                text += fh.read() + '\n'
    else:
        text = sys.stdin.read()

    results = extract(text, drop_noise=args.no_noise)

    if args.json:     out_json(results)
    elif args.csv:    out_csv(results)
    elif args.stix:   out_stix(results)
    elif args.defang: out_defanged(results)
    else:             out_table(results, color=not args.no_color and sys.stdout.isatty())

if __name__ == '__main__':
    main()
