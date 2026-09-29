# ioctopus

![Language: Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Dependencies: none](https://img.shields.io/badge/deps-stdlib_only-green.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)

A threat-intelligence tool that **extracts, refangs, enriches, and exports
indicators of compromise (IOCs)** from unstructured text — a threat report, a
blog post, an email, a log dump. It turns "here's a PDF about the campaign" into
structured, deduplicated, tagged indicators you can feed into a SIEM or share as
STIX. Zero dependencies (Python standard library only).

```
$ ioctopus report.txt
IPV4  (4)
  45.138.12.99  [public]
  192.168.1.50  [private]

DOMAIN  (4)
  drift-invoices.com x2
  x7f3k9q2ml4vn8p1.xyz  [suspicious-tld(.xyz)] [high-entropy(4.0)-possible-DGA]

SHA256  (1)
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  [SHA-256]

CVE  (1)
  CVE-2024-3400

summary: 17 unique indicators across 10 types
```

## What it does

- **Refangs** the ways analysts neuter live IOCs for safe sharing:
  `hxxp://evil[.]com` → `http://evil.com`, `1.1.1[.]1` → `1.1.1.1`,
  `user[at]evil[.]com` → `user@evil.com`, `[dot]`, `(.)`, `[:]`, and more.
- **Extracts** IPv4, IPv6, domains, URLs, emails, MD5 / SHA-1 / SHA-256 hashes,
  CVE IDs, and Bitcoin addresses.
- **Enriches** each indicator:
  - IPs tagged `public` / `private` / `loopback` / `reserved`.
  - Hashes labelled by type (length).
  - Domains scored for **Shannon entropy** and flagged
    `high-entropy-possible-DGA` — the same signal that betrays DNS tunneling and
    domain-generation algorithms — plus a `suspicious-tld` tag for abused TLDs.
- **De-noises**: drops filenames that look like domains (`report.pdf`,
  `config.json`), and with `--no-noise`, benign domains and non-global IPs.
- **Exports** to a colored **table**, **JSON**, **CSV**, or a **STIX 2.1
  bundle** of indicator objects — and can **re-defang** everything for safe
  distribution in your own report.

## Install & use

Needs only Python 3.8+. Nothing to install.

```sh
git clone https://github.com/b17w1z4rd/ioctopus.git
cd ioctopus

./ioctopus.py report.txt              # or: python3 ioctopus.py report.txt
cat report.txt | ./ioctopus.py        # reads stdin too
make test                             # extract from the bundled sample + checks
```

Feeding it a PDF? Pipe it through `pdftotext`:

```sh
pdftotext campaign.pdf - | ./ioctopus.py --stix > iocs.json
```

## Options

| Flag         | Output                                             |
|--------------|----------------------------------------------------|
| *(none)*     | colored table grouped by type, with tags + counts  |
| `--json`     | structured JSON (value, count, tags)               |
| `--csv`      | `type,value,count,tags`                            |
| `--stix`     | a STIX 2.1 bundle of indicator SDOs                |
| `--defang`   | re-defang every IOC for safe sharing               |
| `--no-noise` | drop benign domains and non-global IPs             |
| `--no-color` | plain table                                        |

## The DGA / entropy angle

Algorithmically-generated C2 domains (`x7f3k9q2ml4vn8p1.xyz`) and DNS-tunneling
subdomains look random because they are — high per-character entropy. `ioctopus`
computes the Shannon entropy of each domain's registrable label and flags the
outliers, so a wall of indicators surfaces the machine-generated ones on sight.

## Project layout

| File                | What it is                                    |
|---------------------|-----------------------------------------------|
| `ioctopus.py`       | The whole tool — extract, refang, enrich, export. |
| `sample-report.txt` | A synthetic threat report for the demo/tests. |
| `Makefile`          | `run`, `test`, `clean`.                       |

## Notes & scope

- Defensive / CTI use. It reads text and structures indicators; it contacts
  nothing and executes nothing.
- IPv6 matching is deliberately conservative (full-form addresses; validated
  with `ipaddress`), to avoid matching timestamps.
- Refang/extraction is heuristic — review before blocking on any indicator.

## Roadmap

- [ ] Live enrichment (VirusTotal / AbuseIPDB / GreyNoise) behind `--enrich`
- [ ] MISP event export and OpenIOC output
- [ ] Auto-generate a starter YARA/Suricata rule from extracted hashes/domains
- [ ] Registrable-domain parsing via the public suffix list
- [ ] Per-source confidence + first/last-seen tracking across runs

## References

- [STIX 2.1](https://oasis-open.github.io/cti-documentation/stix/intro) — the CTI interchange standard
- [MITRE ATT&CK](https://attack.mitre.org/) · [MISP](https://www.misp-project.org/)
- The `iocextract` project, for prior art on refang heuristics

## License

MIT — see [LICENSE](LICENSE).
