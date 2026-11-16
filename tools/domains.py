#!/usr/bin/env python3
"""Import, validate and de-duplicate domains for list.txt.

Usage:
    tools/domains.py import SOURCE [SOURCE ...] [--check-active] [--dry-run]
    tools/domains.py lint

A SOURCE is a file path, an http(s) URL, or "-" for stdin. Sources may be plain
domain lists, hosts files, Adblock-style lists, dnsmasq configs or lists of URLs.

Standard library only; needs Python 3.9+.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import sys
import tempfile
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

DEFAULT_LIST = Path(__file__).resolve().parent.parent / "list.txt"
DOH_URL = "https://cloudflare-dns.com/dns-query"
USER_AGENT = "domain-list-importer"

# Names that appear in hosts files but are never real entries.
HOSTS_NOISE = {
    "localhost", "localhost.localdomain", "local", "broadcasthost",
    "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
    "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0",
}

# Second-level labels that act as part of the suffix under a country code
# (example.co.uk), so "www." still belongs in front of a three-label name.
SECOND_LEVEL = {"co", "com", "net", "org", "ac", "gov", "edu", "or", "ne", "go"}

_DNSMASQ = re.compile(r"^(?:address|server|local)=/([^/]+)/")
_ALLOWED = re.compile(r"^[a-z0-9.-]+$")


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.strip("[]"))
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------
# Parsing: turn one line of any supported format into candidate domains
# --------------------------------------------------------------------------

def extract(line: str) -> list[str]:
    """Return the candidate domains found on one line of a source list.

    Candidates are lower-cased and stripped of list syntax (hosts-file IPs,
    Adblock markers, URL schemes, paths and ports) but are NOT validated.
    """
    line = line.strip().lstrip("﻿")
    if not line or line[0] in "#!" or line.startswith("@@") or line.startswith("["):
        return []
    line = line.split("#", 1)[0].strip()  # inline comment
    if not line:
        return []

    match = _DNSMASQ.match(line)
    if match:
        tokens = [match.group(1)]
    else:
        tokens = line.split()
        # hosts file: "0.0.0.0 a.com b.com". A lone IP is kept so it is
        # reported as rejected rather than silently dropped.
        if len(tokens) > 1 and _is_ip(tokens[0]):
            tokens = tokens[1:]
        else:
            tokens = tokens[:1]

    return [c for c in (_clean(t) for t in tokens) if c and c not in HOSTS_NOISE]


def _clean(token: str) -> str:
    token = token.lower()
    if token.startswith("||"):  # Adblock: ||example.com^$third-party
        token = token[2:].split("^", 1)[0]
    if "://" in token:
        token = token.split("://", 1)[1]
    token = re.split(r"[/?]", token, maxsplit=1)[0]  # path, query
    token = token.rsplit("@", 1)[-1]  # userinfo
    if token.startswith("*."):
        token = token[2:]
    if not _is_ip(token):
        token = re.sub(r":\d+$", "", token)  # port
    if token.endswith(".") and not token.endswith(".."):
        token = token[:-1]  # fully-qualified form of the same name
    return token


# --------------------------------------------------------------------------
# Validation: the rules UniFi OS enforces, plus basic hostname sanity
# --------------------------------------------------------------------------

def invalid_reason(domain: str) -> str | None:
    """Return why UniFi would reject this domain, or None if it is acceptable."""
    if _is_ip(domain):
        return "IP address"
    if "_" in domain:
        return "underscore"
    if "--" in domain:
        return "double dash"
    if not domain[-1:].isalnum() or not domain[-1:].isascii():
        return "ends in invalid character"
    if not _ALLOWED.match(domain):
        return "invalid character"
    labels = domain.split(".")
    if len(labels) < 2:
        return "no top-level domain"
    if any(not label for label in labels):
        return "empty label"
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        return "label starts or ends with a dash"
    if len(domain) > 253 or any(len(label) > 63 for label in labels):
        return "too long"
    if not labels[-1].isalpha() or len(labels[-1]) < 2:
        return "invalid top-level domain"
    return None


def www_variant(domain: str) -> str | None:
    """Return "www." + domain for a site's main domain, or None for names that
    are already subdomains (blog.example.com, www.example.com)."""
    labels = domain.split(".")
    main = len(labels) == 2 or (
        len(labels) == 3 and len(labels[2]) == 2 and labels[1] in SECOND_LEVEL
    )
    if not main or labels[0] == "www":
        return None
    variant = "www." + domain
    return None if invalid_reason(variant) else variant


# --------------------------------------------------------------------------
# Activity check: public DNS, then a TCP connection to the web ports
# --------------------------------------------------------------------------

def resolve(domain: str, timeout: float = 8.0) -> list[str] | None:
    """Resolve via DNS-over-HTTPS, bypassing any local DNS blocking.

    Returns a list of addresses (empty if the name does not exist) or None if
    the lookup itself failed.
    """
    addresses: list[str] = []
    for rtype, code in (("A", 1), ("AAAA", 28)):
        query = urllib.parse.urlencode({"name": domain, "type": rtype})
        request = urllib.request.Request(
            f"{DOH_URL}?{query}",
            headers={"Accept": "application/dns-json", "User-Agent": USER_AGENT},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                reply = json.load(response)
        except (OSError, ValueError):
            return None
        if reply.get("Status") == 3:  # NXDOMAIN
            return []
        if reply.get("Status") != 0:
            return None
        for answer in reply.get("Answer", []):
            if answer.get("type") != code:
                continue
            try:
                ip = ipaddress.ip_address(answer["data"])
            except ValueError:
                continue
            if ip.is_global:  # ignores 0.0.0.0, loopback and private sinkholes
                addresses.append(str(ip))
        if addresses:
            break
    return addresses


def accepts_web_connection(addresses: list[str], timeout: float = 6.0) -> bool:
    for address in addresses[:2]:
        for port in (443, 80):
            try:
                with socket.create_connection((address, port), timeout=timeout):
                    return True
            except OSError:
                continue
    return False


def activity(domain: str, resolver=resolve, connector=accepts_web_connection) -> str:
    """Classify a domain as 'active', 'no DNS record', 'no web server' or
    'lookup failed'."""
    addresses = resolver(domain)
    if addresses is None:
        addresses = resolver(domain)  # one retry
    if addresses is None:
        return "lookup failed"
    if not addresses:
        return "no DNS record"
    return "active" if connector(addresses) else "no web server"


def check_activity(domains: list[str], workers: int = 16, checker=activity) -> dict[str, str]:
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return dict(zip(domains, pool.map(checker, domains)))


# --------------------------------------------------------------------------
# Import pipeline
# --------------------------------------------------------------------------

def process(lines, existing: set[str], add_www: bool = True) -> tuple[list[str], list[tuple[str, str]]]:
    """Split source lines into new valid domains and (entry, reason) rejects.

    With add_www, the "www." form of every valid main domain in the input is
    added as well, including for domains that are already in the list.
    """
    new: set[str] = set()
    valid: list[str] = []
    rejected: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in lines:
        for candidate in extract(line):
            if candidate in seen:
                rejected.append((candidate, "duplicate in input"))
                continue
            seen.add(candidate)
            reason = invalid_reason(candidate)
            if reason:
                rejected.append((candidate, reason))
                continue
            valid.append(candidate)
            if candidate in existing:
                rejected.append((candidate, "already in list"))
            else:
                new.add(candidate)
    if add_www:
        for candidate in valid:
            variant = www_variant(candidate)
            if variant and variant not in existing:
                new.add(variant)
    return sorted(new), rejected


def read_source(source: str) -> list[str]:
    if source == "-":
        return sys.stdin.read().splitlines()
    if re.match(r"^https?://", source, re.I):
        request = urllib.request.Request(source, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.read().decode("utf-8", "replace").splitlines()
    return Path(source).read_text(encoding="utf-8", errors="replace").splitlines()


def read_list(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line]


def write_list(path: Path, domains) -> None:
    handle, temp = tempfile.mkstemp(dir=path.parent, prefix=".list-", suffix=".tmp")
    with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as out:
        out.write("\n".join(sorted(set(domains))) + "\n")
    os.replace(temp, path)


def cmd_import(args) -> int:
    existing = read_list(args.list)
    lines: list[str] = []
    for source in args.sources:
        lines.extend(read_source(source))

    new, rejected = process(lines, set(existing), add_www=not args.no_www)

    if args.check_active and new:
        print(f"Checking {len(new)} new domains are active...", file=sys.stderr)
        status = check_activity(new, workers=args.workers)
        rejected.extend((d, s) for d, s in status.items() if s != "active")
        new = [d for d in new if status[d] == "active"]

    counts = Counter(reason for _, reason in rejected)
    print(f"Candidates read:  {len(new) + len(rejected)}")
    print(f"Rejected:         {len(rejected)}")
    for reason, count in counts.most_common():
        print(f"  {count:>7}  {reason}")
    print(f"New domains:      {len(new)}")

    shown = [r for r in rejected if r[1] not in ("already in list", "duplicate in input")]
    if shown and not args.report:
        print("\nRejected entries:")
        for entry, reason in shown[:40]:
            print(f"  {entry}  ({reason})")
        if len(shown) > 40:
            print(f"  ... and {len(shown) - 40} more; use --report FILE for all of them")
    if args.report:
        with open(args.report, "w", encoding="utf-8") as out:
            out.writelines(f"{entry}\t{reason}\n" for entry, reason in rejected)
        print(f"\nFull reject report written to {args.report}")

    if new:
        print("\nNew domains:")
        for domain in new[:60]:
            print(f"  {domain}")
        if len(new) > 60:
            print(f"  ... and {len(new) - 60} more")

    if args.dry_run:
        print(f"\nDry run: {args.list.name} not changed.")
    elif new:
        write_list(args.list, existing + new)
        print(f"\n{args.list.name} now has {len(set(existing + new))} domains.")
    else:
        print(f"\nNothing to add; {args.list.name} not changed.")
    return 0


def lint(lines: list[str]) -> list[str]:
    """Return a list of problems with an existing list file's lines."""
    problems = []
    for number, line in enumerate(lines, 1):
        reason = "blank line" if not line else invalid_reason(line)
        if not reason and line != line.lower():
            reason = "not lower case"
        if reason:
            problems.append(f"line {number}: {line!r}: {reason}")
    for domain, count in Counter(lines).items():
        if count > 1 and domain:
            problems.append(f"{domain!r} appears {count} times")
    if lines != sorted(lines):
        problems.append("list is not sorted")
    return problems


def cmd_lint(args) -> int:
    text = args.list.read_text(encoding="utf-8")
    lines = text.split("\n")
    problems = []
    if lines and lines[-1] == "":
        lines.pop()
    else:
        problems.append("file does not end with a newline")
    problems += lint(lines)
    for problem in problems:
        print(problem)
    print(f"{args.list.name}: {len(lines)} domains, {len(problems)} problems")
    return 1 if problems else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--list", type=Path, default=DEFAULT_LIST,
                        help="list file to maintain (default: list.txt in the repo root)")
    commands = parser.add_subparsers(dest="command", required=True)

    imp = commands.add_parser("import", help="add new valid domains from one or more sources")
    imp.add_argument("sources", nargs="+", metavar="SOURCE", help="file, http(s) URL, or - for stdin")
    imp.add_argument("--check-active", action="store_true",
                     help="only add domains that resolve in public DNS and accept a web connection")
    imp.add_argument("--no-www", action="store_true",
                     help="do not also add the www. form of each main domain")
    imp.add_argument("--dry-run", action="store_true", help="report what would change without writing")
    imp.add_argument("--report", metavar="FILE", help="write every rejected entry and its reason to FILE (TSV)")
    imp.add_argument("--workers", type=int, default=16, help="parallel activity checks (default: 16)")
    imp.set_defaults(func=cmd_import)

    lnt = commands.add_parser("lint", help="check the list is valid, sorted and free of duplicates")
    lnt.set_defaults(func=cmd_lint)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
