# Adult Lists

A plain-text list of adult website domains, for either blocking at the network level with tools such as UniFi gateways and Pi-hole - or for redirecting traffic to these domains over a VPN.

## What's in here

| File | Description |
| --- | --- |
| `list.txt` | Around 13,200 domains, one per line, sorted, no comments or wildcards |
| `tools/domains.py` | Imports new domains into `list.txt` and checks the list is valid |
| `tests/` | Unit tests for the tool |

Each line is a bare hostname:

```
007angels.com
00webcams.com
www.example-site.com
```

## Where the list came from

The list is derived from [emiliodallatorre/adult-hosts-list](https://github.com/emiliodallatorre/adult-hosts-list) ([original `list.txt`](https://raw.githubusercontent.com/emiliodallatorre/adult-hosts-list/refs/heads/main/list.txt)). All credit for compiling it goes to that project.

## What was changed

UniFi rejects a list if it contains entries that aren't valid domain names, so the upstream list was cleaned. A dozen entries were removed:

| Removed entry | Reason |
| --- | --- |
| `85.17.187.83` | IP address, not a domain |
| `collectionofbestporn` | No top-level domain |
| `hdgaytube.xxx!` | Invalid character |
| `hentaiporns.net.`, `pornid.xxx.` | Trailing dot |
| `forgotten_dark_angel.tripod.com`, `topmodel_virginie.cmonbook.com` | Underscore in hostname |
| `free--webcams.com`, `magnetic--blue.tumblr.com`, `x--x--x.com`, `www.x--x--x.com`, `top.x--x--x.com` | Consecutive hyphens |

Every remaining line contains only lowercase letters, digits, dots and hyphens, and there are no duplicates.

Domains from other sources have since been added with the import tool below.

## Adding domains

`tools/domains.py` merges new domains into `list.txt`. It needs Python 3.9 or later and nothing else.

```
tools/domains.py import new-sites.txt --check-active
tools/domains.py import https://example.org/some-blocklist.txt --dry-run
tools/domains.py lint
```

A source can be a file, an `http(s)` URL, or `-` for stdin. Plain domain lists, hosts files, Adblock-style lists, dnsmasq configs and lists of URLs are all understood. Each entry is lower-cased, stripped of any scheme, path, port or trailing dot, then:

1. **Validated against what UniFi accepts.** An entry is rejected if it is an IP address, contains an underscore or a double dash (`--`), ends in anything other than a letter or digit, or is otherwise not a well-formed domain. This also rejects internationalised (`xn--`) domains.
2. **De-duplicated** against the rest of the input and against `list.txt`.
3. **Given a `www.` form.** For each main domain in the input (`example.com`, `example.co.uk`), `www.example.com` is added too, even if the bare domain is already in the list. Subdomains such as `blog.example.com` are left alone. Use `--no-www` to turn this off.
4. **Checked for activity**, with `--check-active`. A domain is kept only if it resolves in public DNS and something accepts a connection on port 443 or 80. Lookups go to Cloudflare's DNS-over-HTTPS service, so local DNS blocking doesn't affect the result.

The survivors are merged into `list.txt` in sorted order. Rejected entries are printed with the reason; `--report FILE` writes all of them to a file, and `--dry-run` shows the outcome without changing the list.

`lint` checks that `list.txt` is valid, sorted and free of duplicates. Run the tests with:

```
python3 -m unittest discover -s tests
```

## Using the list

### Pi-hole

Add the raw URL of `list.txt` as a blocklist (**Lists** in the admin interface, or **Adlists** in older versions), then update gravity:

```
pihole -g
```

### UniFi

Import or paste the contents of `list.txt` wherever your UniFi Network version accepts a list of domains to block, such as a domain-based traffic or firewall rule, or the DNS content filter's block list. The exact location varies between Network versions.

### Anything else

The format is a plain list of domains, which most DNS blockers (AdGuard Home, Technitium, NextDNS and similar) accept directly.

## Limitations

- Entries match exact hostnames. `example.com` and `www.example.com` are separate entries, and other subdomains are only blocked if your blocker treats entries as wildcards.
- DNS blocking is bypassed by VPNs, by devices using their own DNS-over-HTTPS resolver, and by any site not on the list.
- The list is a snapshot. New sites appear constantly and some listed domains will have lapsed or changed hands.

## Contributing

Open an issue or pull request to add or remove a domain. Add domains with `tools/domains.py import` so the list stays valid and sorted.
