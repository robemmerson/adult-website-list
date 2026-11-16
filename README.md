# adult_lists

A plain-text list of adult website domains, for blocking at the network level with tools such as UniFi gateways and Pi-hole.

## What's in here

| File | Description |
| --- | --- |
| `list.txt` | 13,173 domains, one per line, sorted, no comments or wildcards |

Each line is a bare hostname:

```
007angels.com
00webcams.com
www.example-site.com
```

## Where the list came from

The list is derived from [emiliodallatorre/adult-hosts-list](https://github.com/emiliodallatorre/adult-hosts-list) ([original `list.txt`](https://raw.githubusercontent.com/emiliodallatorre/adult-hosts-list/refs/heads/main/list.txt)). All credit for compiling it goes to that project.

## What was changed

UniFi rejects a list if it contains entries that aren't valid domain names, so the upstream list was cleaned. A dozen entries were removed and nothing was added:

| Removed entry | Reason |
| --- | --- |
| `85.17.187.83` | IP address, not a domain |
| `collectionofbestporn` | No top-level domain |
| `hdgaytube.xxx!` | Invalid character |
| `hentaiporns.net.`, `pornid.xxx.` | Trailing dot |
| `forgotten_dark_angel.tripod.com`, `topmodel_virginie.cmonbook.com` | Underscore in hostname |
| `free--webcams.com`, `magnetic--blue.tumblr.com`, `x--x--x.com`, `www.x--x--x.com`, `top.x--x--x.com` | Consecutive hyphens |

Every remaining line contains only lowercase letters, digits, dots and hyphens, and there are no duplicates.

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

Open an issue or pull request to add or remove a domain. Keep entries to one valid hostname per line, lowercase, in sorted order.
