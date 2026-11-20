#!/usr/bin/env python3
"""analyze_blocks: do blocks follow certain proxy IPs, or your whole request pattern?

Reads a TSV or CSV log with a header row that has an exit IP column and a
status column (HTTP status code, or an error name such as ReadTimeout), then
reports block rates per exit IP and per /24 range and gives a verdict.
Standard library only.

  python3 analyze_blocks.py requests.tsv
  python3 analyze_blocks.py requests.csv --ip-col exit_ip --status-col status --blocked 403,429
"""
import argparse
import collections
import csv
import ipaddress
import statistics
import sys


def range_of(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    net = ipaddress.ip_network(f"{ip}/24" if a.version == 4 else f"{ip}/48", strict=False)
    return str(net)


def table(title, stats, limit):
    rows = sorted(stats.items(), key=lambda kv: (-kv[1][1], -kv[1][0]))[:limit]
    print(f"\n{title}")
    print(f"  {'':<20} {'requests':>8} {'blocked':>8} {'rate':>6}")
    for key, (n, b) in rows:
        print(f"  {key:<20} {n:>8} {b:>8} {b / n:>6.0%}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("log")
    ap.add_argument("--ip-col", default="exit_ip")
    ap.add_argument("--status-col", default="status")
    ap.add_argument("--blocked", default="403,429", help="status codes that count as blocked (default 403,429)")
    ap.add_argument("--min-requests", type=int, default=5, help="ignore IPs with fewer requests in the verdict (default 5)")
    ap.add_argument("--top", type=int, default=10)
    a = ap.parse_args()

    blocked_codes = {c.strip() for c in a.blocked.split(",") if c.strip()}
    with open(a.log, newline="", encoding="utf-8") as f:
        sample = f.read(4096); f.seek(0)
        dialect = csv.excel_tab if "\t" in sample.splitlines()[0] else csv.excel
        reader = csv.DictReader(f, dialect=dialect)
        missing = {a.ip_col, a.status_col} - set(reader.fieldnames or [])
        if missing:
            sys.exit(f"columns not found: {', '.join(sorted(missing))}; header is {reader.fieldnames}")
        per_ip = collections.defaultdict(lambda: [0, 0])
        per_range = collections.defaultdict(lambda: [0, 0])
        errors = collections.Counter()
        for row in reader:
            ip, status = row[a.ip_col].strip(), row[a.status_col].strip()
            if not ip:
                continue
            is_blocked = status in blocked_codes
            if not status.isdigit():
                errors[status] += 1
            for d, key in ((per_ip, ip), (per_range, range_of(ip))):
                d[key][0] += 1
                d[key][1] += is_blocked

    total = sum(n for n, _ in per_ip.values())
    blocked = sum(b for _, b in per_ip.values())
    if not total:
        sys.exit("no rows with an exit IP")
    print(f"requests: {total}   blocked ({', '.join(sorted(blocked_codes))}): {blocked} ({blocked / total:.0%})   "
          f"exit IPs: {len(per_ip)}   ranges: {len(per_range)}")
    if errors:
        print("connection errors: " + ", ".join(f"{k} {v}" for k, v in errors.most_common(5)))
    table("worst exit IPs", per_ip, a.top)
    table("worst ranges (/24 for IPv4)", per_range, a.top)

    eligible = {k: v for k, v in per_ip.items() if v[0] >= a.min_requests}
    print("\nverdict:")
    if blocked == 0:
        print("  no blocks in this log.")
        return
    if len(eligible) < 3:
        print(f"  too few IPs with at least {a.min_requests} requests to tell; collect more data.")
        return
    worst_range, (rn, rb) = max(per_range.items(), key=lambda kv: kv[1][1])
    if len(per_range) > 1 and rn < total:
        rest_rate = (blocked - rb) / (total - rn)
        if rb / blocked >= 0.5 and rb / rn >= 3 * max(rest_rate, 0.01):
            print(f"  blocks are concentrated in {worst_range}: {rb / blocked:.0%} of all blocks, blocked {rb / rn:.0%} of the time "
                  f"there vs {rest_rate:.0%} elsewhere. That range is flagged on this site; avoid it rather than slowing down.")
            return
    rates = sorted((b / n for n, b in eligible.values()), reverse=True)
    worst = max(1, len(rates) // 10)
    blocks_sorted = sorted((b for _, b in eligible.values()), reverse=True)
    share_worst = sum(blocks_sorted[:worst]) / max(1, sum(blocks_sorted))
    median_rate = statistics.median(rates)
    if share_worst >= 0.5 and median_rate < 0.1:
        print(f"  blocks are concentrated: the worst {worst} IP(s) hold {share_worst:.0%} of blocks while the median IP is "
              f"blocked {median_rate:.0%} of the time. Those addresses or ranges are flagged on this site; stop using them.")
    elif median_rate >= 0.2:
        print(f"  blocks are spread across most IPs (median IP blocked {median_rate:.0%} of the time). "
              "The cause is likely the request pattern (rate, headers, session handling), not specific IPs.")
    else:
        print(f"  mixed picture: median IP blocked {median_rate:.0%}, worst {worst} IP(s) hold {share_worst:.0%} of blocks. "
              "Look at the worst ranges first, then slow the request rate and compare.")


if __name__ == "__main__":
    main()
