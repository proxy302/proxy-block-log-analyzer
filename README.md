# proxy-block-log-analyzer: are blocks caused by my proxy IPs or by my scraper?

When requests through proxies start getting 403 or 429, the first question is whether the blocks follow particular exit IPs or ranges, or are spread across all of them. If they follow particular addresses or ranges, the site has flagged those, and you should stop using them. If they are spread evenly, the cause is how you send requests (rate, headers, sessions), and new IPs will be blocked too. You can only answer that if you log the exit IP with each request. `analyze_blocks.py` reads such a log, ranks exit IPs and /24 ranges by block rate, and prints a one-paragraph verdict.

Proxy302 maintains this tool and sells proxies. Rotating residential traffic starts at $1.50 per GB if you need more exits to compare ([prices](https://proxy302.com/pricing/)). The analyzer works on logs from any provider.

## Usage

```bash
git clone https://github.com/proxy302/proxy-block-log-analyzer
cd proxy-block-log-analyzer
python3 analyze_blocks.py example-log.tsv
python3 analyze_blocks.py my-run.csv --ip-col exit_ip --status-col status --blocked 403,429,503
```

Python 3.8 or later, standard library only. The log can be TSV or CSV with a header row. It needs one column with the exit IP and one with the HTTP status; anything non-numeric in the status column (for example `ReadTimeout`) is counted as a connection error.

## Getting the exit IP into your log

Look the exit up once per session through the proxy (for example `GET https://api.ipify.org`) and write it next to every request on that session. On sticky sessions one lookup per session is enough; on gateways that rotate per connection, keep the session's connection open or look up again per task.

## Example

`example-log.tsv` is a made-up log for trying the tool, using documentation address ranges. Output:

```
requests: 600   blocked (403, 429): 114 (19%)   exit IPs: 30   ranges: 2
connection errors: ReadTimeout 5

worst exit IPs
                       requests  blocked   rate
  198.51.100.41              18       13    72%
  198.51.100.48              23       12    52%
  198.51.100.44              16       12    75%
  198.51.100.47              15       12    80%
  198.51.100.43              27       11    41%

worst ranges (/24 for IPv4)
                       requests  blocked   rate
  198.51.100.0/24           174      103    59%
  203.0.113.0/24            426       11     3%

verdict:
  blocks are concentrated in 198.51.100.0/24: 90% of all blocks, blocked 59% of the time there vs 3% elsewhere. That range is flagged on this site; avoid it rather than slowing down.
```

## How the verdict is decided

- **Concentrated in a range:** one range holds at least half of all blocks and is blocked at least three times as often as everything else.
- **Concentrated on a few IPs:** the worst tenth of IPs hold at least half of the blocks while the median IP is rarely blocked.
- **Spread out:** the median IP is blocked 20% of the time or more. Change the request pattern before buying more IPs.
- **Mixed:** none of the above clearly applies; start with the worst ranges and lower the rate.

IPs with fewer than `--min-requests` requests (default 5) are left out of the verdict so one unlucky request does not decide it.

## FAQ

**Which status codes count as blocked?** 403 and 429 by default. Add others with `--blocked`, for example 503 for sites that answer bot checks with it.

**What about CAPTCHA pages that return 200?** Mark them yourself when logging (for example write `captcha` in the status column and pass `--blocked 403,429,captcha`).

**My log has no exit IPs.** Then this tool cannot help; add the lookup described above and run the job again for an hour.

*Facts checked 20 November 2026.*
