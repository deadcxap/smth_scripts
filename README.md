# audit-net.sh

### Audit UFW / iptables / nftables / Docker interaction on Ubuntu 22.04/24.04

Default: short report + smoke test.

### Usage:

bash audit-net.sh [--full] [--no-smoke] [--smoke] [--port N]
    --full     : dump full nftables/iptables rules
    --no-smoke : skip the smoke test
    --smoke    : force smoke test (default already does it)
    --port N   : port for smoke test (default 12345)

## Run

```bash
bash <(curl -sL https://github.com/deadcxap/smth_scripts/raw/master/audit-net.sh)
```

---