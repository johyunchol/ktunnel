# Server setup

The server side is three pieces:

1. **A wildcard TLS certificate** for `*.example.com`
2. **frps** — accepts client connections and routes by `Host` header
3. **A TLS-terminating proxy** that sends unregistered subdomains to frps

## 1. Wildcard certificate

Wildcards can only be validated with the **DNS-01** challenge — HTTP-01 cannot
prove control of infinitely many subdomains. That means your ACME client needs
API access to your DNS provider.

If your DNS provider has no API (many regional registrars don't), delegate just
the challenge record to one that does:

```
# one static record at your provider, added once and never touched again
_acme-challenge.example.com.  CNAME  _acme-challenge.your-alias.dedyn.io.
```

Then issue against the alias:

```bash
docker run --rm -v /srv/acme:/acme.sh \
  -e DEDYN_TOKEN="..." -e DEDYN_NAME="your-alias.dedyn.io" \
  neilpang/acme.sh --issue --dns dns_desec \
  -d 'example.com' -d '*.example.com' \
  --challenge-alias your-alias.dedyn.io \
  --server letsencrypt
```

> Rehearse with `--server letsencrypt_test` first. Failed attempts against the
> production endpoint still consume rate limit (50 certs per registered domain
> per week), and hitting it blocks renewals for every other host on the domain.

Gotchas worth knowing up front:

- `--challenge-alias X` makes acme.sh write TXT to `_acme-challenge.X`, so the
  CNAME target needs that prefix — not bare `X`.
- A name cannot hold both a CNAME and any other record type. Delete leftover
  `_acme-challenge` TXT records before adding the CNAME.
- The alias target must actually resolve; some DNS UIs validate this.
- `*.example.com` covers one label only. `a.b.example.com` needs its own
  `*.b.example.com` entry in the certificate.

Run [`reload-nginx-if-cert-changed.sh`](reload-nginx-if-cert-changed.sh) daily
from cron — nginx keeps the old certificate in memory until it is reloaded.

## 2. frps

```bash
cp frps.toml.example frps.toml
openssl rand -hex 32          # paste into auth.token
docker compose up -d
```

Expose **only** `bindPort` (7000) to the internet. Keep the dashboard on
`127.0.0.1`.

## 3. Wildcard vhost

Point [`nginx-tunnel-wildcard.conf`](nginx-tunnel-wildcard.conf) at your
certificate and load it.

nginx resolves exact `server_name` matches before wildcards, so existing hosts
keep working untouched — only names nothing else claims reach frps.

### Synology DSM

DSM's reverse-proxy UI rejects wildcard hostnames, and so does the JSON its API
writes — `synow3tool` refuses to render the config. Register the nginx site
directly instead:

```bash
sudo synow3tool --reg-nginx-sites=/volume1/docker/frp/tunnel-wildcard.conf
sudo synow3tool --enable-nginx-sites=tunnel-wildcard.conf
sudo nginx -t && sudo synosystemctl reload nginx
```

To roll back:

```bash
sudo synow3tool --disable-nginx-sites=tunnel-wildcard.conf
sudo synosystemctl reload nginx
```

## Verifying

```bash
# from outside your own network — a LAN test only proves hairpin NAT
curl -sI https://anything-unused.example.com | head -1     # 404 from frps = wired up
```
