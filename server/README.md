# Server setup

The relay is four pieces:

1. **A wildcard TLS certificate** for `*.example.com`
2. **frps** — accepts client connections and routes by `Host` header
3. **A TLS-terminating proxy** that sends unregistered subdomains to frps
4. **ktunneld** — per-user tokens, subdomain ownership, dashboard

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
- A freshly created dedyn.io zone can take a while to be delegated by its
  parent; DNSSEC-validating resolvers answer SERVFAIL until then.

Run [`reload-nginx-if-cert-changed.sh`](reload-nginx-if-cert-changed.sh) daily
from cron — nginx keeps the old certificate in memory until it is reloaded.

## 2. frps

```bash
cp frps.toml.example frps.toml
docker compose up -d
```

Expose **only** `bindPort` (7000) to the internet. Keep the dashboard on
`127.0.0.1`. Note that the example has **no `auth.token`**: authentication is
handed to ktunneld through the `[[httpPlugins]]` block, so there is no shared
secret for clients to hold.

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

## 4. ktunneld

One static binary and one SQLite file. It listens on two loopback ports:

| port | what | reachable from |
|---|---|---|
| `7601` | frps plugin hook (`POST /frp`) | frps only — never proxy this |
| `7600` | administrator and user web portal | TLS proxy (`ktunnel.kkensu.com`) |

Keeping the hook on a separate port is what stops the dashboard's public
hostname from also exposing the authentication endpoint.

```bash
mkdir -p /srv/ktunneld/data && cp ktunneld-linux-amd64 /srv/ktunneld/ktunneld
docker run -d --name ktunneld --restart unless-stopped --network host \
  -v /srv/ktunneld:/app -e KTUNNELD_DB=/app/data/ktunneld.db \
  alpine:3.20 /app/ktunneld serve \
    --web 127.0.0.1:7600 --plugin 127.0.0.1:7601 \
    --server relay.example.com --port 7000 --domain example.com \
    --tcp-range 20000-29999
```

`--server/--port/--domain` are what gets baked into every token, so a user only
ever needs `ktunnel login <token>`. `--tcp-range` is the window `tcp` tunnels
may claim on the relay — keep it away from anything real, and remember that on
a DMZ every port in it is internet-facing.

Then, through `docker exec ktunneld /app/ktunneld …`:

```bash
ktunneld admin set-password            # login as the fixed "admin" account
ktunneld user add alice
ktunneld token issue alice --label laptop
```

### frps side

Add to `frps.toml` and remove any `auth.token`:

```toml
[[httpPlugins]]
name = "ktunneld"
addr = "http://127.0.0.1:7601"
path = "/frp"
ops  = ["Login", "NewProxy", "Ping", "CloseProxy"]
```

Start ktunneld **before** restarting frps: with the plugin unreachable, frps
fails closed and refuses every login.

### Web portal

Publish `127.0.0.1:7600` as `https://ktunnel.kkensu.com` with
[`nginx-dashboard.conf`](nginx-dashboard.conf) — on DSM, register it with
`synow3tool` exactly like the wildcard block. The example also sends the old
`tunnel-admin.kkensu.com` hostname to the canonical URL with a 308 redirect.

Sign in as `admin`, create a user, and securely deliver the temporary password
shown once. Users sign in on the same page, must change the temporary password,
and then issue their own one-time-display tunnel tokens. There is no sign-up.
Existing users have no web password after migration until an administrator
opens the user and issues one. Existing tunnel tokens continue to work.

Do not publish the dashboard through a tunnel: frps's vhost proxy rewrites
`X-Forwarded-Proto` to `http`, so the session cookie would never be `Secure`,
and the admin UI would go down with the very components it manages. The block
also *overwrites* `X-Forwarded-For` — ktunneld keys its login lockout on
`X-Real-IP`, and an appended header would let a client choose its own key.

Sessions are cookie-based, `HttpOnly`, `SameSite=Strict`, and `Secure` when the
proxy sets `X-Forwarded-Proto: https`. Five failed logins from one address
lock it out for a minute.

### Backups and rollback

State is the single SQLite file (`data/ktunneld.db`, WAL mode). Copy it while
ktunneld runs — WAL makes that safe — or `docker exec ktunneld /app/ktunneld
token ls` to check what you would lose.

To go back to a shared-secret frps: restore the previous `frps.toml`
(with `auth.token`), restart frps, stop ktunneld. Clients would need the shared
token again; `ktunnel` v0.2 or earlier speaks that model.

## Verifying

```bash
# from outside your own network — a LAN test only proves hairpin NAT
curl -sI https://anything-unused.example.com | head -1     # 404 from frps = wired up
docker exec ktunneld /app/ktunneld ls                       # after a client connects
docker logs ktunneld | tail                                 # "login ok" / "proxy ok" / rejections
```
