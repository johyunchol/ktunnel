# Server setup

The relay is four pieces:

1. **A Let's Encrypt wildcard TLS certificate** for `*.example.com`
2. **frps** — accepts authenticated TLS client connections and routes by `Host` header
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

After the initial frps bootstrap in the next section, run
[`reload-nginx-if-cert-changed.sh`](reload-nginx-if-cert-changed.sh) from the
ACME renewal hook or cron. It validates the full chain against the same
pinned ISRG Root X1/X2 bundle as the client, requires at least seven days of
remaining validity, checks the hostname and private-key match, and atomically
replaces one combined PEM. It recreates only the `frps` Compose service and
automatically restores the previous PEM unless an authenticated TLS health
check succeeds:

```bash
SOURCE_CERT=/srv/acme/example.com/fullchain.cer \
SOURCE_KEY=/srv/acme/example.com/example.com.key \
RELAY_SERVER_NAME=relay.example.com \
RELAY_PEM_UID=1026 RELAY_PEM_GID=100 \
  ./reload-nginx-if-cert-changed.sh
```

`RELAY_SERVER_NAME` must equal the TLS name embedded in `kt2` tokens; the
helper verifies that the renewed certificate covers it and chains to the
repository's pinned [`isrg-root-bundle.pem`](isrg-root-bundle.pem). The relay
key must be an unencrypted PEM suitable for unattended frps startup; the
helper never prompts for a key password. Set `COMPOSE_FILE`, `RELAY_PEM`,
`STATE_FILE`, `LOCK_DIR`, `HEALTH_CONNECT`, or `DOCKER_BIN` when the defaults
beside the script do not match the deployment. When the helper runs as root,
set numeric `RELAY_PEM_UID` and `RELAY_PEM_GID` together to the same UID/GID
configured for the frps container; the helper rejects partial or nonnumeric
values and changes ownership before installation. `MIN_VALID_SECONDS`
defaults to `604800` (seven days). The host needs `openssl`, `timeout`, and
`flock` (util-linux), plus Docker Compose. `DOCKER_BIN` first honors an explicit
override, then `docker` on `PATH`, then Synology Container Manager's
`/var/packages/ContainerManager/target/usr/bin/docker`, and otherwise fails
closed. Set
`RELOAD_NGINX=1` only when the same renewed certificate is also used by nginx;
the helper runs `nginx -t` before changing anything, then reloads nginx after
frps restarts. Redirect the script's stdout/stderr in cron instead of placing a
production log path in the repository.

The renewal lock is a persistent 0600 regular file protected by a nonblocking
kernel `flock`. Its contents do not determine ownership, so a file left after a
crash or power loss is harmless. The helper intentionally never deletes it,
which avoids an inode-unlink race. (`LOCK_DIR` remains the environment-variable
name for compatibility, but its value is a file path.) The
state hash is only a cache hint. Even when it matches, the helper compares the
installed PEM and requires the live frps TLS health check before reporting that
nothing changed.

The v0.6 client embeds the official Let's Encrypt ISRG Root X1 and X2 trust
anchors. The relay certificate must include its intermediate chain and chain to
one of those roots. The same wildcard certificate can cover both public tunnel
hosts and `relay.example.com`; another public CA or a self-signed certificate is
intentionally rejected.

After every renewal, use the helper to refresh `relay-tls.pem`; frps keeps its
certificate in memory. The full chain and matching private key share this
single 0600 file so one same-directory rename installs the pair.

## 2. frps

```bash
cp frps.toml.example frps.toml
# Download only the official release for this host architecture and verify it.
./fetch-frps.sh                  # x86_64/amd64 or arm64/aarch64 host
# Or choose the deployment architecture explicitly:
# ./fetch-frps.sh amd64

# Run Compose and the renewal helper as this dedicated, unprivileged account.
printf 'FRPS_UID=%s\nFRPS_GID=%s\n' "$(id -u)" "$(id -g)" >.env
chmod 600 .env
docker compose build --pull frps

# Atomically install the combined 0600 certificate/key and start frps.
SOURCE_CERT=/srv/acme/example.com/fullchain.cer \
SOURCE_KEY=/srv/acme/example.com/example.com.key \
RELAY_SERVER_NAME=relay.example.com \
RELAY_PEM_UID="$(id -u)" RELAY_PEM_GID="$(id -g)" \
  ./reload-nginx-if-cert-changed.sh
```

For a root Synology Task Scheduler renewal hook, use the numeric UID/GID from
the `.env` above (not root's IDs) and the Container Manager binary explicitly:

```bash
SOURCE_CERT=/usr/syno/etc/certificate/_archive/REPLACE/fullchain.pem \
SOURCE_KEY=/usr/syno/etc/certificate/_archive/REPLACE/privkey.pem \
RELAY_SERVER_NAME=relay.example.com \
RELAY_PEM_UID=1026 RELAY_PEM_GID=100 \
DOCKER_BIN=/var/packages/ContainerManager/target/usr/bin/docker \
  /path/to/ktunnel/server/reload-nginx-if-cert-changed.sh
```

[`fetch-frps.sh`](fetch-frps.sh) accepts only `amd64` or `arm64`, downloads the
`v0.71.0` Linux archive and `frp_sha256_checksums.txt` directly from the
official `fatedier/frp` GitHub release, and requires both the upstream checksum
and the reviewed digest pinned in the script to match. It atomically stages
only the verified `frps` executable. The executable and temporary staging
files are ignored by Git.

The local `ktunnel-frps:0.71.0` image is built from `scratch`; its build context
contains only the Dockerfile and verified executable. Compose never pulls an
image with that name. The container runs as the UID/GID in `.env`, with a
read-only root filesystem, all capabilities dropped, and
`no-new-privileges`. Its configuration and combined certificate/key are
read-only bind mounts, and missing host files cause startup to fail instead of
being silently created as directories.

The account running `reload-nginx-if-cert-changed.sh` must own the server
directory and match `FRPS_UID`/`FRPS_GID`; this keeps the combined 0600 PEM
readable by frps without running the container as root. Do not run the renewal
hook with `sudo` unless those values intentionally refer to a dedicated account
and ownership is restored before Compose recreates frps.

To upgrade, review the intended official release notes and checksum file, then
change the version and the two architecture-specific checksums in
`fetch-frps.sh`, and change the image version and OCI label in
`docker-compose.yml` and `Dockerfile.frps` in the same review. Then run:

```bash
./fetch-frps.sh                 # or: ./fetch-frps.sh amd64
docker compose build --pull --no-cache frps
docker compose up -d --no-deps frps
```

Never replace this path with a floating tag or an unofficial third-party
image. `./fetch-frps_test.sh` performs the local script/architecture guard
checks without downloading a release. `./reload-cert_test.sh` exercises
automatic rollback when the renewal process receives a signal after installing
the staged PEM but before committing the health-checked update.

Expose **only** `bindPort` (7000) to the internet. Keep the dashboard on
`127.0.0.1`. Note that the example has **no `auth.token`**: authentication is
handed to ktunneld through the `[[httpPlugins]]` block, so there is no shared
secret for clients to hold. `transport.tls.force = true` refuses plaintext
control connections, and frps loads the combined certificate/key PEM from a
read-only container mount. Never commit `relay-tls.pem`.

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
    --web-host ktunnel.kkensu.com \
    --server relay.example.com --port 7000 --domain example.com \
    --tcp-range 20000-29999
```

`--server/--port/--domain` are what gets baked into every token, so a user only
ever needs the hidden prompt from `ktunnel login`. New tokens use the `kt2` format and use the
`--server` hostname as the certificate name; it must be present in the frps
certificate SAN. `--tcp-range` is the window `tcp` tunnels may claim on the
relay — keep it away from anything real, and remember that on a DMZ every port
in it is internet-facing.

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
opens the user and issues one.

### v0.6 TLS and token migration

Use this order to avoid interrupting existing tunnels:

1. Install the Let's Encrypt full chain and key in frps, set
   `transport.tls.force = true`, restart frps, and verify its certificate.
2. Deploy the v0.6 server. Newly issued tokens are now `kt2` tokens.
3. Upgrade clients to v0.6 and issue each upgraded client a new `kt2` token.
4. After migration, revoke the old `kt1` tokens in the portal.

Existing v0.5 clients with an existing `kt1` token can continue during the
migration: they already negotiate TLS but do not authenticate the certificate.
The v0.6 client deliberately refuses `kt1` when opening a tunnel and tells the
user to reissue a token. Conversely, v0.5 cannot parse a newly issued `kt2`
token, so upgrade that client before replacing its token.

Do not publish the dashboard through a tunnel: the admin UI would depend on the
very components it manages, and frps is not the trusted TLS boundary expected
by the portal. The dedicated nginx block overwrites client-supplied forwarding
headers; ktunneld accepts `X-Real-IP` and `X-Forwarded-Proto` only from a
loopback proxy.

`--web-host` makes ktunneld reject any other HTTP `Host` before routing it. By
default both listeners must use literal loopback IP addresses, and forwarded
scheme/client headers are trusted only from loopback. Container setups that
cannot use host networking may opt in with `--allow-public-listeners`, but only
after firewalling both ports so they are reachable solely by the TLS proxy and
frps respectively. Never expose the plugin port to the internet.

Sessions use a `__Host-` cookie that is always `Secure`, `HttpOnly`,
`SameSite=Strict`, has no `Domain`, and is bounded in memory. Five failed
logins from one address lock it out for a minute. ktunneld also bounds request
headers, web form bodies, connection lifetimes, and idle connections; nginx's
body limit remains a second layer rather than the only enforcement point.

### Backups and rollback

State is the single SQLite file (`data/ktunneld.db`, WAL mode). Copy it while
ktunneld runs — WAL makes that safe — or `docker exec ktunneld /app/ktunneld
token ls` to check what you would lose.

To go back to a shared-secret frps: restore the previous `frps.toml`
(with `auth.token`), restart frps, stop ktunneld. Clients would need the shared
token again; `ktunnel` v0.2 or earlier speaks that model.

## Verifying

```bash
# Confirm the control port presents the expected certificate and chain.
openssl s_client -connect relay.example.com:7000 \
  -servername relay.example.com -verify_return_error </dev/null

# from outside your own network — a LAN test only proves hairpin NAT
curl -sI https://anything-unused.example.com | head -1     # 404 from frps = wired up
docker exec ktunneld /app/ktunneld ls                       # after a client connects
docker logs ktunneld | tail                                 # "login ok" / "proxy ok" / rejections
```
