# ktunnel

[한국어](README.md) | [English](README.en.md)

Expose a local port at `https://<name>.your-domain.com`, on your own hardware —
with per-user tokens, subdomain ownership and a dashboard, like a hosted tunnel
service, except the relay is a box you own.

```console
$ ktunnel login              # enter the issued token at the hidden prompt
$ ktunnel http 3000

  https://happy-zephyr-0faf.kkensu.com
  -> 127.0.0.1:3000   (http)

live - Ctrl-C to stop.
```

Two binaries:

| | runs on | does |
|---|---|---|
| `ktunnel`  | every laptop / Pi / CI box | opens tunnels |
| `ktunneld` | the relay, next to frps | issues and checks tokens, enforces who owns which subdomain, serves the dashboard |

[frp](https://github.com/fatedier/frp) does the actual tunnelling and is
embedded as a library, so there is nothing else to install on either side —
no Docker, no `frpc`, no runtime.

## For users

You need a token from whoever runs the relay. It carries the relay address and
domain and verified TLS server name, so it is the only thing to paste:

```bash
ktunnel login                          # enter the token without displaying it
ktunnel http 3000                      # random subdomain
ktunnel http 3000 --name myapp         # https://myapp.example.com
ktunnel http 8080 --host 192.168.1.50  # forward to another machine on the LAN
ktunnel tcp 22 --remote 20022          # raw TCP (ssh, databases, ...)
ktunnel status                         # where am I logged in
ktunnel logout
ktunnel update                         # install the latest release (upgrade also works)
ktunnel update --check                 # check without installing
```

`ktunnel login` hides token input on a terminal and is the recommended form.
For automation that needs a pipe, use standard input, for example
`printf '%s\n' "$KTUNNEL_TOKEN" | ktunnel login`. The explicit
`ktunnel login <token>` form remains available for compatibility, but is not
recommended interactively because the token may appear in shell history or a
process listing. The config is stored at `~/.config/ktunnel/config`; on POSIX
systems its directory is restricted to `0700` and its file to `0600`.

Once a day, normal CLI use also checks for a newer stable release and prints a
short notice when one is available. The best-effort check waits at most 750 ms
for short commands and runs in the background after a tunnel has started.
Failures are silent until the next daily check. Set `KTUNNEL_NO_UPDATE_CHECK=1`
to disable it.

`update` verifies the release SHA-256 before atomically replacing the current
binary. Public repository releases update without a login. When `GH_TOKEN`,
`GITHUB_TOKEN`, or credentials from `gh auth login` are available, the updater
uses them automatically for higher API limits. The built-in `ktunnel update`
checks only the official `johyunchol/ktunnel` repository; it cannot be pointed
at an arbitrary fork. The updater never stores the token and never invokes
`sudo`. If the binary is installed in a protected directory, reinstall it under
a user-writable directory such as
`~/.local/bin`. For an installation made with `./install.sh --uv`, run that
installer again so the wheel metadata and binary stay in sync. Windows users
are directed to the exact release asset for a manual replacement because a
running `.exe` cannot safely replace itself.

Flags may appear before or after the port. `tcp` tunnels need an explicit
remote port from the range the administrator allows: without HTTP's `Host`
header there is nothing to route on.

If the relay refuses a tunnel you are told why and get your prompt back:

```
error: subdomain "api" belongs to alice
error: tunnel limit reached (5)
error: token has been revoked
```

### Install

Binaries for macOS, Linux and Windows are attached to each
[release](../../releases); `install.sh` picks the right one, or uses `uv`:

```bash
./install.sh          # copies the binary to ~/.local/bin
./install.sh --uv     # uv tool install, from the platform wheel
```

Public releases are downloaded with `curl`, so neither a GitHub account nor
`gh` is required. When an authenticated GitHub CLI is available, the installer
uses it automatically. For a private fork, set `KTUNNEL_REPO=owner/repo` and
run `gh auth login` with an account that has read access. Downloads are installed
only after verification against `SHA256SUMS`. On Windows, download
`ktunnel-windows-amd64.exe` and put it on
your `PATH`. After a binary installation, subsequent releases can be installed
with `ktunnel update` (or its `ktunnel upgrade` alias).

## For administrators

`ktunneld` is a small control plane — one static binary, one SQLite file. It
plugs into frps's [server plugin](https://github.com/fatedier/frp/blob/dev/doc/server_plugin.md)
hooks, so frps asks it on every login, tunnel open and heartbeat:

```
ktunnel ──login, metas.token──▶ frps ──Login/NewProxy/Ping/CloseProxy──▶ ktunneld
                                                                         │
                                                                     SQLite: users,
                                                                     tokens, reservations,
                                                                     sessions, audit
```

There is **no shared frps secret** any more. Each token is personal, hashed at
rest (sha256), shown exactly once, and revocable on its own.

`kt2` tokens also carry the relay certificate name. The v0.6 client trusts only
the embedded Let's Encrypt ISRG Root X1/X2 anchors and verifies both the
certificate chain and host name on the frps control connection. Existing `kt1`
tokens remain valid on the server during migration, but the v0.6 client refuses
to open a new tunnel with one. Issue a new `kt2` token in the web portal.

```bash
ktunneld user add alice --max 5              # concurrent-tunnel limit
ktunneld token issue alice --label laptop    # prints the token once
ktunneld token ls
ktunneld token revoke 6KkHiYxu               # by prefix; live sessions drop ≤30s

ktunneld reserve api alice                   # only alice may open api.example.com
ktunneld release api

ktunneld ls                                  # who is connected, what is exposed
ktunneld kill <session-id | subdomain>       # disconnect; token refused for 5 min
```

The **web portal** listens on `127.0.0.1:7600`. Administrators sign in as
`admin` with the password from `ktunneld admin set-password`, create users, and
hand each user the one-time temporary password shown after creation or reset.
There is no public sign-up. On first sign-in users must change that password,
then they can issue and revoke only their own tunnel tokens and view only their
own connections and reserved addresses. A newly issued token is shown once;
the user saves it through the hidden prompt from `ktunnel login`.

The production portal hostname is `https://ktunnel.kkensu.com`. Keep the old
`tunnel-admin.kkensu.com` hostname as a permanent redirect; see
[`server/nginx-dashboard.conf`](server/nginx-dashboard.conf).

What is enforced on every tunnel:

- the token is active, the account enabled, the session not killed
- `http` tunnels use a plain subdomain (no custom domains, no multi-level names)
- a reserved subdomain is only opened by its owner; an unreserved one is first
  come, first served, and never by two sessions at once
- `tcp` tunnels stay inside the configured remote-port window
- the user's concurrent-tunnel limit

Revoking, disabling or killing takes effect at the client's next heartbeat
(30 s). frpc would normally reconnect straight away, so `ktunnel` exits with a
message instead, and a kill also refuses that token for five minutes.

Setup is in [server/README.md](server/README.md) — the wildcard certificate via
DNS-01, frps, the nginx wildcard vhost (with the Synology DSM workaround), and
`ktunneld` itself.

## How it works

The client dials **out** and the relay reuses that connection in reverse.
Nothing listens on the client: no inbound rule, no port forwarding, no public
IP — it works from a café, behind corporate NAT, on CGNAT, or tethered.

Public web traffic terminates TLS at nginx with a wildcard certificate, so any
subdomain is valid the moment you name it. Separately, the client-to-frps
control channel requires TLS and verifies the relay certificate. No per-tunnel
certificate issuance is what makes tunnel creation instant and keeps you clear
of Let's Encrypt rate limits.

## Building

Go 1.25+, or Docker if you would rather not install Go:

```bash
./build.sh v0.6.0                    # cross-compiles both binaries into dist/
python3 packaging/build_wheels.py 0.6.0
```

An exact stable-version tag such as `v0.6.0` triggers the same build in GitHub
Actions and attaches everything to a release. The release workflow builds all
binaries and wheels before creating one `SHA256SUMS`. Never reuse an older or
locally generated checksum file that does not contain the wheel entries.

## License

MIT
