# ktunnel

Expose a local port at `https://<name>.your-domain.com`, on your own hardware —
with per-user tokens, subdomain ownership and a dashboard, like a hosted tunnel
service, except the relay is a box you own.

```console
$ ktunnel login kt1.…        # once, with the token you were given
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
domain, so it is the only thing to paste:

```bash
ktunnel login kt1.MTI3…      # stores it in ~/.config/ktunnel/config (0600)
ktunnel http 3000                      # random subdomain
ktunnel http 3000 --name myapp         # https://myapp.example.com
ktunnel http 8080 --host 192.168.1.50  # forward to another machine on the LAN
ktunnel tcp 22 --remote 20022          # raw TCP (ssh, databases, ...)
ktunnel status                         # where am I logged in
ktunnel logout
```

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

The repository is private, so both go through the GitHub CLI (`gh auth login`).
On Windows, download `ktunnel-windows-amd64.exe` and put it on your `PATH`.

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

The **dashboard** (users, tokens, reservations, live tunnels, audit log) is the
same thing with buttons. It listens on `127.0.0.1:7600`; put it behind your
TLS-terminating proxy under a hostname of your choice and sign in with the
password from `ktunneld admin set-password`.

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

TLS terminates at nginx with a wildcard certificate, so any subdomain is valid
the moment you name it. No per-tunnel certificate issuance is what makes
tunnel creation instant, and what keeps you clear of Let's Encrypt rate limits.

## Building

Go 1.25+, or Docker if you would rather not install Go:

```bash
./build.sh v0.3.0                    # cross-compiles both binaries into dist/
python3 packaging/build_wheels.py 0.3.0
```

Tags trigger the same build in GitHub Actions and attach everything to a
release.

## License

MIT
