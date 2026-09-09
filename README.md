# ktunnel

Expose a local port at `https://<name>.your-domain.com`, on your own hardware.

```console
$ ktunnel http 3000

  https://brave-otter-7f3a.kkensu.com
  → 127.0.0.1:3000   (http, via docker)

Ctrl-C to stop.
```

Same ergonomics as ngrok, except the relay is a box you own, the domain is
yours, and nothing expires after two hours. It is a thin wrapper around
[frp](https://github.com/fatedier/frp) — frp does the tunnelling, `ktunnel`
removes the config file.

## Why

frp is solid but expects a TOML file per tunnel. That friction is enough to
stop you reaching for it during a quick demo. `ktunnel` generates the config,
picks a random subdomain, prints the URL, and cleans up on Ctrl-C.

## Install

```bash
git clone git@github.com:kshsguy/ktunnel.git
cd ktunnel && ./install.sh
ktunnel init
```

Requires `frpc` or Docker on the client, and a
[configured server](server/README.md).

## Usage

```bash
ktunnel http 3000                      # random subdomain
ktunnel http 3000 --name myapp         # https://myapp.example.com
ktunnel http 3000 --open               # open a browser once connected
ktunnel http 8080 --host 192.168.1.50  # forward to another machine on the LAN
ktunnel tcp 22 --remote 16022          # raw TCP (ssh, databases, ...)
ktunnel ls                             # what's currently running
```

`tcp` tunnels need an explicit remote port: without HTTP's `Host` header there
is nothing to route on, so each one occupies a port on the server.

## How it works

The client dials **out** and the server reuses that connection in reverse:

```
[browser] --https--> [nginx :443] --http--> [frps :18080]
                                                  |
                                          (existing connection)
                                                  v
                                     [frpc] --> [localhost:3000]
```

Nothing listens on the client. No inbound firewall rule, no port forwarding, no
public IP — works from a café, behind corporate NAT, on CGNAT, or tethered to a
phone.

TLS terminates at nginx using a wildcard certificate, so any subdomain is valid
the moment you name it, with no per-tunnel certificate issuance. That is what
makes tunnel creation instant rather than a multi-second ACME round trip — and
what keeps you clear of Let's Encrypt rate limits.

## Configuration

`~/.config/ktunnel/config`, created by `ktunnel init` and `chmod 600`:

```bash
SERVER_ADDR="nas.example.com"
SERVER_PORT="7000"
DOMAIN="example.com"
TOKEN="..."
```

The token authenticates you to frps. Anyone holding it can serve content under
your domain, so treat it like a password. The control channel runs over TLS
(`transport.tls.enable`).

## Server

See [server/README.md](server/README.md) — wildcard certificate via DNS-01,
frps, and the nginx wildcard vhost, including the Synology DSM workaround for
its reverse-proxy UI rejecting wildcard hostnames.

## License

MIT
