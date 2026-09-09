# ktunnel

Expose a local port at `https://<name>.your-domain.com`, on your own hardware.

```console
$ ktunnel http 3000

  https://happy-zephyr-0faf.kkensu.com
  -> 127.0.0.1:3000   (http)

Ctrl-C to stop.
```

Same ergonomics as ngrok, except the relay is a box you own, the domain is
yours, and nothing expires after two hours.

A single static binary. [frp](https://github.com/fatedier/frp) is embedded as a
library, so there is nothing else to install — no Docker, no `frpc`, no runtime.

## Install

Binaries for macOS, Linux and Windows are attached to each
[release](../../releases).

```bash
./install.sh          # picks the right binary for this machine
ktunnel init
```

The repository is private, so `install.sh` uses the GitHub CLI (`gh auth login`)
to authenticate. On Windows, download `ktunnel-windows-amd64.exe` from Releases
and put it somewhere on your `PATH`.

### With uv

Each release also ships platform wheels, so `uv` can manage the binary — the
same packaging trick ruff and uv themselves use. There is no Python wrapper in
front of the binary; the wheel is only a delivery vehicle.

```bash
./install.sh --uv
```

Because the repository is private, GitHub will not serve release assets to an
unauthenticated request, so a bare `uv tool install <url>` cannot work. The
wheel is fetched with `gh` first and handed to `uv` as a local file:

```bash
gh release download --repo johyunchol/ktunnel --pattern '*macosx_11_0_arm64.whl'
uv tool install --force ./ktunnel-*.whl
```

If the repository were public, `uv tool install <asset-url>` would work directly.

## Usage

```bash
ktunnel http 3000                      # random subdomain
ktunnel http 3000 --name myapp         # https://myapp.example.com
ktunnel http 8080 --host 192.168.1.50  # forward to another machine on the LAN
ktunnel tcp 22 --remote 16022          # raw TCP (ssh, databases, ...)
ktunnel http 3000 --verbose            # show frp client logs
```

Flags may appear before or after the port.

`tcp` tunnels need an explicit remote port: without HTTP's `Host` header there
is nothing to route on, so each one occupies a port on the server.

## How it works

The client dials **out** and the server reuses that connection in reverse:

```
[browser] --https--> [nginx :443] --http--> [frps :18080]
                                                  |
                                          (existing connection)
                                                  v
                                     [ktunnel] --> [localhost:3000]
```

Nothing listens on the client. No inbound firewall rule, no port forwarding, no
public IP — works from a café, behind corporate NAT, on CGNAT, or tethered to a
phone.

TLS terminates at nginx using a wildcard certificate, so any subdomain is valid
the moment you name it, with no per-tunnel certificate issuance. That is what
makes tunnel creation instant rather than a multi-second ACME round trip — and
what keeps you clear of Let's Encrypt rate limits.

## Configuration

`~/.config/ktunnel/config` on macOS and Linux, `%AppData%\ktunnel\config` on
Windows. Created by `ktunnel init`, written `0600`:

```bash
SERVER_ADDR="nas.example.com"
SERVER_PORT="7000"
DOMAIN="example.com"
TOKEN="..."
```

The token authenticates you to frps. Anyone holding it can serve content under
your domain, so treat it like a password. The control channel runs over TLS.

## Server

See [server/README.md](server/README.md) — the wildcard certificate via DNS-01,
frps, and the nginx wildcard vhost, including the Synology DSM workaround for
its reverse-proxy UI rejecting wildcard hostnames.

## Building

Requires Go 1.25+, or Docker if you would rather not install Go:

```bash
./build.sh v0.2.0     # cross-compiles into dist/ using the golang image
```

## License

MIT
