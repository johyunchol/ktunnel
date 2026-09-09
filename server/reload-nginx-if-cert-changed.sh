#!/usr/bin/env bash
# Refresh the relay TLS material after ACME renewal. The full chain and key are
# validated, combined, and atomically installed before only frps is recreated.
set -euo pipefail

umask 077
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

: "${SOURCE_CERT:?set SOURCE_CERT to the renewed full-chain PEM}"
: "${SOURCE_KEY:?set SOURCE_KEY to the renewed private-key PEM}"
: "${RELAY_SERVER_NAME:?set RELAY_SERVER_NAME to the kt2 TLS server name}"

relay_pem=${RELAY_PEM:-"$script_dir/relay-tls.pem"}
trusted_ca="$script_dir/isrg-root-bundle.pem"
compose_file=${COMPOSE_FILE:-"$script_dir/docker-compose.yml"}
state_file=${STATE_FILE:-"$script_dir/.relay-cert-hash"}
lock_file=${LOCK_DIR:-"$script_dir/.relay-cert-refresh.lock"}
min_valid_seconds=${MIN_VALID_SECONDS:-604800}
health_connect=${HEALTH_CONNECT:-127.0.0.1:7000}
health_timeout=${HEALTH_TIMEOUT:-3}
health_attempts=${HEALTH_ATTEMPTS:-10}
reload_nginx=${RELOAD_NGINX:-0}
relay_pem_uid=${RELAY_PEM_UID:-}
relay_pem_gid=${RELAY_PEM_GID:-}
docker_bin=${DOCKER_BIN:-}
nginx_ctl=

for positive_integer in "$min_valid_seconds" "$health_timeout" "$health_attempts"; do
  case "$positive_integer" in
    '' | *[!0-9]*)
      echo "MIN_VALID_SECONDS, HEALTH_TIMEOUT, and HEALTH_ATTEMPTS must be positive integers" >&2
      exit 1
      ;;
  esac
  if [ "$positive_integer" -eq 0 ]; then
    echo "MIN_VALID_SECONDS, HEALTH_TIMEOUT, and HEALTH_ATTEMPTS must be positive integers" >&2
    exit 1
  fi
done
if { [ -n "$relay_pem_uid" ] && [ -z "$relay_pem_gid" ]; } ||
  { [ -z "$relay_pem_uid" ] && [ -n "$relay_pem_gid" ]; }; then
  echo "RELAY_PEM_UID and RELAY_PEM_GID must be set together" >&2
  exit 1
fi
for numeric_id in "$relay_pem_uid" "$relay_pem_gid"; do
  case "$numeric_id" in
    '' ) ;;
    *[!0-9]*)
      echo "RELAY_PEM_UID and RELAY_PEM_GID must be numeric" >&2
      exit 1
      ;;
  esac
done

tmp_pem=
backup_pem=
state_tmp=
had_previous=0
installed=0
committed=0
rolling_back=0
lock_fd=9
cleanup() {
  [ -z "$tmp_pem" ] || rm -f -- "$tmp_pem"
  [ -z "$state_tmp" ] || rm -f -- "$state_tmp"
  if [ "$committed" -eq 1 ] && [ -n "$backup_pem" ]; then
    rm -f -- "$backup_pem"
    backup_pem=
  fi
  # The kernel releases flock when this process exits. Never unlink the
  # persistent lock file: doing so could let two processes lock different
  # inodes at the same path.
}

rollback_install() {
  if [ "$installed" -ne 1 ] || [ "$committed" -eq 1 ] || [ "$rolling_back" -eq 1 ]; then
    return 0
  fi
  rolling_back=1
  echo "relay update interrupted or uncommitted; restoring previous state" >&2
  if [ "$had_previous" -eq 1 ]; then
    if ! mv -f -- "$backup_pem" "$relay_pem"; then
      echo "automatic rollback failed; backup preserved at $backup_pem" >&2
      return 1
    fi
    backup_pem=
    installed=0
    timeout 120 "$docker_bin" compose -f "$compose_file" up -d --no-deps --force-recreate frps || true
  else
    timeout 30 "$docker_bin" compose -f "$compose_file" stop frps || true
    rm -f -- "$relay_pem"
    installed=0
  fi
  return 0
}

on_signal() {
  case "$1" in
    HUP) exit 129 ;;
    INT) exit 130 ;;
    TERM) exit 143 ;;
  esac
}

on_exit() {
  status=$?
  trap - EXIT
  # A second signal must not re-enter Docker or start a rollback loop. The
  # bounded timeout still prevents a stuck recovery command.
  trap '' HUP INT TERM
  if ! rollback_install; then
    status=1
  fi
  cleanup
  exit "$status"
}

trap on_exit EXIT
trap 'on_signal HUP' HUP
trap 'on_signal INT' INT
trap 'on_signal TERM' TERM

mkdir -p -- "$(dirname -- "$lock_file")"
if ! command -v flock >/dev/null 2>&1; then
  echo "the flock command is required for safe certificate refresh locking" >&2
  exit 1
fi
if [ -L "$lock_file" ] || { [ -e "$lock_file" ] && [ ! -f "$lock_file" ]; }; then
  echo "refusing unsafe lock-file path: $lock_file" >&2
  exit 1
fi
exec 9>>"$lock_file"
if [ -L "$lock_file" ] || [ ! -f "$lock_file" ]; then
  echo "lock file changed while it was opened: $lock_file" >&2
  exit 1
fi
chmod 0600 "/dev/fd/$lock_fd"
if ! flock -n "$lock_fd"; then
  echo "certificate refresh already running (lock file: $lock_file)" >&2
  exit 1
fi

if [ -n "$docker_bin" ]; then
  if [[ "$docker_bin" == */* ]]; then
    [ -x "$docker_bin" ] || { echo "DOCKER_BIN is not executable: $docker_bin" >&2; exit 1; }
  else
    docker_bin=$(command -v "$docker_bin" 2>/dev/null || true)
    [ -n "$docker_bin" ] || { echo "DOCKER_BIN command not found" >&2; exit 1; }
  fi
elif command -v docker >/dev/null 2>&1; then
  docker_bin=$(command -v docker)
elif [ -x /var/packages/ContainerManager/target/usr/bin/docker ]; then
  docker_bin=/var/packages/ContainerManager/target/usr/bin/docker
else
  echo "docker was not found; set DOCKER_BIN to the Container Manager docker executable" >&2
  exit 1
fi

verify_pair() {
  local cert_file=$1
  local key_file=$2
  local cert_count pkcs7_bundle cert_public_key private_public_key
  cert_count=$(grep -c '^-----BEGIN CERTIFICATE-----$' <"$cert_file" || true)
  if [ "$cert_count" -lt 2 ]; then
    echo "certificate file must contain the leaf and intermediate chain" >&2
    return 1
  fi
  # Capture textual intermediate output before invoking the consumer. This
  # avoids producer SIGPIPE failures under `set -o pipefail` when a consumer
  # exits as soon as it has parsed enough input.
  pkcs7_bundle=$(openssl crl2pkcs7 -nocrl -certfile "$cert_file")
  openssl pkcs7 -print_certs -noout <<<"$pkcs7_bundle" >/dev/null
  openssl x509 -in "$cert_file" -noout -checkend "$min_valid_seconds" >/dev/null
  openssl x509 -in "$cert_file" -noout -checkhost "$RELAY_SERVER_NAME" >/dev/null
  openssl verify -CAfile "$trusted_ca" -untrusted "$cert_file" "$cert_file" >/dev/null
  openssl pkey -passin pass: -in "$key_file" -noout -check >/dev/null

  cert_public_key=$(openssl x509 -in "$cert_file" -pubkey -noout)
  cert_public_key=$(openssl pkey -pubin -pubout -outform PEM 2>/dev/null <<<"$cert_public_key")
  private_public_key=$(openssl pkey -passin pass: -in "$key_file" -pubout -outform PEM 2>/dev/null)
  if [ "$cert_public_key" != "$private_public_key" ]; then
    echo "certificate and private key do not match" >&2
    return 1
  fi
}

sha256_file() {
  local digest
  digest=$(openssl dgst -sha256 "$1")
  # OpenSSL emits `SHA2-256(path)= digest` (or an equivalent name); extracting
  # with shell parameter expansion avoids a short-reading awk pipeline.
  digest=${digest##*= }
  printf '%s\n' "$digest"
}

tls_healthy() {
  local attempt=1
  while [ "$attempt" -le "$health_attempts" ]; do
    if timeout "$health_timeout" openssl s_client \
      -connect "$health_connect" -servername "$RELAY_SERVER_NAME" \
      -verify_hostname "$RELAY_SERVER_NAME" -verify_return_error \
      -CAfile "$trusted_ca" </dev/null >/dev/null 2>&1; then
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  return 1
}

for source_file in "$SOURCE_CERT" "$SOURCE_KEY" "$trusted_ca" "$compose_file"; do
  if [ ! -f "$source_file" ] || [ ! -r "$source_file" ]; then
    echo "missing or unreadable input: $source_file" >&2
    exit 1
  fi
done
verify_pair "$SOURCE_CERT" "$SOURCE_KEY"

if ! command -v timeout >/dev/null 2>&1; then
  echo "the timeout command is required for the bounded TLS health check" >&2
  exit 1
fi
compose_services=$("$docker_bin" compose -f "$compose_file" config --services)
if ! awk '$0 == "frps" { found=1 } END { exit !found }' <<<"$compose_services"; then
  echo "Compose file does not define the required frps service" >&2
  exit 1
fi
if [ "$reload_nginx" = 1 ]; then
  if command -v synosystemctl >/dev/null 2>&1; then
    nginx_ctl=$(command -v synosystemctl)
  elif [ -x /usr/syno/bin/synosystemctl ]; then
    nginx_ctl=/usr/syno/bin/synosystemctl
  elif command -v systemctl >/dev/null 2>&1; then
    nginx_ctl=$(command -v systemctl)
  else
    echo "RELOAD_NGINX=1 but no supported nginx service manager was found" >&2
    exit 1
  fi
  nginx -t
elif [ "$reload_nginx" != 0 ]; then
  echo "RELOAD_NGINX must be 0 or 1" >&2
  exit 1
fi

if [ -L "$relay_pem" ] || { [ -e "$relay_pem" ] && [ ! -f "$relay_pem" ]; }; then
  echo "refusing unsafe relay PEM path: $relay_pem" >&2
  exit 1
fi
mkdir -p -- "$(dirname -- "$relay_pem")" "$(dirname -- "$state_file")"
tmp_pem=$(mktemp "${relay_pem}.tmp.XXXXXX")
cp -- "$SOURCE_CERT" "$tmp_pem"
# Write a canonical unencrypted key; encrypted inputs fail without prompting.
openssl pkey -passin pass: -in "$SOURCE_KEY" -outform PEM >>"$tmp_pem"
chmod 0600 "$tmp_pem"
if [ -n "$relay_pem_uid" ]; then
  chown "$relay_pem_uid:$relay_pem_gid" "$tmp_pem"
fi
verify_pair "$tmp_pem" "$tmp_pem"

new_hash=$(sha256_file "$tmp_pem")
old_hash=$(cat -- "$state_file" 2>/dev/null || true)
current_hash=
if [ -f "$relay_pem" ]; then
  current_hash=$(sha256_file "$relay_pem")
fi
if [ "$new_hash" = "$old_hash" ] && [ "$new_hash" = "$current_hash" ]; then
  if tls_healthy; then
    echo "relay certificate unchanged and frps TLS health check passed"
    exit 0
  fi
  echo "certificate state matches but frps is unhealthy; recreating it" >&2
fi

if [ -f "$relay_pem" ]; then
  had_previous=1
  backup_pem=$(mktemp "${relay_pem}.backup.XXXXXX")
  cp -p -- "$relay_pem" "$backup_pem"
  chmod 0600 "$backup_pem"
fi

# Set the rollback state before rename so a signal immediately before, during,
# or after the move always restores the previous PEM.
installed=1
# certFile and keyFile both reference this combined PEM, so one rename changes
# the certificate/key pair without an observable mismatched-file interval.
mv -f -- "$tmp_pem" "$relay_pem"
tmp_pem=

if timeout 120 "$docker_bin" compose -f "$compose_file" up -d --no-deps --force-recreate frps; then
  if tls_healthy; then
    healthy=1
  else
    healthy=0
  fi
else
  healthy=0
fi

if [ "$healthy" -ne 1 ]; then
  echo "frps failed its authenticated TLS health check; restoring previous relay PEM" >&2
  rollback_install || true
  exit 1
fi

if [ "$reload_nginx" = 1 ]; then
  "$nginx_ctl" reload nginx
fi

# The installed PEM is now live and authenticated. From this point the EXIT
# trap must preserve it; the state file is only a best-effort change cache.
committed=1
state_tmp=$(mktemp "${state_file}.tmp.XXXXXX")
printf '%s\n' "$new_hash" >"$state_tmp"
chmod 0600 "$state_tmp"
mv -f -- "$state_tmp" "$state_file"
state_tmp=
if [ -n "$backup_pem" ]; then
  rm -f -- "$backup_pem"
  backup_pem=
fi
echo "relay certificate refreshed; frps passed the authenticated TLS health check"
