#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
bash -n "$script_dir/reload-nginx-if-cert-changed.sh"

test_dir=$(mktemp -d "${TMPDIR:-/tmp}/ktunnel-renew-test.XXXXXX")
cleanup() {
  rm -rf -- "$test_dir"
}
trap cleanup EXIT HUP INT TERM

mkdir "$test_dir/bin"
cp "$script_dir/reload-nginx-if-cert-changed.sh" "$test_dir/reload.sh"
printf '%s\n' 'services:' '  frps: {}' >"$test_dir/docker-compose.yml"
printf '%s\n' \
  '-----BEGIN CERTIFICATE-----' \
  'leaf' \
  '-----END CERTIFICATE-----' \
  '-----BEGIN CERTIFICATE-----' \
  'intermediate' \
  '-----END CERTIFICATE-----' >"$test_dir/source-cert.pem"
printf '%s\n' 'source-key' >"$test_dir/source-key.pem"
printf '%s\n' 'test-root' >"$test_dir/isrg-root-bundle.pem"
printf '%s\n' 'ORIGINAL RELAY PEM' >"$test_dir/relay-tls.pem"
printf '%s\n' 'new-hash' >"$test_dir/state"
# Existing lock-file contents are harmless because flock state lives in the
# kernel and is released automatically when the prior process exits.
printf '%s\n' 'stale-content-from-crashed-run' >"$test_dir/lock"

# The crypto behavior is covered by openssl integration tests elsewhere. This
# focused harness drives the helper into its post-rename signal window.
cat >"$test_dir/bin/openssl" <<'EOF'
#!/usr/bin/env bash
set -eu
case " $* " in
  *' pkey '*' -outform PEM '*) printf '%s\n' 'FAKE PRIVATE KEY' ;;
  *' x509 '*' -pubkey '*) printf '%s\n' 'public-key' ;;
  *' pkey '*' -pubin '*) while IFS= read -r line; do :; done; printf '%s\n' 'public-key' ;;
  *' pkey '*' -pubout '*) printf '%s\n' 'public-key' ;;
  *' dgst '*)
    while IFS= read -r line; do :; done
    last=${!#}
    if [[ "$last" == */relay-tls.pem ]]; then
      printf '%s\n' 'SHA2-256(file)= old-hash'
    else
      printf '%s\n' 'SHA2-256(file)= new-hash'
    fi
    ;;
  *' crl2pkcs7 '*) printf '%s\n' 'pkcs7' ;;
  *' pkcs7 '*) while IFS= read -r line; do :; done ;;
  *) : ;;
esac
EOF
cat >"$test_dir/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -eu
case " $* " in
  *' config --services '*)
    printf '%s\n' "$PPID" >>"$LOCK_ENTRY_LOG"
    printf '%s\n' frps
    ;;
  *) : ;;
esac
EOF
cat >"$test_dir/bin/timeout" <<'EOF'
#!/usr/bin/env bash
set -eu
duration=$1
shift
case " $* " in
  *' compose '*' up -d '*)
    printf '%s\n' "$PPID" >>"$CRITICAL_LOG"
    # Keep the winning owner alive long enough for the simultaneously released
    # contender to observe and reject its live owner token.
    sleep 0.2
    kill -TERM "$PPID"
    exit 143
    ;;
  *) exit 0 ;;
esac
EOF
cat >"$test_dir/bin/flock" <<'EOF'
#!/usr/bin/env bash
set -eu
if mkdir "$FAKE_FLOCK_STATE" 2>/dev/null; then
  exit 0
fi
exit 1
EOF
chmod 0755 "$test_dir/bin/openssl" "$test_dir/bin/docker" "$test_dir/bin/timeout" "$test_dir/bin/flock" "$test_dir/reload.sh"

set +e
PATH="$test_dir/bin:$PATH" \
SOURCE_CERT="$test_dir/source-cert.pem" \
SOURCE_KEY="$test_dir/source-key.pem" \
RELAY_SERVER_NAME=relay.example.com \
RELAY_PEM="$test_dir/relay-tls.pem" \
STATE_FILE="$test_dir/state" \
LOCK_DIR="$test_dir/lock" \
DOCKER_BIN="$test_dir/bin/docker" \
RELAY_PEM_UID="$(id -u)" \
RELAY_PEM_GID="$(id -g)" \
HEALTH_ATTEMPTS=1 \
CRITICAL_LOG="$test_dir/critical.log" \
LOCK_ENTRY_LOG="$test_dir/lock-entry.log" \
FAKE_FLOCK_STATE="$test_dir/flock-held" \
  "$test_dir/reload.sh" >/dev/null 2>"$test_dir/stderr"
status=$?
set -e

if [ "$status" -eq 0 ]; then
  echo "signal test unexpectedly succeeded" >&2
  cat "$test_dir/stderr" >&2
  exit 1
fi
if [ "$(cat "$test_dir/relay-tls.pem")" != 'ORIGINAL RELAY PEM' ]; then
  echo "signal during recreate did not restore the original relay PEM" >&2
  exit 1
fi
if [ ! -f "$test_dir/lock" ] || [ -L "$test_dir/lock" ]; then
  echo "persistent flock file is missing or unsafe" >&2
  exit 1
fi
leftover_backup=$(find "$test_dir" -maxdepth 1 -name '*.backup.*' -print -quit)
if [ -n "$leftover_backup" ]; then
  echo "successful rollback left a backup file behind" >&2
  exit 1
fi
if ! grep -Fq 'restoring previous state' "$test_dir/stderr"; then
  cat "$test_dir/stderr" >&2
  exit 1
fi
if owner=$(stat -f '%u:%g' "$test_dir/relay-tls.pem" 2>/dev/null); then :; else
  owner=$(stat -c '%u:%g' "$test_dir/relay-tls.pem")
fi
if [ "$owner" != "$(id -u):$(id -g)" ]; then
  echo "relay PEM ownership was not preserved across rollback" >&2
  exit 1
fi

# Reset only the fake kernel state. The real persistent lock file intentionally
# remains present and must be harmless on the next acquisition.
rm -rf -- "$test_dir/flock-held"
rm -f -- "$test_dir/critical.log"
rm -f -- "$test_dir/lock-entry.log"

run_helper() {
  PATH="$test_dir/bin:$PATH" \
  SOURCE_CERT="$test_dir/source-cert.pem" \
  SOURCE_KEY="$test_dir/source-key.pem" \
  RELAY_SERVER_NAME=relay.example.com \
  RELAY_PEM="$test_dir/relay-tls.pem" \
  STATE_FILE="$test_dir/state" \
  LOCK_DIR="$test_dir/lock" \
  DOCKER_BIN="$test_dir/bin/docker" \
  RELAY_PEM_UID="$(id -u)" \
  RELAY_PEM_GID="$(id -g)" \
  FAKE_FLOCK_STATE="$test_dir/flock-held" \
  CRITICAL_LOG="$test_dir/critical.log" \
  LOCK_ENTRY_LOG="$test_dir/lock-entry.log" \
  HEALTH_ATTEMPTS=1 \
    "$test_dir/reload.sh"
}

set +e
run_helper >/dev/null 2>"$test_dir/concurrent-1.stderr" &
pid1=$!
run_helper >/dev/null 2>"$test_dir/concurrent-2.stderr" &
pid2=$!
wait "$pid1"
status1=$?
wait "$pid2"
status2=$?
set -e
if [ "$status1" -eq 0 ] || [ "$status2" -eq 0 ]; then
  echo "concurrent signal test unexpectedly succeeded" >&2
  exit 1
fi
critical_entries=$(wc -l <"$test_dir/lock-entry.log")
if [ "$critical_entries" -ne 1 ]; then
  echo "expected exactly one critical-section entry, got $critical_entries" >&2
  sed -n '1,120p' "$test_dir/concurrent-1.stderr" >&2
  sed -n '1,120p' "$test_dir/concurrent-2.stderr" >&2
  exit 1
fi
if [ ! -f "$test_dir/lock" ]; then
  echo "persistent flock file was unexpectedly removed" >&2
  exit 1
fi
leftover_backup=$(find "$test_dir" -maxdepth 1 -name '*.backup.*' -print -quit)
if [ -n "$leftover_backup" ]; then
  echo "concurrent rollback left a backup file behind" >&2
  exit 1
fi

echo "reload certificate signal rollback test: OK"
