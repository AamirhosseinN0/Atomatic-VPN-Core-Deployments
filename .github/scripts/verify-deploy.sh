#!/usr/bin/env bash
# Shared post-deploy verification for the README fresh-setup test.
#
# Checks exactly what the READMEs promise, nothing more:
#   - the management CLI (`ikev2ctl` / `singboxctl` / `xrayctl` / `mihomoctl`)
#     is installed and its `check` and `status` subcommands exit 0
#   - the deployed service is active
#   - the kernel-tuning sysctl drop-in exists
#   - every promised client-bundle file exists and is non-empty
#   - generated JSON client configs parse
#   - a per-script extra check (e.g. charon bound to UDP 500/4500)
#
# Required env:
#   CLI          absolute path of the management CLI
#   SERVICE      systemd unit name
#   CLIENTS_DIR  where the client bundle was written
#   SYSCTL_FILE  kernel-tuning drop-in the README promises
# Optional env:
#   BUNDLE_FILES   space-separated files that must exist and be non-empty
#   JSON_GLOB      glob (expanded as root) of JSON client configs to validate
#   EXTRA_CHECK_NAME / EXTRA_CHECK_CMD   one extra bash snippet, run via sudo

set -u

rm -f verify.log check.err
FAILED=0

pass() { printf 'PASS: %s\n' "$*" | tee -a verify.log; }
fail() { printf 'FAIL: %s\n' "$*" | tee -a verify.log; FAILED=1; }

run() { # run "description" command [args...]
  local name="$1"; shift
  if "$@" >/dev/null 2>check.err; then
    pass "$name"
  else
    fail "$name"
    sed 's/^/    /' check.err >> verify.log
  fi
}

CLI_NAME="$(basename "${CLI:?}")"

# 1. Management CLI installed and healthy — README: "a check command re-runs
#    every health check" / "A management CLI stays behind"
run "${CLI_NAME} is installed at ${CLI}" sudo test -x "$CLI"
run "${CLI_NAME} check exits 0"            sudo "$CLI" check
run "${CLI_NAME} status exits 0"           sudo "$CLI" status

# 2. Service active — README: "turns a fresh Ubuntu server into a working node"
run "service '${SERVICE:?}' is active" systemctl is-active --quiet "$SERVICE"

# 3. Kernel tuning drop-in — README: "written as a sysctl drop-in"
run "sysctl drop-in ${SYSCTL_FILE:?} exists and is non-empty" sudo test -s "$SYSCTL_FILE"

# 4. Client bundle files — README: "Client bundles written to ..."
if [[ -n "${BUNDLE_FILES:-}" ]]; then
  # shellcheck disable=SC2086  # intentional word splitting
  for f in $BUNDLE_FILES; do
    run "bundle file ${f} exists and is non-empty" sudo test -s "$f"
  done
fi

# 5. JSON client configs actually parse
if [[ -n "${JSON_GLOB:-}" ]]; then
  while IFS= read -r f; do
    [[ -e "$f" ]] || continue
    run "JSON parses: ${f}" sudo jq -e . "$f"
  done < <(sudo sh -c "printf '%s\n' ${JSON_GLOB}" 2>/dev/null)
fi

# 6. Per-script extra check
if [[ -n "${EXTRA_CHECK_CMD:-}" ]]; then
  run "${EXTRA_CHECK_NAME:-extra check}" sudo bash -c "$EXTRA_CHECK_CMD"
fi

echo
if (( FAILED )); then
  echo "verify-deploy: FAILURES PRESENT (see verify.log)"
else
  echo "verify-deploy: all checks passed"
fi
exit "$FAILED"
