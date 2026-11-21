#!/usr/bin/env bash
# =============================================================================
# ZKA Aztec TXE Test Runner
#
# Runs the in-process TXE (Test eXecution Environment) tests for the Aztec
# contracts. TXE tests (the `test::` module in zka_transfer_aztec) deploy the
# contracts and drive private/public calls against an in-process oracle. NO
# Docker / external sandbox is required -- the TXE runs in-process.
#
# This script exists because the stock `aztec test` command hits two traps that
# make the TXE transition tests fail or flake. It side-steps both:
#
# TRAP 1 -- "public bytecode has not been transpiled" (the deterministic one):
#   `aztec test` internally runs `aztec compile`, which calls `nargo compile`
#   and then `bb aztec_process` to TRANSPILE each contract's public functions
#   from Brillig to AVM bytecode and stamp `transpiled: true` on the artifact.
#   The TXE deploy path REQUIRES that transpiled artifact; without it deploys
#   fail with:
#       "Could not generate contract artifact for ZKATransfer:
#        Error: Contract's public bytecode has not been transpiled"
#   Two sub-traps silently skip transpilation:
#     1a. CWD trap: `aztec compile`'s postprocessing scans `./target/` relative
#         to the CWD, but nargo writes artifacts to the WORKSPACE-ROOT target/.
#         Run from a member dir (e.g. zka_transfer_aztec/) and postprocessing
#         finds nothing -> the artifact is never transpiled.
#     1b. Stale-cache trap: `aztec compile` skips recompiling when no source is
#         newer than the existing artifact -- even if that artifact is NOT
#         transpiled. A non-transpiled artifact left by trap 1a then persists,
#         and `aztec test` cannot pass --force through to its embedded compile.
#   Fix: always run from the workspace root and `aztec compile --force` after a
#   clean target/, so every artifact ends up freshly transpiled.
#
# TRAP 2 -- "mdb_txn_begin: 22 - Invalid argument" (the flaky one):
#   `aztec test` hardcodes `nargo test --test-threads 16`. Running the TXE
#   transition tests in parallel races the shared TXE world-state LMDB, which
#   intermittently fails one (non-deterministic) test with that error. You
#   cannot lower the thread count via `aztec test` (nargo rejects a second
#   --test-threads). Fix: drive `nargo test` directly against our own TXE
#   oracle with a controllable, serial-by-default thread count.
#
# Prerequisites:
#   - Aztec toolchain (`aztec`, `aztec-nargo`) on PATH, the v6.0.0 build pinned by scripts/ci/install-aztec.sh.
#   - macOS: the `aztec` CLI needs Bash >= 4 (`shopt -s inherit_errexit`).
#     The stock /bin/bash is 3.2 and breaks it; put a Homebrew bash first on
#     PATH, e.g.  export PATH="/opt/homebrew/bin:$PATH"
#
# Environment overrides:
#   TXE_PORT        TXE oracle port (default 8081)
#   TEST_THREADS    nargo test thread count (default 1 -- serial avoids TRAP 2)
#   TXE_LOG_FILE    retained TXE oracle log path (default under RUNNER_TEMP or /tmp)
#   TXE_READY_TIMEOUT_SECONDS  readiness deadline (default 60; positive integer)
#   TXE_READY_POLL_SECONDS     readiness poll interval (default 0.2)
#   TXE_TEST_TIMEOUT_SECONDS   per-package test deadline (default 900)
#   TXE_RESTART_EVERY          restart the oracle after this many tests (default
#                              0 = one oracle for the whole run). The oracle's
#                              memory grows with every test; on a 6 GiB runner it
#                              is SIGKILLed after ~13 tests, so the Forgejo lane
#                              sets a small batch size.
#   TXE_COMPILE_TIMEOUT_SECONDS compile/transpile deadline (default 900)
#   TXE_TELEMETRY_DIR          resource JSON directory (default .ci-telemetry/txe)
#
# If the oracle process exits while tests run, the wrapper stops the run at once
# and prints the oracle's exit status and log tail (instead of one "Connect"
# failure per remaining test).
#
# Usage (run from anywhere -- the script cd's to the workspace root itself):
#   ./aztec/scripts/txe-test.sh                 # all TXE tests across the 3
#                                                 contract packages
#   ./aztec/scripts/txe-test.sh test            # only the TXE transition tests
#   ./aztec/scripts/txe-test.sh test::non_verified_recipient_reverts  # one test
#
# Packages exercised (all have a src/test.nr module with TXE tests):
#   zka_transfer_aztec        -- transfer + compliance gate
#   zka_pay_aztec             -- ownerless Pay + recipient-encrypted receipt
#   zka_credential_aztec      -- SS5.2 context binding on disclosure proofs
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AZTEC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$AZTEC_DIR/.." && pwd)"
TELEMETRY_RUNNER="$REPO_ROOT/scripts/ci-resource-telemetry.py"

TXE_PORT="${TXE_PORT:-8081}"
TEST_THREADS="${TEST_THREADS:-1}"
TXE_READY_TIMEOUT_SECONDS="${TXE_READY_TIMEOUT_SECONDS:-60}"
TXE_READY_POLL_SECONDS="${TXE_READY_POLL_SECONDS:-0.2}"
TXE_RESTART_EVERY="${TXE_RESTART_EVERY:-0}"
if [[ ! "${TXE_RESTART_EVERY}" =~ ^[0-9]+$ ]]; then
    echo "ERROR: TXE_RESTART_EVERY must be a non-negative integer" >&2
    exit 1
fi
TXE_TEST_TIMEOUT_SECONDS="${TXE_TEST_TIMEOUT_SECONDS:-900}"
TXE_COMPILE_TIMEOUT_SECONDS="${TXE_COMPILE_TIMEOUT_SECONDS:-900}"
TXE_TELEMETRY_DIR="${TXE_TELEMETRY_DIR:-$REPO_ROOT/.ci-telemetry/txe}"
TXE_LOG_FILE="${TXE_LOG_FILE:-${TXE_LOG_PATH:-${RUNNER_TEMP:-/tmp}/zka-txe-${TXE_PORT}.log}}"

# TXE_PORT is used in both a command argument and the `ss` filter grammar.
# Restrict it to a decimal TCP port before any build work starts.
if [[ ! "${TXE_PORT}" =~ ^[0-9]{1,5}$ ]] \
    || (( 10#${TXE_PORT} < 1 || 10#${TXE_PORT} > 65535 )); then
    echo "ERROR: TXE_PORT must be a decimal TCP port between 1 and 65535" >&2
    exit 2
fi
TXE_PORT=$((10#${TXE_PORT}))

for value_name in TXE_READY_TIMEOUT_SECONDS TXE_TEST_TIMEOUT_SECONDS TXE_COMPILE_TIMEOUT_SECONDS; do
    value="${!value_name}"
    if [[ ! "${value}" =~ ^[1-9][0-9]*$ ]] || (( ${#value} > 9 )); then
        echo "ERROR: ${value_name} must be a positive integer" >&2
        exit 2
    fi
done
if [[ ! "${TXE_READY_POLL_SECONDS}" =~ ^([0-9]+([.][0-9]+)?|[.][0-9]+)$ ]] \
    || ! awk -v value="${TXE_READY_POLL_SECONDS}" \
        'BEGIN { exit !(value > 0 && value < 1e308) }'; then
    echo "ERROR: TXE_READY_POLL_SECONDS must be a finite positive number" >&2
    exit 2
fi

if [[ ! -f "$TELEMETRY_RUNNER" ]]; then
    echo "ERROR: telemetry runner not found: $TELEMETRY_RUNNER" >&2
    exit 1
fi
mkdir -p "$TXE_TELEMETRY_DIR"

server_pid=""
server_pgid=""
log_tail_pid=""

# These helpers are reached through the EXIT trap installed below.
# shellcheck disable=SC2329
terminate_pid() {
    local pid="${1:-}"
    [[ -n "${pid}" ]] || return 0

    # This helper only owns the stateless log follower. Reap it immediately;
    # a zombie still answers `kill -0` and would otherwise burn the cleanup
    # grace period before the oracle process group is terminated.
    kill -KILL "${pid}" >/dev/null 2>&1 || true
    wait "${pid}" >/dev/null 2>&1 || true
}

# shellcheck disable=SC2329
terminate_process_group() {
    local pgid="${1:-}"
    local leader_pid="${2:-}"
    [[ -n "${pgid}" ]] || return 0

    kill -TERM -- "-${pgid}" >/dev/null 2>&1 || true
    # Keep total EXIT cleanup below the readiness/test deadline envelope. A
    # resistant oracle is force-killed after this short TERM grace.
    for _ in {1..5}; do
        kill -0 -- "-${pgid}" >/dev/null 2>&1 || break
        sleep 0.05
    done
    if kill -0 -- "-${pgid}" >/dev/null 2>&1; then
        kill -KILL -- "-${pgid}" >/dev/null 2>&1 || true
    fi
    if [[ -n "${leader_pid}" ]]; then
        wait "${leader_pid}" >/dev/null 2>&1 || true
    fi
}

# shellcheck disable=SC2329
cleanup() {
    local status=$?
    trap - EXIT INT TERM
    terminate_pid "${log_tail_pid}"
    terminate_process_group "${server_pgid}" "${server_pid}"
    exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if ! command -v aztec &>/dev/null || ! command -v aztec-nargo &>/dev/null; then
    echo "ERROR: 'aztec' / 'aztec-nargo' CLI not found on PATH." >&2
    echo "Install the pinned v6 Aztec toolchain with scripts/ci/install-aztec.sh and re-run." >&2
    exit 1
fi

# Must run from the workspace ROOT so that `aztec compile`'s artifact scan
# (./target/) matches nargo's output dir (the workspace-root target/). See TRAP 1a.
cd "$AZTEC_DIR"

echo "=== [1/3] Cleaning target/ (avoids the stale non-transpiled-artifact cache trap) ==="
rm -rf target
for member in zka_aztec_lib zka_transfer_aztec zka_pay_aztec zka_credential_aztec zka_cross_env_tests; do
    rm -rf "$member/target"
done

echo "=== [2/3] Compiling + transpiling contracts (aztec compile --force) ==="
# --force guarantees a fresh nargo compile AND the bb aztec_process transpile
# pass, so every contract artifact ends up with transpiled AVM public bytecode.
python3 "$TELEMETRY_RUNNER" \
    --output "$TXE_TELEMETRY_DIR/compile.json" \
    --label "txe-compile" \
    --timeout-seconds "$TXE_COMPILE_TIMEOUT_SECONDS" \
    -- aztec compile --force

echo "=== [3/3] Running TXE tests (serial, oracle on :${TXE_PORT}) ==="
# Start our own in-process TXE oracle and drive nargo test directly so we can
# control --test-threads (TRAP 2). Mirrors what `aztec test` does internally.
export LOG_LEVEL="${LOG_LEVEL:-error}"
mkdir -p "$(dirname "${TXE_LOG_FILE}")"
: > "${TXE_LOG_FILE}"
# Job control gives the oracle its own process group. That lets cleanup reap
# the complete oracle tree without signalling this wrapper or its log tail.
set -m
node "$SCRIPT_DIR/txe-trace-server.mjs" "$(command -v aztec)" "${TXE_PORT}" >"${TXE_LOG_FILE}" 2>&1 &
server_pid=$!
server_pgid="${server_pid}"
set +m
tail -n +1 -F "${TXE_LOG_FILE}" &
log_tail_pid=$!

print_oracle_log() {
    echo "--- TXE oracle log: ${TXE_LOG_FILE} ---" >&2
    if [[ -s "${TXE_LOG_FILE}" ]]; then
        tail -n 200 "${TXE_LOG_FILE}" >&2
    else
        echo "(oracle log is empty)" >&2
    fi
}

# nc is absent from the Forgejo runner image, so fall back to bash's /dev/tcp.
port_is_open() {
    local wait_seconds="$1"
    if command -v nc >/dev/null 2>&1; then
        nc -z -w "${wait_seconds}" 127.0.0.1 "${TXE_PORT}" >/dev/null 2>&1
    else
        timeout "${wait_seconds}" bash -c "exec 3<>/dev/tcp/127.0.0.1/${TXE_PORT}" >/dev/null 2>&1
    fi
}

# A successful TCP probe alone is insufficient: an unrelated process may own
# TXE_PORT and make the oracle's subsequent bind fail with EADDRINUSE. Resolve
# only listener PIDs, then require at least one to be in the process group
# created for our aztec start command. Never print process command lines.
listener_pids() {
    if command -v ss >/dev/null 2>&1; then
        local pids
        pids="$(ss -H -ltnp "sport = :${TXE_PORT}" 2>/dev/null \
            | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u)"
        if [[ -n "${pids}" ]]; then
            printf '%s\n' "${pids}"
            return 0
        fi
    fi
    if [[ -r /proc/net/tcp ]]; then
        local inode fd_path socket_ref listener_pid port_hex
        printf -v port_hex '%04X' "${TXE_PORT}"
        while IFS= read -r inode; do
            [[ "${inode}" =~ ^[0-9]+$ ]] || continue
            for fd_path in /proc/[0-9]*/fd/*; do
                [[ -L "${fd_path}" ]] || continue
                socket_ref="$(readlink "${fd_path}" 2>/dev/null)" || continue
                [[ "${socket_ref}" == "socket:[${inode}]" ]] || continue
                listener_pid="${fd_path#/proc/}"
                listener_pid="${listener_pid%%/*}"
                printf '%s\n' "${listener_pid}"
            done
        done < <(awk -v port="${port_hex}" \
            'toupper($2) ~ (":" port "$") && $4 == "0A" { print $10 }' \
            /proc/net/tcp /proc/net/tcp6 2>/dev/null) | sort -u
    elif command -v lsof >/dev/null 2>&1; then
        lsof -nP -t -iTCP:"${TXE_PORT}" -sTCP:LISTEN 2>/dev/null | sort -u
    fi
}

listener_is_wrapper_owned() {
    local listener_pid listener_pgid
    while IFS= read -r listener_pid; do
        [[ "${listener_pid}" =~ ^[0-9]+$ ]] || continue
        listener_pgid="$(ps -o pgid= -p "${listener_pid}" 2>/dev/null | tr -d '[:space:]')"
        [[ "${listener_pgid}" =~ ^[0-9]+$ ]] || continue
        if [[ "${listener_pgid}" == "${server_pgid}" ]]; then
            return 0
        fi
    done < <(listener_pids)
    return 1
}

server_is_running() {
    local process_state
    kill -0 "${server_pid}" >/dev/null 2>&1 || return 1
    process_state="$(ps -o stat= -p "${server_pid}" 2>/dev/null | tr -d '[:space:]')"
    [[ -n "${process_state}" && "${process_state}" != Z* && "${process_state}" != X* ]]
}

echo "TXE oracle starting (pid ${server_pid}); waiting up to ${TXE_READY_TIMEOUT_SECONDS}s for :${TXE_PORT} ..."
ready_deadline=$((SECONDS + TXE_READY_TIMEOUT_SECONDS))
while true; do
    if ! server_is_running; then
        wait "${server_pid}" >/dev/null 2>&1 || server_status=$?
        echo "ERROR: TXE oracle exited before becoming ready (status ${server_status:-0})" >&2
        print_oracle_log
        exit 1
    fi
    if (( SECONDS >= ready_deadline )); then
        echo "ERROR: TXE oracle readiness timed out after ${TXE_READY_TIMEOUT_SECONDS}s; TXE oracle did not become ready on :${TXE_PORT}" >&2
        ps -o pid,ppid,etime,%cpu,%mem,rss,command -p "${server_pid}" >&2 || true
        {
            echo "--- readiness probe diagnostics ---"
            command -v nc || echo "nc: not found"
            (ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null || cat /proc/net/tcp /proc/net/tcp6) | head -20
            for host in 127.0.0.1 ::1 localhost; do
                if timeout 2 bash -c "exec 3<>/dev/tcp/${host}/${TXE_PORT}" 2>/dev/null; then
                    echo "tcp ${host}:${TXE_PORT}: open"
                else
                    echo "tcp ${host}:${TXE_PORT}: closed"
                fi
            done
        } >&2 || true
        print_oracle_log
        exit 1
    fi
    remaining_seconds=$((ready_deadline - SECONDS))
    if port_is_open "${remaining_seconds}" \
        && (( SECONDS < ready_deadline )); then
        # The probe can complete just as the oracle exits. Recheck the owner
        # before inspecting the socket so a stale/reused PID cannot satisfy
        # readiness after an oracle crash.
        if ! server_is_running; then
            wait "${server_pid}" >/dev/null 2>&1 || server_status=$?
            echo "ERROR: TXE oracle exited before becoming ready (status ${server_status:-0})" >&2
            print_oracle_log
            exit 1
        fi
        if listener_is_wrapper_owned; then
            break
        fi
        if ! server_is_running; then
            wait "${server_pid}" >/dev/null 2>&1 || server_status=$?
            echo "ERROR: TXE oracle exited before becoming ready (status ${server_status:-0})" >&2
            print_oracle_log
            exit 1
        fi
        echo "ERROR: TXE port ${TXE_PORT} is open but its listener is not owned by the wrapper's oracle process group (pgid ${server_pgid}); refusing unrelated readiness." >&2
        echo "Listener PIDs: $(listener_pids | paste -sd, -)" >&2
        print_oracle_log
        exit 1
    fi

    remaining_seconds=$((ready_deadline - SECONDS))
    if (( remaining_seconds <= 0 )); then
        continue
    fi
    sleep_seconds="$(awk \
        -v poll="${TXE_READY_POLL_SECONDS}" \
        -v remaining="${remaining_seconds}" \
        'BEGIN { if (poll < remaining) print poll; else print remaining }')"
    sleep "${sleep_seconds}"
done
echo "TXE oracle ready on :${TXE_PORT}"

export NARGO_FOREIGN_CALL_TIMEOUT=300000

# Run TXE tests for each contract package serially. Each package has its own
# src/test.nr module driving the in-process TXE oracle. We iterate explicitly
# rather than passing `--workspace` so the failure of one package's tests does
# not leave the others unreported (`nargo test --workspace` short-circuits at
# the first failing package).
oracle_used=0
# Replace the oracle with a fresh process so per-test memory is released.
# Appends to the retained log; the existing log tail keeps following it.
restart_oracle() {
    terminate_process_group "${server_pgid}" "${server_pid}"
    server_pid=""
    server_pgid=""
    set -m
    node "$SCRIPT_DIR/txe-trace-server.mjs" "$(command -v aztec)" "${TXE_PORT}" >>"${TXE_LOG_FILE}" 2>&1 &
    server_pid=$!
    server_pgid="${server_pid}"
    set +m
    local deadline=$((SECONDS + TXE_READY_TIMEOUT_SECONDS))
    until port_is_open 1; do
        if ! kill -0 "${server_pid}" >/dev/null 2>&1 || (( SECONDS >= deadline )); then
            echo "ERROR: restarted TXE oracle did not become ready on :${TXE_PORT}" >&2
            print_oracle_log
            return 1
        fi
        sleep "${TXE_READY_POLL_SECONDS}"
    done
}

# Run a test command while watching the oracle. If the oracle exits mid-run,
# every later test would fail with an opaque "Failed calling external resolver"
# Connect error. Stop the command at once and report the oracle's exit status
# and log instead. Returns 125 when the oracle died, else the command's status.
TXE_ORACLE_EXIT_STATUS=""
run_guarded() {
    local marker="${TXE_TELEMETRY_DIR}/oracle-exited"
    rm -f "${marker}"
    set -m
    "$@" &
    local cmd_pid=$!
    set +m
    (
        while kill -0 "${cmd_pid}" >/dev/null 2>&1; do
            if ! kill -0 "${server_pid}" >/dev/null 2>&1; then
                : > "${marker}"
                kill -TERM -- "-${cmd_pid}" >/dev/null 2>&1 || true
                break
            fi
            /bin/sleep 0.5
        done
    ) &
    local watcher_pid=$!
    local rc=0
    wait "${cmd_pid}" || rc=$?
    kill -KILL "${watcher_pid}" >/dev/null 2>&1 || true
    wait "${watcher_pid}" >/dev/null 2>&1 || true
    if [[ -f "${marker}" ]]; then
        local oracle_status=0
        wait "${server_pid}" >/dev/null 2>&1 || oracle_status=$?
        TXE_ORACLE_EXIT_STATUS="${oracle_status}"
        local signal_note=""
        (( oracle_status > 128 )) && signal_note=", signal $((oracle_status - 128))"
        {
            echo "ERROR: TXE oracle exited during the test run (status ${oracle_status}${signal_note}); remaining tests were skipped."
            echo "Status 134 is SIGABRT (for example an uncaught Napi::Error); 137 is SIGKILL (often the OOM killer)."
        } >&2
        print_oracle_log
        return 125
    fi
    return "${rc}"
}

# Run one package in batches of TXE_RESTART_EVERY tests, one oracle per batch.
# Prints nothing on success; returns the first non-zero batch status.
run_package_in_batches() {
    local pkg="$1"
    shift
    local names=() batch=() status=0 rc line
    while IFS= read -r line; do
        [[ "${line}" == "${pkg} "* ]] && names+=("${line#"${pkg} "}")
    done < <(aztec-nargo test --list-tests --silence-warnings --package "${pkg}" "$@")
    if (( ${#names[@]} == 0 )); then
        echo "ERROR: no tests listed for ${pkg}" >&2
        return 1
    fi
    local total=${#names[@]} index=0 batch_number=0
    while (( index < total )); do
        batch=("${names[@]:index:TXE_RESTART_EVERY}")
        index=$((index + TXE_RESTART_EVERY))
        batch_number=$((batch_number + 1))
        if (( oracle_used )); then
            restart_oracle || return 1
        fi
        oracle_used=1
        echo "--- ${pkg}: batch ${batch_number} (${#batch[@]} tests) ---"
        if run_guarded python3 "$TELEMETRY_RUNNER" \
            --output "$TXE_TELEMETRY_DIR/${pkg}-${batch_number}.json" \
            --label "txe-${pkg}-${batch_number}" \
            --timeout-seconds "$TXE_TEST_TIMEOUT_SECONDS" \
            -- aztec-nargo test \
                --silence-warnings \
                --oracle-resolver "http://127.0.0.1:${TXE_PORT}" \
                --test-threads "${TEST_THREADS}" \
                --package "${pkg}" \
                --exact "${batch[@]}"; then
            :
        else
            rc=$?
            # A dead oracle makes every remaining batch meaningless.
            (( rc == 125 )) && return 125
            (( status == 0 )) && status="${rc}"
        fi
    done
    return "${status}"
}

fail=0
for pkg in zka_transfer_aztec zka_credential_aztec zka_pay_aztec; do
    echo "--- TXE tests: ${pkg} ---"
    if (( TXE_RESTART_EVERY > 0 )); then
        package_cmd=(run_package_in_batches "${pkg}" "$@")
    else
        package_cmd=(run_guarded python3 "$TELEMETRY_RUNNER" \
            --output "$TXE_TELEMETRY_DIR/${pkg}.json" \
            --label "txe-${pkg}" \
            --timeout-seconds "$TXE_TEST_TIMEOUT_SECONDS" \
            -- aztec-nargo test \
                --silence-warnings \
                --oracle-resolver "http://127.0.0.1:${TXE_PORT}" \
                --test-threads "${TEST_THREADS}" \
                --package "${pkg}" \
                "$@")
    fi
    if "${package_cmd[@]}"; then
        :
    else
        rc=$?
        if [[ "$rc" -eq 125 ]]; then
            echo "ERROR: TXE tests for ${pkg} aborted: the oracle exited." >&2
            fail=1
            break
        elif [[ "$rc" -eq 124 ]]; then
            echo "ERROR: TXE tests for ${pkg} timed out after ${TXE_TEST_TIMEOUT_SECONDS}s." >&2
        else
            echo "ERROR: TXE tests for ${pkg} failed with exit code ${rc}." >&2
        fi
        print_oracle_log
        fail=1
    fi
done
exit "${fail}"
