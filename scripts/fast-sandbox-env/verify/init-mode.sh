#!/usr/bin/env bash
# Copyright 2026 The OpenSandbox Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# verify/init-mode.sh — execd-as-init in-guest process verify (OSEP-0018)
#
# The server config in this environment sets runtime.execd_run_as_init, so
# every template bakes EXECD_INIT=1 and the golden image's guest init boots
# bootstrap.sh, which execs `execd --init` (execd supervises the workload
# through the fsb guest init, which stays PID 1 — subreaper mode, no PID 1
# signal shield). This stage pins the in-guest process topology that the
# other verifies cannot see, all through one template sandbox driven by
# `osb command run`:
#
#   0. Dump the FULL in-guest process table first (ps pid/ppid/pgid/sid/
#      stat/args) — the human-readable ground truth every assertion below
#      filters, kept verbatim in the stage log and at
#      $LOGS_DIR/init-mode-processes.txt as failure evidence.
#   1. PID 1 is the fsb guest init (cmdline contains sandbox-init), NOT
#      bootstrap.sh or execd.
#   2. execd runs with the --init flag (OSEP-0018 init duties armed).
#   3. execd is a direct child of PID 1 (bootstrap exec'd away).
#   4. The baked entrypoint (default tail -f /dev/null) is a child of execd
#      — the workload is supervised by execd, not a sibling shell.
#   5. Subreaper semantics: an orphaned process reparents to execd (nearest
#      subreaper ancestor), not to PID 1.
#   6. execd /v1/isolated/capabilities reports hardening.init_mode =
#      subreaper and signal_shield = false (the documented fsb/Pool tier).
#
# Guest-side tool expectations: the golden image (Debian + procps) provides
# pgrep/awk/grep/curl; each probe prints one KEY=VALUE line that the host
# side extracts (the CLI stream may carry non-JSON framing).
#
# NOTE: integration-env.sh carries an inline copy of this stage (like
# vault.sh); keep the two in sync until the env.sh split is completed.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"

# guest_out <words...>: run a command in the sandbox through the CLI; stdout
# is the guest command's output (framing lines tolerated downstream).
guest_out() {
	osb_api command run "$VERIFY_ID" -- "$@" 2>"$LOGS_DIR/init-mode-cmd.err"
}

# guest_value <key> <words...>: extract the VALUE of the guest's KEY=VALUE
# line (first match wins; non-matching framing lines are skipped).
guest_value() { # <key> <probe-words...>
	local key="$1" line
	shift
	while IFS= read -r line || [[ -n "$line" ]]; do
		case "$line" in
			"$key="*) printf '%s\n' "${line#*=}"; return 0 ;;
		esac
	done < <(guest_out "$@")
	return 1
}

init_mode_verify() { # [template-id]
	local template_id="${1:-$TEMPLATE_ID}"
	local created execd_pid probe

	log "verify (init-mode): creating a sandbox via the opensandbox CLI (templateId=$template_id)"
	created="$(osb_api sandbox create --template "$template_id" --timeout 1h \
		--metadata origin=fast-sandbox-env-init-mode -o json 2>/dev/null)" \
		|| fail "osb sandbox create failed against $SERVER_URL"
	VERIFY_ID="$(printf '%s' "$created" | jq -r '.id')"
	[[ -n "$VERIFY_ID" && "$VERIFY_ID" != "null" ]] || fail "create response carried no id"
	wait_for "init-mode target Running" 600 sandbox_running

	# 0. The full in-guest process table, verbatim: the ground truth every
	#    assertion below filters, and the first evidence a failure reads.
	log "verify (init-mode): in-guest process table (pid ppid pgid sid stat args):"
	guest_out sh -c 'ps -eo pid,ppid,pgid,sid,stat,args || ps -ef' \
		| tee "$LOGS_DIR/init-mode-processes.txt" >&2 \
		|| log "verify (init-mode): process table dump failed (continuing; the probes below carry the diagnostics)"

	# 1. PID 1 is the fsb guest init (not bootstrap.sh, not execd).
	probe="$(guest_value PID1 sh -c 'echo "PID1=$(tr "\0" " " < /proc/1/cmdline)"')" \
		|| fail "init-mode: /proc/1/cmdline probe failed: $(head -c 300 "$LOGS_DIR/init-mode-cmd.err" 2>/dev/null)"
	case "$probe" in
		*sandbox-init*) pass "guest PID 1 is the fsb guest init ($probe)" ;;
		*) fail "guest PID 1 is not the guest init: /proc/1/cmdline = $probe" ;;
	esac

	# 2. execd is present and armed with --init.
	execd_pid="$(guest_value EXECD_PID sh -c 'echo "EXECD_PID=$(pgrep -x execd | head -1)"')" \
		|| fail "init-mode: execd pgrep probe failed: $(head -c 300 "$LOGS_DIR/init-mode-cmd.err" 2>/dev/null)"
	case "$execd_pid" in
		''|*[!0-9]*) fail "execd process not found in the guest (EXECD_PID='$execd_pid')" ;;
	esac
	probe="$(guest_value INIT_FLAG sh -c "tr \"\\0\" \"\\n\" < /proc/$execd_pid/cmdline | grep -qx -- --init && echo INIT_FLAG=1")" \
		|| fail "init-mode: execd cmdline probe failed: $(head -c 300 "$LOGS_DIR/init-mode-cmd.err" 2>/dev/null)"
	[[ "$probe" == "1" ]] \
		|| fail "execd (pid $execd_pid) does not carry --init (cmdline probe output: $probe)"
	pass "execd runs with --init (pid $execd_pid)"

	# 3. execd is a direct child of PID 1 (bootstrap.sh exec'd away).
	probe="$(guest_value EXECD_PPID sh -c "echo \"EXECD_PPID=\$(grep '^PPid:' /proc/$execd_pid/status | grep -o '[0-9]*')\"")" \
		|| fail "init-mode: execd PPid probe failed: $(head -c 300 "$LOGS_DIR/init-mode-cmd.err" 2>/dev/null)"
	[[ "$probe" == "1" ]] \
		|| fail "execd (pid $execd_pid) is not a child of PID 1: PPid=$probe"
	pass "execd is a direct child of the guest init (PPid=1)"

	# 4. The baked entrypoint is supervised by execd (its child, not a
	#    sibling of bootstrap: the template default is tail -f /dev/null).
	probe="$(guest_value TAIL_PPID sh -c 'p=$(pgrep -f "tail -f /dev/null" | head -1); echo "TAIL_PPID=$(grep "^PPid:" /proc/$p/status | grep -o "[0-9]*")"')" \
		|| fail "init-mode: entrypoint PPid probe failed: $(head -c 300 "$LOGS_DIR/init-mode-cmd.err" 2>/dev/null)"
	[[ "$probe" == "$execd_pid" ]] \
		|| fail "the entrypoint is not a child of execd (pid $execd_pid): entrypoint PPid=$probe"
	pass "the baked entrypoint is supervised by execd (entrypoint PPid=$execd_pid)"

	# 5. Subreaper semantics: an orphaned background process reparents to
	#    execd (the nearest subreaper ancestor), not to PID 1.
	guest_out sh -c 'sleep 30 >/dev/null 2>&1 & echo $! > /tmp/osb-init-mode-orphan.pid' >/dev/null \
		|| fail "init-mode: orphan spawn failed: $(head -c 300 "$LOGS_DIR/init-mode-cmd.err" 2>/dev/null)"
	probe="$(guest_value ORPHAN_PPID sh -c 'p=$(cat /tmp/osb-init-mode-orphan.pid); echo "ORPHAN_PPID=$(grep "^PPid:" /proc/$p/status | grep -o "[0-9]*")"')" \
		|| fail "init-mode: orphan PPid probe failed: $(head -c 300 "$LOGS_DIR/init-mode-cmd.err" 2>/dev/null)"
	[[ "$probe" == "$execd_pid" ]] \
		|| fail "the orphan did not reparent to execd (pid $execd_pid): orphan PPid=$probe"
	pass "orphaned processes reparent to execd (subreaper; orphan PPid=$execd_pid)"
	guest_out sh -c 'kill $(cat /tmp/osb-init-mode-orphan.pid) 2>/dev/null; rm -f /tmp/osb-init-mode-orphan.pid' >/dev/null 2>&1 || true

	# 6. The capabilities endpoint reports the fsb/Pool init tier: execd owns
	#    the process tree as a subreaper; the kernel PID 1 signal shield
	#    stays with the fsb guest init.
	local hardening_line hardening
	hardening_line="$(guest_out curl -fsS http://127.0.0.1:44772/v1/isolated/capabilities 2>/dev/null \
		| while IFS= read -r line || [[ -n "$line" ]]; do
			printf '%s' "$line" | jq -ce '.hardening // empty' 2>/dev/null && break
		done)" \
		|| fail "init-mode: capabilities probe failed (no .hardening in the response): $(head -c 300 "$LOGS_DIR/init-mode-cmd.err" 2>/dev/null)"
	log "verify (init-mode): hardening report: $hardening_line"
	[[ "$(printf '%s' "$hardening_line" | jq -r '.init_mode')" == "subreaper" ]] \
		|| fail "hardening.init_mode is not subreaper: $hardening_line"
	[[ "$(printf '%s' "$hardening_line" | jq -r '.signal_shield')" == "false" ]] \
		|| fail "hardening.signal_shield is not false (fsb guest init owns PID 1): $hardening_line"
	pass "capabilities: hardening.init_mode=subreaper, signal_shield=false (fsb/Pool tier; no isolation TOML, floor layers stay disabled)"

	osb_api sandbox kill "$VERIFY_ID" >/dev/null 2>&1 \
		|| log "verify cleanup: kill failed; remove $VERIFY_ID manually"
	wait_for "init-mode sandbox deleted" 120 verify_sandbox_gone
}

# --- standalone entry ----------------------------------------------------------------

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	resolve_osb
	require_template_id
	trap 'on_error verify-init-mode' ERR
	run_stage "execd-as-init verify (in-guest process topology)" init_mode_verify
fi
