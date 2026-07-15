#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "Usage: $0 LOADER OUTPUT_DIRECTORY" >&2
    exit 2
}

die() {
    echo "qemu-refind-smoke: $*" >&2
    exit 1
}

[[ $# -eq 2 ]] || usage

loader=$1
requested_output=$2
qemu_binary=${QEMU_SYSTEM_X86_64:-qemu-system-x86_64}
ovmf_code=${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}
ovmf_vars_template=${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}
socket_timeout=${QEMU_SOCKET_TIMEOUT_SECONDS:-30}
boot_wait=${QEMU_BOOT_WAIT_SECONDS:-10}

[[ -f "$loader" ]] || die "loader is not a regular file: $loader"
[[ -f "$ovmf_code" ]] || die "OVMF code image is not a regular file: $ovmf_code"
[[ -f "$ovmf_vars_template" ]] || die \
    "OVMF vars template is not a regular file: $ovmf_vars_template"
command -v "$qemu_binary" >/dev/null || die "QEMU executable not found: $qemu_binary"
command -v nc >/dev/null || die "nc executable not found"
command -v iconv >/dev/null || die "iconv executable not found"
[[ $socket_timeout =~ ^[1-9][0-9]*$ ]] || die \
    "QEMU_SOCKET_TIMEOUT_SECONDS must be a positive integer"
[[ $boot_wait =~ ^[0-9]+$ ]] || die \
    "QEMU_BOOT_WAIT_SECONDS must be a non-negative integer"

if [[ -e "$requested_output" || -L "$requested_output" ]]; then
    die "output directory already exists: $requested_output"
fi
mkdir -p -- "$(dirname -- "$requested_output")"
umask 077
mkdir -- "$requested_output" || die \
    "could not create output directory: $requested_output"
output_directory=$(cd -- "$requested_output" && pwd -P)

esp_directory="$output_directory/esp"
boot_directory="$esp_directory/EFI/BOOT"
boot_loader="$esp_directory/EFI/BOOT/BOOTX64.EFI"
ovmf_vars="$output_directory/OVMF_VARS.fd"
monitor_socket="$output_directory/qemu-monitor.sock"
screen_ppm="$output_directory/screen.ppm"
qemu_log="$output_directory/qemu.log"
hmp_log="$output_directory/hmp.log"
guest_log="$boot_directory/refind.log"
converted_log="$output_directory/refind.log"
converted_log_tmp="$output_directory/.refind.log.tmp"
qemu_pid=

cleanup() {
    status=$?
    trap - EXIT
    rm -f -- "$monitor_socket" "$converted_log_tmp"
    if [[ -n "$qemu_pid" ]]; then
        if kill -0 "$qemu_pid" 2>/dev/null; then
            kill "$qemu_pid" 2>/dev/null || true
        fi
        wait "$qemu_pid" 2>/dev/null || true
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p -- "$boot_directory"
cp -- "$loader" "$boot_loader"
cp -- "$ovmf_vars_template" "$ovmf_vars"
chmod u+w "$ovmf_vars"
cat >"$boot_directory/refind.conf" <<'EOF'
timeout 0
log_level 4
use_nvram false
showtools reboot,shutdown
EOF

"$qemu_binary" \
    -name refind-smoke \
    -machine q35 \
    -accel tcg \
    -m 512 \
    -display none \
    -serial none \
    -parallel none \
    -net none \
    -no-reboot \
    -drive "if=pflash,format=raw,unit=0,readonly=on,file=$ovmf_code" \
    -drive "if=pflash,format=raw,unit=1,file=$ovmf_vars" \
    -drive "if=ide,format=raw,file=fat:rw:$esp_directory" \
    -monitor "unix:$monitor_socket,server=on,wait=off" \
    >"$qemu_log" 2>&1 &
qemu_pid=$!

socket_deadline=$((SECONDS + socket_timeout))
while [[ ! -S "$monitor_socket" ]]; do
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
        set +e
        wait "$qemu_pid"
        qemu_status=$?
        set -e
        qemu_pid=
        die "QEMU exited before creating its monitor socket (status $qemu_status)"
    fi
    ((SECONDS < socket_deadline)) || die "timed out waiting for QEMU monitor socket"
    sleep 0.1
done

# timeout 0 keeps the rEFInd menu visible while firmware and the loader settle.
sleep "$boot_wait"

monitor_status=0
nc -U -N "$monitor_socket" >"$hmp_log" <<EOF || monitor_status=$?
screendump "$screen_ppm"
quit
EOF
((monitor_status == 0)) || die "HMP command stream failed (status $monitor_status)"

set +e
wait "$qemu_pid"
qemu_status=$?
set -e
qemu_pid=
((qemu_status == 0)) || die "QEMU exited unsuccessfully (status $qemu_status)"
[[ -s "$screen_ppm" ]] || die "QEMU did not produce a screenshot"
[[ -f "$guest_log" ]] || die "rEFInd did not produce its diagnostic log"

iconv -f UTF-16 -t UTF-8 "$guest_log" >"$converted_log_tmp"
mv -- "$converted_log_tmp" "$converted_log"
grep -Fq "Entering main loop" "$converted_log" || die \
    "rEFInd log did not reach the main menu"
