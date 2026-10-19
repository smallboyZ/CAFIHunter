#!/usr/bin/env bash

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRIDA_DIR="${PROJECT_DIR}/frida-server-16.6.6"
REMOTE_TMP="/data/local/tmp"
REMOTE_DIR="/data/adb"

if ! command -v adb >/dev/null 2>&1; then
    echo "[ERROR] adb not found in PATH."
    exit 1
fi

if ! adb get-state >/dev/null 2>&1; then
    echo "[ERROR] No adb device connected. Run: adb devices -l"
    adb devices -l || true
    exit 1
fi

ABI="$(adb shell getprop ro.product.cpu.abi | tr -d '\r\n')"
if [[ -z "${ABI}" ]]; then
    echo "[ERROR] Failed to detect device ABI."
    exit 1
fi

case "${ABI}" in
    arm64-v8a)
        FRIDA_NAME="frida-server-16.6.6-android-arm64-AE"
        LOCAL_FRIDA="${FRIDA_DIR}/arm64/${FRIDA_NAME}"
        ;;
    armeabi-v7a|armeabi)
        FRIDA_NAME="frida-server-16.6.6-android-arm"
        LOCAL_FRIDA="${FRIDA_DIR}/arm/${FRIDA_NAME}"
        ;;
    x86)
        FRIDA_NAME="frida-server-16.6.6-android-x86"
        LOCAL_FRIDA="${FRIDA_DIR}/x86/${FRIDA_NAME}"
        ;;
    x86_64)
        FRIDA_NAME="frida-server-16.6.6-android-x86_64"
        LOCAL_FRIDA="${FRIDA_DIR}/x86_64/${FRIDA_NAME}"
        ;;
    *)
        echo "[ERROR] Unsupported ABI: ${ABI}"
        exit 1
        ;;
esac

if [[ ! -f "${LOCAL_FRIDA}" ]]; then
    echo "[ERROR] Frida server not found: ${LOCAL_FRIDA}"
    exit 1
fi

echo "[INFO] Device ABI: ${ABI}"
echo "[INFO] Selected Frida server: ${LOCAL_FRIDA}"

adb shell su 0 sh -c "mkdir -p '${REMOTE_DIR}'"
adb push "${LOCAL_FRIDA}" "${REMOTE_TMP}/${FRIDA_NAME}"
adb shell su 0 sh -c "cp '${REMOTE_TMP}/${FRIDA_NAME}' '${REMOTE_DIR}/${FRIDA_NAME}'"
adb shell su 0 sh -c "chmod 755 '${REMOTE_DIR}/${FRIDA_NAME}'"
adb shell su 0 sh -c "pkill -f frida-server >/dev/null 2>&1 || true"
adb shell su 0 sh -c "nohup '${REMOTE_DIR}/${FRIDA_NAME}' >/dev/null 2>&1 &"

sleep 1
echo "[INFO] Frida server process:"
adb shell su 0 sh -c "ps -A | grep frida || ps | grep frida" || true
echo "[INFO] Done."
