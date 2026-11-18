#!/usr/bin/env bash
set -euo pipefail
. /etc/os-release
case "$ID" in
    kali)
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 xvfb xauth libxtst6 libxi6 libxrender1 libfontconfig1 fonts-dejavu-core libgl1
        ;;
    arch)
        pacman -Syu --noconfirm --needed python xorg-server-xvfb xorg-xauth libxtst libxi libxrender fontconfig ttf-dejavu libglvnd
        ;;
    *) exit 2 ;;
esac
/opt/PAVAROTTI/PAVAROTTI --check | tee /tmp/pavarotti-check.log
grep -F "PAVAROTTI OK" /tmp/pavarotti-check.log
xvfb-run -a python3 /tests/desktop.py /opt/PAVAROTTI
