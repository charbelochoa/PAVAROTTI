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
export XDG_CACHE_HOME=/tmp/pavarotti-cache
bash /media/PAVAROTTI.run --check | tee /tmp/pavarotti-check.log
grep -F "PAVAROTTI OK" /tmp/pavarotti-check.log
packages=("$XDG_CACHE_HOME"/pavarotti-usb/*/PAVAROTTI)
bash /media/PAVAROTTI.run --install-desktop
grep -Fx 'Name=PAVAROTTI' "$HOME/.local/share/applications/pavarotti.desktop"
test -s "$HOME/.local/share/icons/hicolor/96x96/apps/pavarotti.png"
xvfb-run -a python3 /tests/desktop.py "${packages[0]}"
