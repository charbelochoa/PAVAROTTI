#!/usr/bin/env bash
set -euo pipefail
umask 077
digest=@SHA256@
cache="${XDG_CACHE_HOME:-$HOME/.cache}/pavarotti-usb"
app="$cache/$digest/PAVAROTTI/PAVAROTTI"
mkdir -p -- "$cache"
if [[ ! -x "$app" ]]; then
    (
        flock -x 9
        [[ ! -x "$app" ]] || exit 0
        tmp=$(mktemp -d "$cache/.extraer-XXXXXXXX")
        trap 'rm -rf -- "$tmp"' EXIT
        offset=$(awk '/^__PAVAROTTI_PAYLOAD__$/{print NR+1;exit}' "$0")
        [[ -n "$offset" ]]
        tail -n +"$offset" -- "$0" > "$tmp/payload"
        (cd "$tmp" && echo "$digest  payload" | sha256sum --check --status)
        tar -xzf "$tmp/payload" -C "$tmp"
        rm -- "$tmp/payload"
        mv -T -- "$tmp" "$cache/$digest"
    ) 9>"$cache/$digest.lock"
fi
# Register the extracted program so the Linux application menu can display its icon.
if [[ ${1:-} != --check ]]; then
    data=${XDG_DATA_HOME:-"$HOME/.local/share"}
    icons="$data/icons/hicolor/96x96/apps"
    apps="$data/applications"
    mkdir -p -- "$icons" "$apps"
    install -m 644 -- "$(dirname "$app")/pavarotti.png" "$icons/pavarotti.png"
    # Exec has its own quoting rules, including expansion of percent field codes.
    escaped=$(printf '%s' "$app" | sed 's/[\\"$`]/\\&/g; s/%/%%/g; s/\\/\\\\/g')
    entry=$(mktemp "$apps/.pavarotti-XXXXXXXX")
    printf '%s\n' '[Desktop Entry]' 'Type=Application' 'Name=PAVAROTTI' 'Icon=pavarotti' \
        "Exec=\"$escaped\"" 'Terminal=false' 'Categories=Utility;' > "$entry"
    chmod 644 "$entry"
    mv -f -- "$entry" "$apps/pavarotti.desktop"
    if [[ ${1:-} == --install-desktop ]]; then exit 0; fi
fi
exec "$app" "$@"
__PAVAROTTI_PAYLOAD__
