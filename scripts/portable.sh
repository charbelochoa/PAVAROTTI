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
exec "$app" "$@"
__PAVAROTTI_PAYLOAD__
