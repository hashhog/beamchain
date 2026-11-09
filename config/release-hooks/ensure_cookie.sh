# relx pre_start hook (installed as bin/hooks/ensure_cookie.sh, see
# rebar.config). The relx start script SOURCES this file before it boots
# the node for daemon / foreground / console.
#
# vm.args sets no cookie, so the node uses $HOME/.erlang.cookie. The
# start script reads that file before boot; on a fresh install it does
# not exist yet, COOKIE is empty, and `daemon` would wait forever for a
# node it can no longer authenticate to. So create it here, once per
# install: 20 random A-Z characters (the shape the runtime itself
# generates), owner read-only (0400), created atomically so a concurrent
# start cannot see a partial file. An existing file or RELX_COOKIE is
# left alone.
if [ -z "$COOKIE" ] && [ -n "$HOME" ] && [ -d "$HOME" ]; then
    _bc_cookie_file="$HOME/.erlang.cookie"
    if [ ! -e "$_bc_cookie_file" ]; then
        _bc_cookie_tmp="$(umask 077 && mktemp "$HOME/.erlang.cookie.XXXXXX")" || _bc_cookie_tmp=""
        if [ -n "$_bc_cookie_tmp" ]; then
            # Finite read, no endless pipe: started from a BEAM, SIGPIPE is
            # ignored and `tr </dev/urandom | head` would spew write errors.
            # Bytes >= 234 are dropped so `mod 26` stays unbiased.
            head -c 256 /dev/urandom 2>/dev/null | od -An -v -tu1 2>/dev/null |
                awk '{for (i = 1; i <= NF; i++) if ($i < 234 && n < 20) { printf "%c", 65 + $i % 26; n++ }}' \
                > "$_bc_cookie_tmp"
            if [ "$(wc -c < "$_bc_cookie_tmp")" -eq 20 ]; then
                chmod 0400 "$_bc_cookie_tmp"
                # ln fails if another start created the file first; keep theirs.
                ln "$_bc_cookie_tmp" "$_bc_cookie_file" 2>/dev/null || true
            fi
            rm -f "$_bc_cookie_tmp"
        fi
        unset _bc_cookie_tmp
    fi
    if [ -r "$_bc_cookie_file" ]; then
        COOKIE="$(cat "$_bc_cookie_file")"
    fi
    unset _bc_cookie_file
fi
