#!/bin/sh

if [ -f /config/app.env ]; then
    # Parse the complete file before applying anything.  Keep the normalized
    # assignments in shell memory so mounted secrets are never copied to disk.
    env_exports="$(awk '
        function ltrim(value) {
            sub(/^[ \t]+/, "", value)
            return value
        }
        function rtrim(value) {
            sub(/[ \t]+$/, "", value)
            return value
        }
        function trim(value) {
            return rtrim(ltrim(value))
        }
        function fail(reason) {
            printf "load-env: app.env: line %d: %s\n", NR, reason > "/dev/stderr"
            exit 2
        }
        function parse_value(value,    ch, i, out, prev, quote, tail) {
            sub(/\r$/, "", value)
            value = ltrim(value)
            quote = substr(value, 1, 1)
            if (quote == "\"" || quote == sprintf("%c", 39)) {
                out = ""
                for (i = 2; i <= length(value); i++) {
                    ch = substr(value, i, 1)
                    if (ch == quote) {
                        tail = substr(value, i + 1)
                        if (tail == "" || tail ~ /^[ \t]+#/) {
                            return out
                        }
                        fail("unexpected trailing characters after quoted value")
                    }
                    out = out ch
                }
                fail("unterminated quoted value")
            }

            out = ""
            prev = ""
            for (i = 1; i <= length(value); i++) {
                ch = substr(value, i, 1)
                if (ch == "#" && (prev == " " || prev == "\t")) {
                    break
                }
                out = out ch
                prev = ch
            }
            return rtrim(out)
        }
        {
            line = $0
            sub(/\r$/, "", line)
            line = trim(line)
            if (line == "" || substr(line, 1, 1) == "#") {
                next
            }
            if (line ~ /^export[ \t]+/) {
                sub(/^export[ \t]+/, "", line)
                line = ltrim(line)
            }
            eq = index(line, "=")
            if (eq == 0) {
                fail("expected environment assignment")
            }
            key = rtrim(substr(line, 1, eq - 1))
            if (key !~ /^[A-Za-z_][A-Za-z0-9_]*$/) {
                fail("invalid environment variable name")
            }
            value = parse_value(substr(line, eq + 1))
            quote = sprintf("%c", 39)
            escaped_quote = quote "\\" quote quote
            gsub(quote, escaped_quote, value)
            print "export " key "=" quote value quote
        }
    ' /config/app.env)" || exit $?

    # The parser admits only validated names and emits single-quoted literal
    # values, so this evaluates assignments rather than app.env shell syntax.
    eval "$env_exports"
    unset env_exports
fi
