#!/bin/sh

if [ -f /config/app.env ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%\r}"
        case "$line" in
            ''|\#*) continue ;;
        esac
        case "$line" in
            export\ *) line="${line#export }" ;;
        esac
        case "$line" in
            *=*)
                key="${line%%=*}"
                val="${line#*=}"
                key="$(printf '%s' "$key" | tr -d ' \t')"
                case "$key" in
                    ''|*[!A-Za-z0-9_]* ) continue ;;
                esac
                export "$key=$val"
                ;;
        esac
    done < /config/app.env
fi