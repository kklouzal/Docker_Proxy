#!/bin/sh
# Record which base image and Alpine package snapshot an image build resolved.
# Alpine edge moves continuously, so the Dockerfile tag alone does not identify
# the Squid/Python/OpenSSL builds that shipped; this file does.
#
# usage: record-build-info <base-image-ref> <package> [<package> ...] [-- key=value ...]
set -eu

if [ "$#" -lt 2 ]; then
    echo "usage: record-build-info <base-image-ref> <package> [<package> ...] [-- key=value ...]" >&2
    exit 64
fi

out=/usr/share/docker-proxy/build-info
base_image="$1"
shift

mkdir -p "${out%/*}"
{
    printf 'base_image=%s\n' "$base_image"
    printf 'alpine_release=%s\n' "$(cat /etc/alpine-release)"
    while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
        # apk prints "<name>-<version>-r<rel>" for an installed package; a
        # missing one must abort the build instead of recording a gap.
        installed="$(apk info -e -v "$1")"
        if [ -z "$installed" ]; then
            echo "record-build-info: package $1 is not installed" >&2
            exit 1
        fi
        printf 'apk.%s=%s\n' "$1" "$installed"
        shift
    done
    if [ "$#" -gt 0 ]; then
        shift
        for entry in "$@"; do
            printf '%s\n' "$entry"
        done
    fi
} >"$out"
cat "$out"
