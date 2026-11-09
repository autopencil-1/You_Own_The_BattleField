#!/usr/bin/env bash
set -euo pipefail

# Generate a behavioral reference for the 2B metadata renderer. The container
# receives this script over stdin: it never mounts or inspects the host tree.

readonly IMAGE='ubuntu@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852'
readonly HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SNAPSHOT="${HERE}/ubuntu_24_04_coreutils_9_4.txt"

generate() {
  docker run --rm -i \
    --network none \
    --read-only \
    --tmpfs /reference:rw,noexec,nosuid,nodev,noatime,size=16m,mode=0755 \
    --cap-drop ALL \
    --cap-add CHOWN \
    --cap-add DAC_OVERRIDE \
    --cap-add FOWNER \
    --cap-add FSETID \
    --cap-add SETGID \
    --cap-add SETUID \
    "${IMAGE}" bash -s <<'CONTAINER_SCRIPT'
set -euo pipefail
export LC_ALL=C
export TZ=UTC
umask 077

root=/reference
fixed_mtime='2025-01-17 03:42:11.123456789 UTC'
fixed_atime='2025-02-03 07:08:09.987654321 UTC'

mkdir -p \
  "${root}/etc" \
  "${root}/home/ubuntu/bin" \
  "${root}/var/log" \
  "${root}/var/backups/recovery" \
  "${root}/var/backups/staging" \
  "${root}/shared" \
  "${root}/list-only" \
  "${root}/traverse-only"

chmod 0755 "${root}/etc" "${root}/home" "${root}/var" "${root}/var/backups"

printf 'mode=synthetic\n' >"${root}/etc/app.conf"
printf 'operator note\n' >"${root}/home/ubuntu/notes.txt"
printf '#!/bin/sh\nprintf "synthetic helper\\n"\n' >"${root}/home/ubuntu/bin/report"
printf 'service started\n' >"${root}/var/log/service.log"
printf 'synthetic archive\n' >"${root}/var/backups/recovery/archive.txt"
printf 'staged data\n' >"${root}/var/backups/staging/private.txt"
printf 'shared note\n' >"${root}/shared/note.txt"
printf 'visible name, inaccessible metadata\n' >"${root}/list-only/entry.txt"
printf 'known child is reachable without listing\n' >"${root}/traverse-only/known.txt"

ln "${root}/etc/app.conf" "${root}/etc/app.conf.hard"
ln -s 'recovery/archive.txt' "${root}/var/backups/latest"
ln -s 'recovery/missing.txt' "${root}/var/backups/dangling"
ln -s 'cycle-b' "${root}/var/backups/cycle-a"
ln -s 'cycle-a' "${root}/var/backups/cycle-b"

chown 1000:1000 "${root}/home/ubuntu" "${root}/home/ubuntu/bin" \
  "${root}/home/ubuntu/notes.txt" "${root}/home/ubuntu/bin/report"
chown 0:4 "${root}/var/log" "${root}/var/log/service.log"
chown 34:34 "${root}/var/backups/recovery" \
  "${root}/var/backups/recovery/archive.txt"
chown 1500:1600 "${root}/var/backups/staging" \
  "${root}/var/backups/staging/private.txt"

chmod 0750 "${root}/home/ubuntu" "${root}/home/ubuntu/bin"
chmod 0640 "${root}/home/ubuntu/notes.txt"
chmod 0755 "${root}/home/ubuntu/bin/report"
chmod 0750 "${root}/var/log"
chmod 0640 "${root}/var/log/service.log"
chmod 0750 "${root}/var/backups/recovery"
chmod 0440 "${root}/var/backups/recovery/archive.txt"
chmod 2750 "${root}/var/backups/staging"
chmod 0640 "${root}/var/backups/staging/private.txt"
chmod 1777 "${root}/shared"
chmod 0644 "${root}/shared/note.txt"
chmod 0744 "${root}/list-only"
chmod 0644 "${root}/list-only/entry.txt"
chmod 0711 "${root}/traverse-only"
chmod 0644 "${root}/traverse-only/known.txt"

# Set mtime and atime after ownership/mode changes. ctime and birth time cannot
# be assigned portably, so the snapshot below labels them runtime-dependent.
find "${root}" -xdev ! -type l -exec touch -m -d "${fixed_mtime}" {} +
find "${root}" -xdev ! -type l -exec touch -a -d "${fixed_atime}" {} +
find "${root}" -xdev -type l -exec touch -h -m -d "${fixed_mtime}" {} +
find "${root}" -xdev -type l -exec touch -h -a -d "${fixed_atime}" {} +

printf '%s\n' 'SHAPE 2B Ubuntu metadata behavior reference'
printf 'image=%s\n' 'ubuntu@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852'
printf 'locale=%s timezone=%s\n' "${LC_ALL}" "${TZ}"
stat --version | sed -n '1p'
ls --version | sed -n '1p'
find --version | sed -n '1p'

printf '\n[ls-long-numeric]\n'
ls -lan --time-style=long-iso "${root}/home/ubuntu"
ls -lan --time-style=long-iso "${root}/var/backups"

printf '\n[ls-long-names]\n'
ls -ld --time-style=long-iso \
  "${root}/home/ubuntu/notes.txt" \
  "${root}/var/log/service.log" \
  "${root}/var/backups/staging" \
  "${root}/var/backups/staging/private.txt"

printf '\n[stat-stable-fields]\n'
printf '%s\n' 'path|type|octal|symbolic|uid|user|gid|group|size|links|atime|mtime|quoted-name'
for path in \
  "${root}/home/ubuntu" \
  "${root}/home/ubuntu/notes.txt" \
  "${root}/var/log/service.log" \
  "${root}/var/backups/staging" \
  "${root}/var/backups/staging/private.txt" \
  "${root}/var/backups/latest" \
  "${root}/var/backups/dangling"; do
  stat --printf='%n|%F|%a|%A|%u|%U|%g|%G|%s|%h|%x|%y|%N\n' "${path}"
done

printf '\n[stat-default-layout-normalized]\n'
stat "${root}/var/backups/latest" | sed -E \
  -e 's/Device: [^[:space:]]+/Device: <runtime-device>/' \
  -e 's/Inode: [0-9]+/Inode: <runtime-inode>/' \
  -e 's/^Change: .*/Change: <runtime-dependent>/' \
  -e 's/^ Birth: .*/ Birth: <runtime-dependent>/'

printf '\n[hard-link-relationship]\n'
test "$(stat --printf='%i' "${root}/etc/app.conf")" = \
  "$(stat --printf='%i' "${root}/etc/app.conf.hard")"
stat --printf='%n|inode=%i|links=%h|size=%s\n' \
  "${root}/etc/app.conf" "${root}/etc/app.conf.hard" | \
  sed -E 's/inode=[0-9]+/inode=<same-inode>/'

printf '\n[find-permission-forms]\n'
printf '%s\n' 'exact-0640:'
find "${root}" -xdev -perm 0640 -printf '%P|%m|%u|%g\n' | sort
printf '%s\n' 'all-u+r-and-g+r:'
find "${root}" -xdev -perm -0440 -printf '%P|%m|%u|%g\n' | sort
printf '%s\n' 'any-world-write:'
find "${root}" -xdev -perm /0002 -printf '%P|%m|%u|%g\n' | sort
printf '%s\n' 'uid-1500:'
find "${root}" -xdev -uid 1500 -printf '%P|%m|%U|%G\n' | sort

printf '\n[symlink-following]\n'
stat --printf='lstat|%N|type=%F|mode=%a|size=%s\n' "${root}/var/backups/latest"
stat -L --printf='follow|%N|type=%F|mode=%a|size=%s\n' "${root}/var/backups/latest"
set +e
cycle_error="$(stat -L "${root}/var/backups/cycle-a" 2>&1)"
cycle_status=$?
set -e
printf 'cycle-status=%s\n' "${cycle_status}"
printf '%s\n' "${cycle_error}" | sed "s#${root}#<virtual-root>#g"

printf '\n[unprivileged-access-as-ubuntu]\n'
for specification in \
  'read|-r|/reference/home/ubuntu/notes.txt' \
  'write|-w|/reference/home/ubuntu/notes.txt' \
  'read|-r|/reference/var/log/service.log' \
  'read|-r|/reference/var/backups/recovery/archive.txt' \
  'traverse|-x|/reference/list-only' \
  'list|-r|/reference/list-only' \
  'traverse|-x|/reference/traverse-only' \
  'list|-r|/reference/traverse-only'; do
  IFS='|' read -r operation predicate path <<<"${specification}"
  if setpriv --reuid=1000 --regid=1000 --clear-groups test "${predicate}" "${path}"; then
    result=allowed
  else
    result=denied
  fi
  printf '%s|%s|%s\n' "${operation}" "${path}" "${result}"
done
CONTAINER_SCRIPT
}

case "${1:-}" in
  '')
    generate
    ;;
  --check)
    diff -u "${SNAPSHOT}" <(generate)
    ;;
  *)
    printf 'usage: %s [--check]\n' "$0" >&2
    exit 2
    ;;
esac
