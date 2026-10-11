#!/usr/bin/env bash
# Unpack one release archive into a fresh directory and run the binary in an
# empty environment: no toolchain, no PATH, no HOME. Checks the version, a
# decryption against an OpenSSL-produced vector and the exit-code contract.
#
#   smoke.sh <archive> <version>
set -euo pipefail

archive=$1
version=$2
py=$(command -v python3 || command -v python)
room=$(mktemp -d)
trap 'rm -rf "$room"' EXIT

"$py" -m zipfile -l "$archive" >/dev/null 2>&1 && kind=zip || kind=tar
if [[ "$kind" == zip ]]; then
  "$py" -m zipfile -e "$archive" "$room"
  exe=cnlman.exe
else
  "$py" -m tarfile -e "$archive" "$room"
  exe=cnlman
fi

# Exactly one top-level directory, selected by count rather than by luck.
count=$(find "$room" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')
top=$(find "$room" -mindepth 1 -maxdepth 1 -type d)
if [[ "$count" -ne 1 || -z "$top" ]]; then
  echo "smoke: the archive must hold exactly one top-level directory" >&2
  exit 1
fi
binary="$top/$exe"
for file in "$binary" "$top/LICENSE" "$top/README.md"; do
  [[ -s "$file" ]] || { echo "smoke: missing $file" >&2; exit 1; }
done
chmod +x "$binary"

# Windows needs SYSTEMROOT even for a statically linked executable.
clean=(env -i)
if [[ -n "${SYSTEMROOT:-}" ]]; then clean+=("SYSTEMROOT=$SYSTEMROOT"); fi

out=$("${clean[@]}" "$binary" --version | tr -d '\r')
[[ "$out" == "cnlman $version" ]] || { echo "smoke: --version said '$out'" >&2; exit 1; }

# The key of the vector is the ASCII text below, hex-encoded at run time.
key=$(printf '%s' 0123456789abcdef | od -An -tx1 | tr -d ' \n')
crypted='RnATJ+qxAkpHoFYfjZKfGIoMKq9yo6hLgc5BX1Qe/6qUNj/2AN1z0oQMNXP9K7qwLHW2sRDDJb8R3VaX/+cC8Q=='
links=$("${clean[@]}" "$binary" decrypt --jk "$key" --crypted "$crypted" --format links | tr -d '\r')
expected=$'https://example.org/smoke\nhttps://example.org/test'
[[ "$links" == "$expected" ]] || { echo "smoke: decrypt returned '$links'" >&2; exit 1; }

set +e
printf '<html></html>' | "${clean[@]}" "$binary" extract >/dev/null 2>&1
code=$?
set -e
[[ "$code" -eq 3 ]] || { echo "smoke: extract without payload exited $code, expected 3" >&2; exit 1; }

echo "smoke: $(basename "$archive") ok"
