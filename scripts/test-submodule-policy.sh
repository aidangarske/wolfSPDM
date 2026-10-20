#!/bin/sh
# Verify the real .gitmodules policy using small, local Git repositories.
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fixture=$(mktemp -d "${TMPDIR:-/tmp}/wolfspdm-submodules.XXXXXX")
trap 'rm -rf "$fixture"' EXIT
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1

commit_fixture() {
    git -C "$1" -c user.name=Test -c user.email=test@example.com \
        commit --quiet -m fixture
}

assert_skipped() {
    git_dir=$(git -C "$1" rev-parse --absolute-git-dir)
    if [ -e "$1/lib/wolfssl/.git" ] ||
            [ -d "$git_dir/modules/lib/wolfssl" ]; then
        echo "FAIL: wolfSPDM downloaded its opt-in wolfSSL: $1" >&2
        exit 1
    fi
}

git -c init.defaultBranch=master init --quiet "$fixture/wolfssl"
echo fixture > "$fixture/wolfssl/marker"
git -C "$fixture/wolfssl" add marker
commit_fixture "$fixture/wolfssl"
wolfssl_sha=$(git -C "$fixture/wolfssl" rev-parse HEAD)

git init --quiet "$fixture/wolfspdm"
cp "$root/.gitmodules" "$fixture/wolfspdm/.gitmodules"
git config -f "$fixture/wolfspdm/.gitmodules" \
    submodule.lib/wolfssl.url "$fixture/wolfssl"
git -C "$fixture/wolfspdm" add .gitmodules
git -C "$fixture/wolfspdm" update-index --add --cacheinfo \
    160000 "$wolfssl_sha" lib/wolfssl
commit_fixture "$fixture/wolfspdm"
wolfspdm_sha=$(git -C "$fixture/wolfspdm" rev-parse HEAD)

git init --quiet "$fixture/wolftpm"
for name in wolfssl wolfspdm; do
    case "$name" in
        wolfssl) path=lib/wolfssl; sha=$wolfssl_sha ;;
        wolfspdm) path=lib/wolfSPDM; sha=$wolfspdm_sha ;;
    esac
    git -C "$fixture/wolftpm" config -f .gitmodules \
        "submodule.$path.path" "$path"
    git -C "$fixture/wolftpm" config -f .gitmodules \
        "submodule.$path.url" "$fixture/$name"
    git -C "$fixture/wolftpm" update-index --add --cacheinfo \
        160000 "$sha" "$path"
done
git -C "$fixture/wolftpm" add .gitmodules
commit_fixture "$fixture/wolftpm"

git -c protocol.file.allow=always clone --quiet --recursive \
    "$fixture/wolftpm" "$fixture/recursive"
test -f "$fixture/recursive/lib/wolfssl/marker"
assert_skipped "$fixture/recursive/lib/wolfSPDM"
echo 'PASS: recursive parent clone gets one wolfSSL'

git clone --quiet "$fixture/wolftpm" "$fixture/update"
git -C "$fixture/update" -c protocol.file.allow=always \
    submodule update --quiet --init --force --recursive
test -f "$fixture/update/lib/wolfssl/marker"
assert_skipped "$fixture/update/lib/wolfSPDM"
echo 'PASS: recursive forced update skips nested wolfSSL'

git -c protocol.file.allow=always clone --quiet --recursive \
    "$fixture/wolfspdm" "$fixture/standalone"
assert_skipped "$fixture/standalone"
git -C "$fixture/standalone" -c protocol.file.allow=always \
    submodule update --quiet --init lib/wolfssl
assert_skipped "$fixture/standalone"
echo 'PASS: standalone wolfSSL requires explicit opt-in'

git -C "$fixture/standalone" -c protocol.file.allow=always \
    submodule update --quiet --init --checkout lib/wolfssl
test -f "$fixture/standalone/lib/wolfssl/marker"
echo 'PASS: explicit standalone checkout gets the pinned wolfSSL'
