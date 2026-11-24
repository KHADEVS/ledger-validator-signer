#!/bin/sh
# Downloads the public test sets, at fixed commits.
set -eu
cd "$(dirname "$0")"
mkdir -p data
get() {
  rm -rf "data/$2"
  git init --quiet "data/$2"
  git -C "data/$2" fetch --quiet --depth 1 "https://github.com/$1/$2.git" "$3"
  git -C "data/$2" checkout --quiet FETCH_HEAD
}
get ethereum remote-signing-api 514525ca961a9d001e96a02bf870285a8ae401a4
get eth-clients slashing-protection-interchange-tests bb7900688eecd287d8723154faac6addb5e63336