#!/usr/bin/env bash

set -e

git submodule update -i
cp ./sparse-checkout ../.git/modules/secp256k1-abc-sys/bitcoin-abc/info/
cd bitcoin-abc
git config core.sparsecheckout true
git read-tree -mu HEAD
